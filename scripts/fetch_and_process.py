#!/usr/bin/env python3
"""
Advanced fetch + dedupe + scoring for Nuclei templates.

- Fetches sources listed in sources.json (github_repo, zip, raw/gist)
- Extracts YAML files
- Canonicalizes YAML and computes structural and content hashes
- Groups templates by id / structural hash / fuzzy similarity
- Scores templates using heuristics + source priority and picks one canonical template per cluster
- Produces a raw_url for canonical templates when possible (best effort)
- Writes templates/ and templates_index.json only if changes are detected
- Usage: python scripts/fetch_and_process.py [--dry-run] [--similarity 0.82]
"""
from pathlib import Path
import json, os, sys, re, tempfile, shutil, io, hashlib, argparse
from datetime import datetime
import zipfile
import requests
import yaml
import difflib

ROOT = Path(__file__).resolve().parents[1]
SOURCES_FILE = ROOT / "sources.json"
TEMPLATES_DIR = ROOT / "templates"
TMP_OUT_DIR = ROOT / "templates_out"
INDEX_FILE = ROOT / "templates_index.json"

HEADERS = {"User-Agent":"TFnuclei-templates-fetcher/1.0 (+https://github.com/yourorg/TFnuclei-templates)"}

# ---- Tunables (defaults) ----
SIMILARITY_THRESHOLD = 0.82   # difflib ratio threshold for fuzzy grouping
BUCKET_PREFIX_LEN = 8         # first N chars of hash used for bucketing
# -----------------------------

def log(*args, **kwargs):
    ts = datetime.utcnow().isoformat()
    print(f"[{ts}]", *args, **kwargs)

def sanitize_filename(s: str) -> str:
    s = re.sub(r"[^\w\-.]+", "_", s)
    return s.strip("_")[:200]

def download_to_bytes(url, timeout=60):
    r = requests.get(url, headers=HEADERS, timeout=timeout, stream=True)
    r.raise_for_status()
    return r.content

def try_extract_zip_bytes(data: bytes, dest: Path):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            z.extractall(dest)
        return True
    except zipfile.BadZipFile:
        return False

def find_yaml_files(search_dir: Path):
    for p in search_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".yml", ".yaml"):
            yield p

def canonicalize_yaml_text(text: str):
    try:
        obj = yaml.safe_load(text)
        canonical = yaml.safe_dump(obj, sort_keys=True)
        canonical = "\n".join(line.rstrip() for line in canonical.splitlines()) + "\n"
        return canonical, obj
    except Exception:
        normalized = "\n".join(line.rstrip() for line in text.splitlines()) + "\n"
        return normalized, None

def compute_sha256(text: str):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def structuralize(obj):
    if isinstance(obj, dict):
        return {k: structuralize(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [structuralize(v) for v in obj]
    if isinstance(obj, str):
        return "<STR>"
    if isinstance(obj, (int, float, bool)):
        return "<NUM>"
    return "<VAL>"

def structural_hash_from_obj(obj):
    try:
        struct = structuralize(obj)
        dumped = yaml.safe_dump(struct, sort_keys=True)
        return compute_sha256(dumped)
    except Exception:
        return None

def get_template_id_from_yaml_obj(obj):
    if not isinstance(obj, dict):
        return None
    if "id" in obj and isinstance(obj["id"], str) and obj["id"].strip():
        return obj["id"].strip()
    info = obj.get("info") if isinstance(obj.get("info"), dict) else None
    if info:
        if "name" in info and isinstance(info["name"], str) and info["name"].strip():
            return info["name"].strip()
    return None

def source_identifier(source):
    """
    Auto-derive a short source id from source entry.
    For github_repo: owner__repo
    For url-based sources: sanitized url
    """
    if source.get("repo"):
        return source["repo"].replace("/", "__")
    if source.get("url"):
        return sanitize_filename(source["url"])
    return "unknown_source"

def parse_github_zip_url(url: str):
    """
    Try to extract (owner, repo, branch) if URL is a github archive url like:
    https://github.com/owner/repo/archive/refs/heads/main.zip
    returns (owner, repo, branch) or (None, None, None)
    """
    try:
        # typical pattern: github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip
        m = re.search(r"github\.com/([^/]+)/([^/]+)/archive/refs/(?:heads|tags)/([^/]+)\.zip", url)
        if m:
            return m.group(1), m.group(2), m.group(3)
        # sometimes: github.com/{owner}/{repo}/archive/{branch}.zip
        m2 = re.search(r"github\.com/([^/]+)/([^/]+)/archive/([^/]+)\.zip", url)
        if m2:
            return m2.group(1), m2.group(2), m2.group(3)
    except Exception:
        pass
    return None, None, None

def fetch_source_to_temp(source):
    """
    Downloads source and extracts into a temp dir.
    Returns (tmp_path, meta) where meta describes type and useful info (branch if github).
    """
    sid = source_identifier(source)
    typ = source.get("type")
    tmpd = Path(tempfile.mkdtemp(prefix="tf_nuc_"))
    meta = {"type": typ}
    try:
        if typ == "github_repo":
            owner_repo = source["repo"]
            owner, repo_name = owner_repo.split("/", 1)
            meta["repo_owner"] = owner
            meta["repo_name"] = repo_name
            # Try branches in order; note which branch succeeded
            for branch in ("main", "master"):
                zurl = f"https://github.com/{owner_repo}/archive/refs/heads/{branch}.zip"
                try:
                    data = download_to_bytes(zurl)
                    if try_extract_zip_bytes(data, tmpd):
                        meta["branch"] = branch
                        return tmpd, meta
                except Exception:
                    continue
            # No branch found -> return tmpd empty
            return tmpd, meta

        elif typ == "zip":
            url = source.get("url")
            data = download_to_bytes(url)
            # check if it's a GitHub-style archive (so we can later derive raw_url)
            owner, repo_name, branch = parse_github_zip_url(url)
            if owner and repo_name and branch:
                meta.update({"repo_owner": owner, "repo_name": repo_name, "branch": branch, "zip_from_github": True})
            if try_extract_zip_bytes(data, tmpd):
                return tmpd, meta
            # if not extractable, save raw file to tmp for later attempts
            (tmpd / "downloaded.zip").write_bytes(data)
            return tmpd, meta

        elif typ in ("raw", "gist_raw"):
            url = source.get("url")
            data = download_to_bytes(url)
            # save as a yaml file
            fname = tmpd / f"{sanitize_filename(sid)}.yaml"
            fname.write_bytes(data)
            meta["raw_url"] = url
            return tmpd, meta

        else:
            raise RuntimeError(f"Unknown source type: {typ}")

    except Exception as e:
        # on failure, cleanup and re-raise
        try:
            shutil.rmtree(tmpd)
        except Exception:
            pass
        raise

def compute_raw_url_for_path(meta, file_path: Path, tmpd: Path):
    """
    Best-effort raw URL for a file extracted from tmpd.
    - For github_repo and github zip archives: construct raw.githubusercontent.com URL using owner/repo/branch/<path>
    - For raw/gist: use provided url
    - Otherwise: return None
    """
    try:
        if not file_path.exists():
            return None
        # path relative to tmp root: top-level folder is repo-branch or similar
        rel = file_path.relative_to(tmpd)
        parts = list(rel.parts)
        if meta.get("type") == "github_repo":
            owner = meta.get("repo_owner")
            repo_name = meta.get("repo_name")
            branch = meta.get("branch", "main")
            # drop first top-level folder in archive (e.g. "repo-main/...")
            if len(parts) >= 2:
                inner_path = "/".join(parts[1:])
            else:
                inner_path = "/".join(parts)
            return f"https://raw.githubusercontent.com/{owner}/{repo_name}/{branch}/{inner_path}"
        if meta.get("zip_from_github"):
            owner = meta.get("repo_owner")
            repo_name = meta.get("repo_name")
            branch = meta.get("branch")
            if owner and repo_name and branch:
                if len(parts) >= 2:
                    inner_path = "/".join(parts[1:])
                else:
                    inner_path = "/".join(parts)
                return f"https://raw.githubusercontent.com/{owner}/{repo_name}/{branch}/{inner_path}"
        if meta.get("raw_url"):
            # raw/gist source - return the raw url pointed to the saved file
            return meta.get("raw_url")
    except Exception:
        pass
    return None

# ---------------- scoring and grouping ----------------

def score_template(parsed_obj, canonical_text, source_priority):
    score = 0.0
    score += float(source_priority) * 10.0
    if isinstance(parsed_obj, dict):
        if "id" in parsed_obj and isinstance(parsed_obj["id"], str) and parsed_obj["id"].strip():
            score += 50.0
        info = parsed_obj.get("info") if isinstance(parsed_obj.get("info"), dict) else {}
        if info:
            if info.get("name"):
                score += 10.0
            if info.get("severity"):
                score += 8.0
            if info.get("author"):
                score += 5.0
            if info.get("reference") or info.get("references"):
                score += 6.0
        keys = set(parsed_obj.keys())
        score += min(len(keys) * 0.8, 25.0)
        match_fields = 0
        for f in ("requests", "request", "matchers", "match", "payloads", "payload"):
            if f in parsed_obj:
                match_fields += 1
        score += match_fields * 8.0
    line_count = len(canonical_text.splitlines())
    if line_count > 5:
        score += min((line_count / 25.0), 10.0)
    return score

def choose_best_in_group(members):
    for m in members:
        m['_score'] = score_template(m.get("parsed"), m.get("canonical"), m.get("source_priority", 0))
    members.sort(key=lambda x: (x['_score'], x.get('source_priority',0), x.get('text_len',0)), reverse=True)
    chosen = members[0]
    others = members[1:]
    return chosen, others

def fuzzy_grouping(candidates, similarity_threshold):
    buckets = {}
    for c in candidates:
        key = c['content_hash'][:BUCKET_PREFIX_LEN]
        buckets.setdefault(key, []).append(c)
    groups = []
    visited = set()
    for items in buckets.values():
        for i, item in enumerate(items):
            if id(item) in visited:
                continue
            group = [item]; visited.add(id(item))
            for j in range(i+1, len(items)):
                other = items[j]
                if id(other) in visited:
                    continue
                # structural exact
                if item.get('structural_hash') and item.get('structural_hash') == other.get('structural_hash'):
                    group.append(other); visited.add(id(other)); continue
                try:
                    ratio = difflib.SequenceMatcher(None, item['canonical'], other['canonical']).ratio()
                except Exception:
                    ratio = 0.0
                if ratio >= similarity_threshold:
                    group.append(other); visited.add(id(other))
            groups.append(group)
    return groups

# ---------------- main processing ----------------

def gather_candidates(sources):
    candidates = []
    stats = {"downloaded":0, "yaml_found":0, "errors":0}
    for source in sources:
        sid = source_identifier(source)
        priority = int(source.get("priority", 0))
        typ = source.get("type")
        log(f"Processing {sid} ({typ}) priority={priority}")
        try:
            tmpd, meta = fetch_source_to_temp(source)
            stats["downloaded"] += 1
            found = list(find_yaml_files(tmpd))
            stats["yaml_found"] += len(found)
            for p in found:
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    canonical, parsed = canonicalize_yaml_text(text)
                    content_hash = compute_sha256(canonical)
                    struct_hash = structural_hash_from_obj(parsed) if parsed is not None else None
                    tid = get_template_id_from_yaml_obj(parsed) if parsed is not None else None
                    raw_url = compute_raw_url_for_path(meta, p, tmpd)
                    candidate = {
                        "template_id": tid,
                        "canonical": canonical,
                        "parsed": parsed,
                        "content_hash": content_hash,
                        "structural_hash": struct_hash,
                        "source_repo": source.get("repo"),
                        "source_url_field": source.get("url"),
                        "source_id": sid,
                        "source_type": typ,
                        "source_priority": priority,
                        "path": str(p),
                        "text_len": len(canonical.splitlines()),
                        "raw_url_candidate": raw_url
                    }
                    candidates.append(candidate)
                except Exception as e:
                    log(f"ERROR processing file {p}: {e}")
                    stats["errors"] += 1
        except Exception as e:
            log(f"ERROR fetching source {sid}: {e}")
            stats["errors"] += 1
        finally:
            try:
                if 'tmpd' in locals() and tmpd and tmpd.exists():
                    shutil.rmtree(tmpd)
            except Exception:
                pass
    return candidates, stats

def write_outputs_if_changed(idx_map, chosen_items, dry_run=False):
    """
    Build a temporary templates_out directory and index JSON.
    Replace TEMPLATES_DIR and INDEX_FILE only if changes detected.
    Returns True if changes were written, False if no changes.
    """
    # prepare tmp out dir
    if TMP_OUT_DIR.exists():
        shutil.rmtree(TMP_OUT_DIR)
    TMP_OUT_DIR.mkdir(parents=True, exist_ok=True)

    # write files to tmp out
    for item in chosen_items:
        src_label = sanitize_filename(item.get("source_id") or item.get("source_repo") or "unknown")
        short_hash = item["content_hash"][:12]
        out_name = f"{src_label}__{short_hash}.yaml"
        out_path = TMP_OUT_DIR / out_name
        out_path.write_text(item["canonical"], encoding="utf-8")

    # compute whether TMP_OUT_DIR differs from current templates dir
    changed = False
    if not TEMPLATES_DIR.exists():
        changed = True
    else:
        # compare filenames
        existing_files = set(p.name for p in TEMPLATES_DIR.iterdir() if p.is_file())
        new_files = set(p.name for p in TMP_OUT_DIR.iterdir() if p.is_file())
        if existing_files != new_files:
            changed = True
        else:
            # compare contents
            for fn in new_files:
                if (TEMPLATES_DIR / fn).read_bytes() != (TMP_OUT_DIR / fn).read_bytes():
                    changed = True
                    break

    # If changed and not dry_run -> replace templates dir and write index file
    if changed and not dry_run:
        # atomically replace templates dir
        backup = None
        try:
            if TEMPLATES_DIR.exists():
                backup = ROOT / f"templates_backup_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                TEMPLATES_DIR.rename(backup)
            TMP_OUT_DIR.rename(TEMPLATES_DIR)
            # write index
            # add repository-level metadata
            index_obj = {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "last_updated": datetime.utcnow().isoformat() + "Z",
                "count": len(idx_map),
                "templates": idx_map
            }
            with open(INDEX_FILE, "w", encoding="utf-8") as fh:
                json.dump(index_obj, fh, indent=2)
            # cleanup backup
            if backup and backup.exists():
                try:
                    shutil.rmtree(backup)
                except Exception:
                    pass
            log("Wrote new templates and updated index.")
            return True
        except Exception as e:
            log("ERROR while replacing templates dir:", e)
            # try to restore backup if present
            try:
                if backup and backup.exists() and not TEMPLATES_DIR.exists():
                    backup.rename(TEMPLATES_DIR)
            except Exception:
                pass
            raise
    else:
        # no changes -> remove tmp_out
        try:
            if TMP_OUT_DIR.exists():
                shutil.rmtree(TMP_OUT_DIR)
        except Exception:
            pass
        log("No changes detected; not updating templates/ or templates_index.json.")
        return False

def process_all(sources, similarity_threshold, dry_run=False):
    # gather
    candidates, gather_stats = gather_candidates(sources)
    stats = {"downloaded": gather_stats["downloaded"], "yaml_found": gather_stats["yaml_found"], "candidates": len(candidates), "clusters": 0, "saved": 0, "errors": gather_stats["errors"]}

    log(f"Collected {len(candidates)} candidates")

    # by id
    by_id = {}
    no_id = []
    for c in candidates:
        if c.get("template_id"):
            by_id.setdefault(c["template_id"], []).append(c)
        else:
            no_id.append(c)

    chosen_items = []
    duplicates_info = {}

    for tid, members in by_id.items():
        chosen, others = choose_best_in_group(members)
        chosen_items.append(chosen)
        dup_list = []
        for o in others:
            dup_list.append({
                "template_id": o.get("template_id"),
                "source_id": o.get("source_id"),
                "source_repo": o.get("source_repo"),
                "source_url_field": o.get("source_url_field"),
                "content_hash": o.get("content_hash"),
                "structural_hash": o.get("structural_hash"),
                "raw_url_candidate": o.get("raw_url_candidate")
            })
        duplicates_info[chosen["content_hash"]] = dup_list

    # structural grouping for no-id
    structural_map = {}
    remaining = []
    for c in no_id:
        sh = c.get("structural_hash")
        if sh:
            structural_map.setdefault(sh, []).append(c)
        else:
            remaining.append(c)

    for sh, members in structural_map.items():
        if len(members) == 1:
            remaining.append(members[0])
        else:
            chosen, others = choose_best_in_group(members)
            chosen_items.append(chosen)
            dup_list = []
            for o in others:
                dup_list.append({
                    "template_id": o.get("template_id"),
                    "source_id": o.get("source_id"),
                    "source_repo": o.get("source_repo"),
                    "source_url_field": o.get("source_url_field"),
                    "content_hash": o.get("content_hash"),
                    "structural_hash": o.get("structural_hash"),
                    "raw_url_candidate": o.get("raw_url_candidate")
                })
            duplicates_info[chosen["content_hash"]] = dup_list

    # fuzzy grouping for remaining
    if remaining:
        fuzzy_groups = fuzzy_grouping(remaining, similarity_threshold)
        stats["clusters"] = len(fuzzy_groups)
        for group in fuzzy_groups:
            if len(group) == 1:
                chosen_items.append(group[0])
            else:
                chosen, others = choose_best_in_group(group)
                chosen_items.append(chosen)
                dup_list = []
                for o in others:
                    dup_list.append({
                        "template_id": o.get("template_id"),
                        "source_id": o.get("source_id"),
                        "source_repo": o.get("source_repo"),
                        "source_url_field": o.get("source_url_field"),
                        "content_hash": o.get("content_hash"),
                        "structural_hash": o.get("structural_hash"),
                        "raw_url_candidate": o.get("raw_url_candidate")
                    })
                duplicates_info[chosen["content_hash"]] = dup_list

    # prepare index map
    idx_map = {}
    for item in chosen_items:
        src_label = sanitize_filename(item.get("source_id") or item.get("source_repo") or "unknown")
        short_hash = item["content_hash"][:12]
        filename = f"{src_label}__{short_hash}.yaml"
        raw_url = item.get("raw_url_candidate")
        idx_map[item["content_hash"]] = {
            "template_id": item.get("template_id"),
            "filename": str(Path("templates") / filename),
            "source_id": item.get("source_id"),
            "source_repo": item.get("source_repo"),
            "source_url_field": item.get("source_url_field"),
            "source_priority": item.get("source_priority"),
            "structural_hash": item.get("structural_hash"),
            "text_len": item.get("text_len"),
            "raw_url": raw_url,
            "collected_at": datetime.utcnow().isoformat() + "Z",
            "duplicates": duplicates_info.get(item["content_hash"], [])
        }

    # write outputs only if changed
    changed = write_outputs_if_changed(idx_map, chosen_items, dry_run=dry_run)
    if changed:
        stats["saved"] = len(idx_map)

    log("SUMMARY:", stats)
    return stats

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Don't write outputs (useful for testing)")
    parser.add_argument("--similarity", type=float, default=SIMILARITY_THRESHOLD, help="Similarity threshold (0..1) for fuzzy grouping")
    args = parser.parse_args()

    # override module-level default safely
    globals()["SIMILARITY_THRESHOLD"] = args.similarity

    if not SOURCES_FILE.exists():
        log("sources.json not found at", SOURCES_FILE)
        sys.exit(2)

    with open(SOURCES_FILE, "r", encoding="utf-8") as fh:
        try:
            sources = json.load(fh)
        except Exception as e:
            log("Failed to parse sources.json:", e)
            sys.exit(2)

    stats = process_all(sources, globals()["SIMILARITY_THRESHOLD"], dry_run=args.dry_run)

    # if nothing saved and no previous templates exist, consider failure
    existing_templates_present = TEMPLATES_DIR.exists() and any(TEMPLATES_DIR.iterdir())
    if stats.get("saved", 0) == 0 and not existing_templates_present:
        log("No templates saved and no existing templates present -> failing")
        sys.exit(2)

    # success
    sys.exit(0)

if __name__ == "__main__":
    main()
