#!/usr/bin/env python3
"""
Advanced fetch + dedupe + scoring for Nuclei templates.

Features:
- Fetch github_repo / zip / raw (gist/raw)
- Extract YAML files
- Compute content_hash, structural_hash, canonicalized YAML
- Group by template id, structural_hash, and fuzzy similarity
- Score templates based on heuristics + source priority, prefer higher score
- Write one canonical YAML per cluster to templates/
- Write templates_index.json with provenance + duplicates list

Usage:
  python scripts/fetch_and_process.py [--dry-run] [--similarity N] [--min-score-diff M]

Tune parameters near the top of the file.
"""
from pathlib import Path
import json, os, sys, re, tempfile, shutil, io, hashlib, argparse
from datetime import datetime
import zipfile
import requests
import yaml
import difflib

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = ROOT / "templates"
SOURCES_FILE = ROOT / "sources.json"
INDEX_FILE = ROOT / "templates_index.json"

HEADERS = {"User-Agent":"TFnuclei-templates-fetcher/1.0 (+https://github.com/yourorg/TFnuclei-templates)"}

# ---- Tunables ----
SIMILARITY_THRESHOLD = 0.82   # difflib SequenceMatcher ratio for fuzzy grouping (0..1)
BUCKET_PREFIX_LEN = 8         # use first N chars of content-hash to bucket for faster fuzzy compare
MIN_SCORE_DIFF = 0.0001       # ties resolved by higher source priority then earliest saved
# -------------------

def sanitize_filename(s: str) -> str:
    s = re.sub(r"[^\w\-.]+", "_", s)
    return s.strip("_")[:200]

def source_identifier(source):
    if source.get("repo"):
        return source["repo"].replace("/", "__")
    if source.get("url"):
        return sanitize_filename(source["url"])
    return "unknown-source"

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
    """Return canonical YAML text (sorted keys) if possible, else a normalized text fallback."""
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
    """
    Replace scalar values with placeholders, preserving keys and structure,
    so we can compute a structure-only fingerprint.
    """
    if isinstance(obj, dict):
        return {k: structuralize(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [structuralize(v) for v in obj]
    # scalar -> placeholder token with type
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

def fetch_source_to_temp(source):
    """
    Download and extract (if archive) into a temp directory and return Path to it.
    """
    sid = source_identifier(src)
    typ = source.get("type")
    tmpd = Path(tempfile.mkdtemp(prefix="tf_nuc_"))
    try:
        if typ == "github_repo":
            owner_repo = source["repo"]
            for branch in ("main", "master"):
                zurl = f"https://github.com/{owner_repo}/archive/refs/heads/{branch}.zip"
                try:
                    data = download_to_bytes(zurl)
                    if try_extract_zip_bytes(data, tmpd):
                        return tmpd
                except Exception:
                    continue
            # if nothing extracted, leave empty tmpd (no YAMLs)
            return tmpd

        elif typ == "zip":
            data = download_to_bytes(source["url"])
            if try_extract_zip_bytes(data, tmpd):
                return tmpd
            # If it's not extractable, store as downloaded.zip and try to read YAMLs later
            (tmpd / "downloaded.zip").write_bytes(data)
            return tmpd

        elif typ in ("raw", "gist_raw"):
            try:
                raw_data = download_to_bytes(source["url"])
                fname = tmpd / f"{sanitize_filename(sid)}.yaml"
                fname.write_bytes(raw_data)
                return tmpd
            except Exception:
                raise

        else:
            raise RuntimeError(f"Unknown source type: {typ}")
    except Exception:
        # cleanup on failure by caller
        raise

def score_template(parsed_obj, canonical_text, source_priority):
    """
    Heuristic scoring function. Higher is better.
    Factors (weights):
     - source_priority (dominant)
     - has_id
     - info.name present
     - info.severity present
     - number of keys/sections (more sections -> richer template)
     - presence of 'requests' / 'requests' or 'matchers' / 'payloads'
     - length (lines)
     - references present
    """
    score = 0.0
    # base from source priority (scaled)
    score += float(source_priority) * 10.0

    # parsed object heuristics
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

        # structural richness: count top-level keys and important fields
        keys = set(parsed_obj.keys())
        score += min(len(keys) * 0.8, 25.0)

        # presence of matching/request sections common to nuclei templates
        match_fields = 0
        for f in ("requests", "request", "matchers", "match", "payloads", "payload"):
            if f in parsed_obj:
                match_fields += 1
        score += match_fields * 8.0

    # length: give slight bonus for non-trivial templates (but avoid awarding long irrelevant files too much)
    line_count = len(canonical_text.splitlines())
    if line_count > 5:
        score += min((line_count / 25.0), 10.0)

    # small tie-breaker: content uniqueness
    # (we'll compare later using source priority and score)

    return score

def choose_best_in_group(members):
    """
    members: list of dicts with keys:
      - canonical (str)
      - parsed (obj or None)
      - content_hash (str)
      - structural_hash (str or None)
      - source_id, source_priority, source_url, path
      - text_len
    Returns: chosen member (the dict), others list
    """
    # compute scores
    for m in members:
        m['_score'] = score_template(m.get("parsed"), m.get("canonical"), m.get("source_priority", 0))

    # sort by score desc, then by source_priority desc, then by text_len desc
    members.sort(key=lambda x: (x['_score'], x.get('source_priority',0), x.get('text_len',0)), reverse=True)
    chosen = members[0]
    others = members[1:]
    return chosen, others

def fuzzy_grouping(candidates):
    """
    Agglomerative-ish clustering using buckets + difflib for speed.
    candidates: list of dicts with keys 'content_hash' and 'canonical' and so on.
    Returns list of groups (each group is list of candidate dicts).
    """
    # bucket by first N chars of content_hash
    buckets = {}
    for c in candidates:
        key = c['content_hash'][:BUCKET_PREFIX_LEN]
        buckets.setdefault(key, []).append(c)

    groups = []
    visited = set()
    for bkey, items in buckets.items():
        # local greedy clustering
        for i, item in enumerate(items):
            if id(item) in visited:
                continue
            group = [item]
            visited.add(id(item))
            # compare to remaining in bucket
            for j in range(i+1, len(items)):
                other = items[j]
                if id(other) in visited:
                    continue
                # quick exact structural match check
                if item.get('structural_hash') and item.get('structural_hash') == other.get('structural_hash'):
                    group.append(other); visited.add(id(other)); continue
                # else fuzzy compare canonical text
                try:
                    ratio = difflib.SequenceMatcher(None, item['canonical'], other['canonical']).ratio()
                except Exception:
                    ratio = 0.0
                if ratio >= SIMILARITY_THRESHOLD:
                    group.append(other)
                    visited.add(id(other))
            groups.append(group)
    return groups

def process_sources(dry_run=False):
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources = json.load(f)

    # ensure templates dir
    if TEMPLATES_DIR.exists():
        shutil.rmtree(TEMPLATES_DIR)
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

    index = {"generated_at": datetime.utcnow().isoformat()+"Z", "count": 0, "templates": {}}
    stats = {"downloaded":0, "yaml_found":0, "candidates":0, "clusters":0, "saved":0, "skipped":0, "errors":0}

    # collect all YAML candidates from all sources into memory
    candidates = []

    for src in sources:
        sid = source_identifier(src)
        typ = src.get("type")
        priority = int(src.get("priority", 0))
        print(f"[{datetime.utcnow().isoformat()}] Processing {sid} ({typ}) priority={priority}")
        tmpd = None
        try:
            tmpd = fetch_source_to_temp(src)
            stats["downloaded"] += 1

            # find yamls
            found = list(find_yaml_files(tmpd))
            stats["yaml_found"] += len(found)

            for p in found:
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    canonical, parsed = canonicalize_yaml_text(text)
                    content_hash = compute_sha256(canonical)
                    struct_hash = structural_hash_from_obj(parsed) if parsed is not None else None
                    tid = get_template_id_from_yaml_obj(parsed) if parsed is not None else None
                    candidate = {
                        "template_id": tid,
                        "canonical": canonical,
                        "parsed": parsed,
                        "content_hash": content_hash,
                        "structural_hash": struct_hash,
                        "source_id": sid,
                        "source_type": typ,
                        "source_url": src.get("url") or src.get("repo"),
                        "source_priority": priority,
                        "path": str(p),
                        "text_len": len(canonical.splitlines())
                    }
                    candidates.append(candidate)
                except Exception as e:
                    print(f"ERROR processing file {p}: {e}")
                    stats["errors"] += 1

        except Exception as e:
            print(f"ERROR fetching source {sid}: {e}")
            stats["errors"] += 1
        finally:
            # cleanup temp dir
            try:
                if tmpd and tmpd.exists():
                    shutil.rmtree(tmpd)
            except Exception:
                pass

    stats["candidates"] = len(candidates)
    print(f"[{datetime.utcnow().isoformat()}] Collected {len(candidates)} template candidates")

    # 1) Group by template_id when present
    by_id = {}
    no_id = []
    for c in candidates:
        if c.get("template_id"):
            by_id.setdefault(c["template_id"], []).append(c)
        else:
            no_id.append(c)

    chosen_items = []   # final chosen canonical templates
    duplicates_info = {}  # map canonical_content_hash -> list of duplicates

    # resolve id groups
    for tid, members in by_id.items():
        chosen, others = choose_best_in_group(members)
        chosen_items.append(chosen)
        dup_list = []
        for o in others:
            dup_list.append({
                "template_id": o.get("template_id"),
                "source_id": o.get("source_id"),
                "source_url": o.get("source_url"),
                "content_hash": o.get("content_hash"),
                "structural_hash": o.get("structural_hash")
            })
        duplicates_info[chosen["content_hash"]] = dup_list

    # 2) For no-id templates, group by exact structural_hash first
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
                    "source_url": o.get("source_url"),
                    "content_hash": o.get("content_hash"),
                    "structural_hash": o.get("structural_hash")
                })
            duplicates_info[chosen["content_hash"]] = dup_list

    # 3) Fuzzy cluster remaining (use bucketing + difflib)
    if remaining:
        fuzzy_groups = fuzzy_grouping(remaining)
        for group in fuzzy_groups:
            if len(group) == 1:
                # single candidate -> keep as chosen
                chosen_items.append(group[0])
            else:
                chosen, others = choose_best_in_group(group)
                chosen_items.append(chosen)
                dup_list = []
                for o in others:
                    dup_list.append({
                        "template_id": o.get("template_id"),
                        "source_id": o.get("source_id"),
                        "source_url": o.get("source_url"),
                        "content_hash": o.get("content_hash"),
                        "structural_hash": o.get("structural_hash")
                    })
                duplicates_info[chosen["content_hash"]] = dup_list

    # 4) Save chosen_items into templates/ and write index
    idx_map = {}
    for item in chosen_items:
        # file name: <source>__<shorthash>.yaml
        src_label = sanitize_filename(item.get("source_id") or "unknown")
        short_hash = item["content_hash"][:12]
        out_name = f"{src_label}__{short_hash}.yaml"
        out_path = TEMPLATES_DIR / out_name
        # write canonical YAML
        if not dry_run:
            out_path.write_text(item["canonical"], encoding="utf-8")
        # index entry keyed by content_hash
        idx_map[item["content_hash"]] = {
            "template_id": item.get("template_id"),
            "filename": str(Path("templates")/out_name),
            "source_id": item.get("source_id"),
            "source_url": item.get("source_url"),
            "source_priority": item.get("source_priority"),
            "structural_hash": item.get("structural_hash"),
            "text_len": item.get("text_len"),
            "collected_at": datetime.utcnow().isoformat()+"Z",
            "duplicates": duplicates_info.get(item["content_hash"], [])
        }
        stats["saved"] += 1

    index["count"] = len(idx_map)
    index["templates"] = idx_map

    if not dry_run:
        with open(INDEX_FILE, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2)

    print("SUMMARY:", stats)
    return stats

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--similarity", type=float, default=SIMILARITY_THRESHOLD)
    args = parser.parse_args()

    # override module-level value safely
    globals()["SIMILARITY_THRESHOLD"] = args.similarity

    stats = process_sources(dry_run=args.dry_run)

    # fail only if nothing saved
    if stats["saved"] == 0:
        sys.exit(2)
    sys.exit(0)

if __name__ == "__main__":
    main()
