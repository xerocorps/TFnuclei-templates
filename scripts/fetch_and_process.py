#!/usr/bin/env python3
"""
Merge candidate chunks and run advanced dedupe, scoring, and write templates + index only on change.

Usage:
 python scripts/merge_and_dedupe.py --chunks-dir artifacts_all --dry-run false --similarity 0.82
"""
import argparse, json, os, sys, shutil
from pathlib import Path
from datetime import datetime
import yaml, hashlib, difflib, re

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = ROOT / "templates"
INDEX_FILE = ROOT / "templates_index.json"

# Tunables (same semantics as before)
SIMILARITY_THRESHOLD = 0.82
BUCKET_PREFIX_LEN = 8

def log(*a, **k):
    print(datetime.utcnow().isoformat(), *a, **k)

def sanitize_filename(s: str) -> str:
    return re.sub(r"[^\w\-.]+", "_", s).strip("_")[:200]

def compute_sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def structuralize(obj):
    if isinstance(obj, dict):
        return {k: structuralize(v) for k,v in sorted(obj.items())}
    if isinstance(obj, list):
        return [structuralize(v) for v in obj]
    if isinstance(obj, str):
        return "<STR>"
    if isinstance(obj, (int,float,bool)):
        return "<NUM>"
    return "<VAL>"

def structural_hash_from_obj(obj):
    try:
        return hashlib.sha256(yaml.safe_dump(structuralize(obj), sort_keys=True).encode("utf-8")).hexdigest()
    except Exception:
        return None

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
        for f in ("requests", "request", "matchers", "match", "payloads", "payload"):
            if f in parsed_obj:
                score += 8.0
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

def load_chunks(chunks_dir: Path):
    # chunks_dir contains one or more directories like chunk-0, chunk-1 (from download-artifact)
    all_candidates = []
    for p in chunks_dir.iterdir():
        if p.is_dir():
            cjson = p / "candidates.json"
            files_dir = p / "files"
            if not cjson.exists():
                continue
            try:
                blob = json.load(open(cjson, "r", encoding="utf-8"))
            except Exception:
                continue
            for c in blob.get("candidates", []):
                # read canonical text from file
                rel = c.get("relpath")
                if not rel:
                    continue
                fpath = files_dir / Path(rel).name  # file name written by chunk script
                if not fpath.exists():
                    # try relative path
                    fpath = p / rel
                if not fpath.exists():
                    continue
                try:
                    text = fpath.read_text(encoding="utf-8", errors="replace")
                    parsed = None
                    try:
                        parsed = yaml.safe_load(text)
                    except Exception:
                        parsed = None
                    _struct = c.get("structural_hash")
                    if not _struct and parsed is not None:
                        _struct = structural_hash_from_obj(parsed)
                    all_candidates.append({
                        "content_hash": c.get("content_hash"),
                        "structural_hash": _struct,
                        "template_id": c.get("template_id"),
                        "source_repo": c.get("source_repo"),
                        "source_id": c.get("source_id"),
                        "source_priority": c.get("source_priority"),
                        "canonical": text,
                        "parsed": parsed,
                        "text_len": c.get("text_len"),
                        "raw_url_candidate": c.get("raw_url_candidate")
                    })
                except Exception:
                    continue
    return all_candidates

def structural_hash_from_obj(obj):
    try:
        return hashlib.sha256(yaml.safe_dump(structuralize(obj), sort_keys=True).encode("utf-8")).hexdigest()
    except Exception:
        return None

def write_outputs_if_changed(idx_map, chosen_items, dry_run=False):
    tmp = ROOT / "templates_tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True, exist_ok=True)

    for item in chosen_items:
        src_label = sanitize_filename(item.get("source_id") or item.get("source_repo") or "unknown")
        short_hash = item["content_hash"][:12]
        fname = f"{src_label}__{short_hash}.yaml"
        (tmp / fname).write_text(item["canonical"], encoding="utf-8")

    changed = False
    if not TEMPLATES_DIR.exists():
        changed = True
    else:
        existing = {p.name: p.read_bytes() for p in TEMPLATES_DIR.iterdir() if p.is_file()}
        new = {p.name: p.read_bytes() for p in tmp.iterdir() if p.is_file()}
        if existing.keys() != new.keys():
            changed = True
        else:
            for k in new:
                if existing[k] != new[k]:
                    changed = True
                    break

    if changed and not dry_run:
        backup = None
        try:
            if TEMPLATES_DIR.exists():
                backup = ROOT / f"templates_backup_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                TEMPLATES_DIR.rename(backup)
            tmp.rename(TEMPLATES_DIR)
            # write index
            index_obj = {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "last_updated": datetime.utcnow().isoformat() + "Z",
                "count": len(idx_map),
                "templates": idx_map
            }
            with open(INDEX_FILE, "w", encoding="utf-8") as fh:
                json.dump(index_obj, fh, indent=2)
            # clean backup
            if backup and backup.exists():
                try:
                    shutil.rmtree(backup)
                except Exception:
                    pass
            log("Templates updated on disk.")
            return True
        except Exception as e:
            log("Error writing outputs:", e)
            try:
                if backup and backup.exists() and not TEMPLATES_DIR.exists():
                    backup.rename(TEMPLATES_DIR)
            except Exception:
                pass
            raise
    else:
        shutil.rmtree(tmp)
        log("No changes; nothing written.")
        return False

def process_all(chunks_dir: Path, similarity_threshold: float, dry_run=False):
    candidates = load_chunks(chunks_dir)
    log(f"Loaded {len(candidates)} canonical candidates from chunks")
    # group by id
    by_id = {}
    no_id = []
    for c in candidates:
        if c.get("template_id"):
            by_id.setdefault(c["template_id"], []).append(c)
        else:
            no_id.append(c)

    chosen = []
    duplicates = {}
    for tid, members in by_id.items():
        ch, others = choose_best_in_group(members)
        chosen.append(ch)
        duplicates[ch['content_hash']] = [{"source_id":o['source_id'], "source_repo": o['source_repo'], "content_hash": o['content_hash']} for o in others]

    # structural grouping
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
            ch, others = choose_best_in_group(members)
            chosen.append(ch)
            duplicates[ch['content_hash']] = [{"source_id":o['source_id'], "source_repo": o['source_repo'], "content_hash": o['content_hash']} for o in others]

    # fuzzy grouping for remaining
    if remaining:
        groups = fuzzy_grouping(remaining, similarity_threshold)
        for g in groups:
            if len(g) == 1:
                chosen.append(g[0])
            else:
                ch, others = choose_best_in_group(g)
                chosen.append(ch)
                duplicates[ch['content_hash']] = [{"source_id":o['source_id'], "source_repo": o['source_repo'], "content_hash": o['content_hash']} for o in others]

    # build index map
    idx_map = {}
    for item in chosen:
        src_label = sanitize_filename(item.get("source_id") or item.get("source_repo") or "unknown")
        short_hash = item["content_hash"][:12]
        filename = f"{src_label}__{short_hash}.yaml"
        idx_map[item["content_hash"]] = {
            "template_id": item.get("template_id"),
            "filename": str(Path("templates") / filename),
            "source_id": item.get("source_id"),
            "source_repo": item.get("source_repo"),
            "source_priority": item.get("source_priority"),
            "structural_hash": item.get("structural_hash"),
            "text_len": item.get("text_len"),
            "raw_url": item.get("raw_url_candidate"),
            "collected_at": datetime.utcnow().isoformat() + "Z",
            "duplicates": duplicates.get(item["content_hash"], [])
        }

    changed = write_outputs_if_changed(idx_map, chosen, dry_run=dry_run)
    return {"candidates": len(candidates), "chosen": len(chosen), "changed": changed}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--chunks-dir", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--similarity", type=float, default=SIMILARITY_THRESHOLD)
    args = p.parse_args()

    stats = process_all(Path(args.chunks_dir), args.similarity, dry_run=args.dry_run)
    log("Done:", stats)
    if not stats["changed"]:
        sys.exit(0)
    sys.exit(0)

if __name__ == "__main__":
    main()
