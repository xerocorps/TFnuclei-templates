#!/usr/bin/env python3
"""
Fetch, extract, canonicalize and deduplicate nuclei templates.

Usage:
  python scripts/fetch_and_process.py [--dry-run]

Outputs:
  - templates/   (yaml files)
  - templates_index.json
"""
import os
import sys
import json
import shutil
import hashlib
import tempfile
import argparse
from pathlib import Path
from urllib.parse import urlparse
import requests
import zipfile
import io
import re
import yaml
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = ROOT / "templates"
SOURCES_FILE = ROOT / "sources.json"
INDEX_FILE = ROOT / "templates_index.json"

HEADERS = {"User-Agent":"TFnuclei-templates-fetcher/1.0 (+https://github.com/xerocorps/TFnuclei-templates)"}

def sanitize_filename(s: str) -> str:
    s = re.sub(r"[^\w\-.]+", "_", s)
    return s.strip("_")[:200]

def download_to_bytes(url, timeout=30):
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
    # Try to parse YAML, dump canonical form (sort keys) for consistent hashing
    try:
        obj = yaml.safe_load(text)
        canonical = yaml.safe_dump(obj, sort_keys=True)
        # normalize line endings and trailing spaces
        canonical = "\n".join(line.rstrip() for line in canonical.splitlines()) + "\n"
        return canonical
    except Exception:
        # if parsing fails, fallback to normalized whitespace
        return "\n".join(line.rstrip() for line in text.splitlines()) + "\n"

def get_template_id_from_yaml_obj(obj):
    if not isinstance(obj, dict):
        return None
    if "id" in obj and isinstance(obj["id"], str):
        return obj["id"].strip()
    if "info" in obj and isinstance(obj["info"], dict):
        if "name" in obj["info"] and isinstance(obj["info"]["name"], str):
            return obj["info"]["name"].strip()
        if "severity" in obj["info"] and isinstance(obj["info"]["severity"], str):
            # fallback (not ideal)
            return obj["info"]["severity"].strip()
    return None

def process_sources(dry_run=False):
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources = json.load(f)

    # recreate templates dir from scratch to ensure updates/removals are reflected
    if TEMPLATES_DIR.exists():
        shutil.rmtree(TEMPLATES_DIR)
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

    index = {}
    ids_seen = set()
    stats = {"downloaded":0, "yaml_found":0, "saved":0, "skipped_dups":0, "errors":0}

    for src in sources:
        sid = src.get("id") or src.get("repo") or src.get("url")
        typ = src.get("type")
        print(f"[{datetime.utcnow().isoformat()}] Processing {sid} ({typ})")
        try:
            tmpd = Path(tempfile.mkdtemp(prefix="tf_nuc_"))
            collected_yamls = []

            if typ == "github_repo":
                owner_repo = src["repo"]
                # try main then master branches as archives
                for branch in ("main", "master"):
                    zurl = f"https://github.com/{owner_repo}/archive/refs/heads/{branch}.zip"
                    try:
                        data = download_to_bytes(zurl)
                        stats["downloaded"] += 1
                        extracted_ok = try_extract_zip_bytes(data, tmpd)
                        if extracted_ok:
                            break
                    except Exception as e:
                        # try next
                        #print("branch fail", branch, e)
                        continue
                # continue even if not extracted; we'll still search tmpd (may be empty)

            elif typ == "zip":
                data = download_to_bytes(src["url"])
                stats["downloaded"] += 1
                if not try_extract_zip_bytes(data, tmpd):
                    # maybe zip of single file? try saving raw file
                    p = tmpd / "downloaded.zip"
                    p.write_bytes(data)
                    try:
                        with zipfile.ZipFile(str(p)) as z:
                            z.extractall(tmpd)
                    except Exception:
                        # not a zip, skip
                        raise RuntimeError("zip extraction failed")

            elif typ in ("raw", "gist_raw"):
                # direct YAML file
                raw_data = download_to_bytes(src["url"])
                stats["downloaded"] += 1
                # save as a file so subsequent logic can reuse
                fname = tmpd / sanitize_filename(sid) + ".yaml"
                fname.write_bytes(raw_data)
            else:
                print(f"Unknown source type: {typ}")
                continue

            # find all yaml files
            found = list(find_yaml_files(tmpd))
            stats["yaml_found"] += len(found)
            for p in found:
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    canonical = canonicalize_yaml_text(text)
                    # compute content hash as fallback id
                    content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                    parsed = None
                    try:
                        parsed = yaml.safe_load(text)
                    except Exception:
                        parsed = None

                    tid = None
                    if parsed:
                        tid = get_template_id_from_yaml_obj(parsed)
                    if not tid:
                        tid = content_hash[:12]

                    # if id already seen, treat as duplicate: skip
                    if tid in ids_seen:
                        stats["skipped_dups"] += 1
                        # record duplicate mapping optionally
                        continue

                    ids_seen.add(tid)

                    # create a filename: <source-id>__<tid>.yaml
                    src_label = sanitize_filename(sid)
                    out_name = f"{src_label}__{sanitize_filename(tid)}.yaml"
                    out_path = TEMPLATES_DIR / out_name

                    # save canonical text (not necessarily the parsed dump to preserve original)
                    out_path.write_text(canonical, encoding="utf-8")
                    index[tid] = {
                        "source_id": sid,
                        "source_type": typ,
                        "source_url": src.get("url") or src.get("repo"),
                        "filename": str(Path("templates")/out_name),
                        "sha256": content_hash,
                        "collected_at": datetime.utcnow().isoformat()+"Z"
                    }
                    stats["saved"] += 1
                except Exception as e:
                    print(f"error processing file {p}: {e}")
                    stats["errors"] += 1

        except Exception as e:
            print(f"ERROR downloading/processing source {sid}: {e}")
            stats["errors"] += 1
        finally:
            # cleanup temp dir
            try:
                shutil.rmtree(tmpd)
            except Exception:
                pass

    # write index
    if not dry_run:
        with open(INDEX_FILE, "w", encoding="utf-8") as fh:
            json.dump({"generated_at": datetime.utcnow().isoformat()+"Z", "count": len(index), "templates": index}, fh, indent=2)
    # print summary
    print("SUMMARY:", stats)
    return stats

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Don't write files (useful for testing)")
    args = parser.parse_args()
    stats = process_sources(dry_run=args.dry_run)
    if stats["errors"] > 0:
        sys.exit(2)
    sys.exit(0)

if __name__ == "__main__":
    main()
