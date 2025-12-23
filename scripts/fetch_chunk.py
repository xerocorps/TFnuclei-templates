#!/usr/bin/env python3
"""
Fetch a chunk of sources, canonicalize YAMLs and write a compact artifact.

Produces:
 out_dir/
   candidates.json   # list of candidate metadata
   files/
     <source_label>__<shorthash>.yaml

Usage:
 python scripts/fetch_chunk.py --chunk-index 0 --chunk-size 50 --out artifacts/chunk-0
"""
import argparse, json, os, sys, tempfile, shutil, zipfile, io, re, hashlib
from pathlib import Path
from datetime import datetime
import requests, yaml, zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES_FILE = ROOT / "sources.json"

HEADERS = {"User-Agent":"TFnuclei-templates-fetcher/1.0 (+https://github.com/yourorg/TFnuclei-templates)"}

def log(*a, **k):
    print(datetime.utcnow().isoformat(), *a, **k)

def sanitize_filename(s: str) -> str:
    return re.sub(r"[^\w\-.]+", "_", s).strip("_")[:200]

def download_bytes(url):
    r = requests.get(url, headers=HEADERS, timeout=60, stream=True)
    r.raise_for_status()
    return r.content

def try_extract_zip_bytes(data: bytes, dest: Path):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            z.extractall(dest)
        return True
    except zipfile.BadZipFile:
        return False

def find_yaml_files(d: Path):
    for p in d.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".yml", ".yaml"):
            yield p

def canonicalize(text):
    try:
        obj = yaml.safe_load(text)
        canonical = yaml.safe_dump(obj, sort_keys=True)
        canonical = "\n".join(line.rstrip() for line in canonical.splitlines()) + "\n"
        return canonical, obj
    except Exception:
        normalized = "\n".join(line.rstrip() for line in text.splitlines()) + "\n"
        return normalized, None

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

def structural_hash(obj):
    try:
        s = yaml.safe_dump(structuralize(obj), sort_keys=True)
        return hashlib.sha256(s.encode("utf-8")).hexdigest()
    except Exception:
        return None

def compute_sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def source_identifier(source):
    if source.get("repo"):
        return source["repo"].replace("/", "__")
    if source.get("url"):
        return sanitize_filename(source["url"])
    return "unknown"

def fetch_and_extract(source, tmpd: Path):
    typ = source.get("type")
    if typ == "github_repo":
        owner_repo = source["repo"]
        for branch in ("main","master"):
            zurl = f"https://github.com/{owner_repo}/archive/refs/heads/{branch}.zip"
            try:
                data = download_bytes(zurl)
                if try_extract_zip_bytes(data, tmpd):
                    return {"repo_owner": owner_repo.split("/",1)[0], "repo_name": owner_repo.split("/",1)[1], "branch": branch}
            except Exception:
                continue
        return {}
    elif typ == "zip":
        data = download_bytes(source.get("url"))
        # try to detect github archive as best-effort
        try:
            m = re.search(r"github\.com/([^/]+)/([^/]+)/archive/refs/heads/([^/]+)\.zip", source.get("url",""))
            if m:
                info = {"repo_owner": m.group(1), "repo_name": m.group(2), "branch": m.group(3), "zip_from_github": True}
            else:
                info = {}
        except Exception:
            info = {}
        if try_extract_zip_bytes(data, tmpd):
            return info
        # fallback: save the raw bytes as downloaded.zip
        (tmpd / "downloaded.zip").write_bytes(data)
        return info
    elif typ in ("raw","gist_raw"):
        data = download_bytes(source.get("url"))
        f = tmpd / f"{sanitize_filename(source_identifier(source))}.yaml"
        f.write_bytes(data)
        return {"raw_url": source.get("url")}
    else:
        return {}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--chunk-index", type=int, default=0)
    p.add_argument("--chunk-size", type=int, default=50)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    out_dir = Path(args.out)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files_dir = out_dir / "files"
    files_dir.mkdir()

    if not SOURCES_FILE.exists():
        log("sources.json missing")
        return 2

    sources = json.load(open(SOURCES_FILE, "r", encoding="utf-8"))
    start = args.chunk_index * args.chunk_size
    end = start + args.chunk_size
    slice_sources = sources[start:end]
    log(f"Processing sources {start}..{end} (count {len(slice_sources)})")

    candidates = []
    for src in slice_sources:
        sid = source_identifier(src)
        priority = int(src.get("priority", 0))
        log("Fetching", sid)
        tmpd = Path(tempfile.mkdtemp(prefix="tf_chunk_"))
        try:
            meta = fetch_and_extract(src, tmpd)
            # find yamls
            for pth in find_yaml_files(tmpd):
                try:
                    text = pth.read_text(encoding="utf-8", errors="replace")
                    canonical, parsed = canonicalize(text)
                    ch = compute_sha(canonical)
                    sh = structural_hash(parsed) if parsed is not None else None
                    tid = None
                    if parsed and isinstance(parsed, dict):
                        if "id" in parsed and isinstance(parsed["id"], str):
                            tid = parsed["id"].strip()
                        elif "info" in parsed and isinstance(parsed["info"], dict) and parsed["info"].get("name"):
                            tid = parsed["info"]["name"].strip()
                    # create canonical file name and write it
                    fname = f"{sanitize_filename(sid)}__{ch[:12]}.yaml"
                    fpath = files_dir / fname
                    fpath.write_text(canonical, encoding="utf-8")
                    # compute raw_url candidate if possible (best-effort)
                    raw_url = None
                    if meta.get("raw_url"):
                        raw_url = meta.get("raw_url")
                    else:
                        # if meta has github info and file path within archive, try to build raw url
                        # find relative path inside tmpd
                        try:
                            rel = pth.relative_to(tmpd)
                            parts = list(rel.parts)
                            if meta.get("repo_owner") and meta.get("repo_name") and meta.get("branch"):
                                inner = "/".join(parts[1:]) if len(parts) > 1 else "/".join(parts)
                                raw_url = f"https://raw.githubusercontent.com/{meta['repo_owner']}/{meta['repo_name']}/{meta['branch']}/{inner}"
                        except Exception:
                            pass
                    candidates.append({
                        "content_hash": ch,
                        "structural_hash": sh,
                        "template_id": tid,
                        "source_repo": src.get("repo"),
                        "source_url_field": src.get("url"),
                        "source_id": sid,
                        "source_priority": priority,
                        "relpath": f"files/{fname}",
                        "text_len": len(canonical.splitlines()),
                        "raw_url_candidate": raw_url
                    })
                except Exception as e:
                    log("Error processing file", pth, e)
        except Exception as e:
            log("Fetch error for", sid, e)
        finally:
            try:
                shutil.rmtree(tmpd)
            except Exception:
                pass

    # write candidates.json
    with open(out_dir / "candidates.json", "w", encoding="utf-8") as fh:
        json.dump({"generated_at": datetime.utcnow().isoformat() + "Z", "count": len(candidates), "candidates": candidates}, fh, indent=2)

    log("Wrote", (out_dir))

if __name__ == "__main__":
    main()
