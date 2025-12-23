#!/usr/bin/env python3
import argparse, json, tempfile, shutil, io, re, hashlib
from pathlib import Path
from datetime import datetime
import zipfile, requests, yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCES_FILE = ROOT / "sources.json"

HEADERS = {"User-Agent": "TFnuclei-templates/1.0"}

MAX_FILES = 5000   # hard safety limit

def log(*a):
    print(datetime.utcnow().isoformat(), *a, flush=True)

def sanitize(s):
    return re.sub(r"[^\w\-.]+", "_", s).strip("_")[:200]

def download(url):
    r = requests.get(url, headers=HEADERS, timeout=60)
    r.raise_for_status()
    return r.content

def extract_zip(data, dest):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            z.extractall(dest)
        return True
    except zipfile.BadZipFile:
        return False

def find_yaml_files(d):
    for p in d.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".yaml", ".yml"):
            yield p

def canonicalize(text):
    try:
        obj = yaml.safe_load(text)
        dumped = yaml.safe_dump(obj, sort_keys=True)
        dumped = "\n".join(l.rstrip() for l in dumped.splitlines()) + "\n"
        return dumped, obj
    except Exception:
        norm = "\n".join(l.rstrip() for l in text.splitlines()) + "\n"
        return norm, None

def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()

def fetch_source(src, tmp):
    if src["type"] == "github_repo":
        owner, repo = src["repo"].split("/", 1)
        for br in ("main", "master"):
            url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{br}.zip"
            try:
                data = download(url)
                if extract_zip(data, tmp):
                    return
            except Exception:
                pass
    elif src["type"] == "zip":
        extract_zip(download(src["url"]), tmp)
    elif src["type"] in ("raw", "gist_raw"):
        (tmp / "single.yaml").write_bytes(download(src["url"]))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunk-index", type=int, required=True)
    ap.add_argument("--chunk-size", type=int, required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files_dir = out / "files"
    files_dir.mkdir(exist_ok=True)

    sources = json.loads(SOURCES_FILE.read_text())
    start = args.chunk_index * args.chunk_size
    end = start + args.chunk_size
    chunk = sources[start:end]

    written = 0

    for src in chunk:
        sid = sanitize(src.get("repo") or src.get("url") or "unknown")
        log("Fetching", sid)
        tmp = Path(tempfile.mkdtemp())
        try:
            fetch_source(src, tmp)
            for p in find_yaml_files(tmp):
                text = p.read_text(errors="replace")
                canon, _ = canonicalize(text)
                h = sha256(canon)
                fname = files_dir / f"{sid}__{h[:12]}.yaml"
                fname.write_text(canon)
                written += 1
                if written > MAX_FILES:
                    raise RuntimeError("Chunk too large; reduce CHUNK_SIZE")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    log(f"Wrote {written} templates to {out}")

if __name__ == "__main__":
    main()
