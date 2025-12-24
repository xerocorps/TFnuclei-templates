#!/usr/bin/env python3
import argparse, json, tempfile, shutil, io, re, hashlib
from pathlib import Path
import requests, zipfile, yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCES = json.loads((ROOT / "sources.json").read_text())

HEADERS = {"User-Agent": "TFnuclei-templates/1.0"}
MAX_FILES = 3000

def sanitize(s):
    return re.sub(r"[^\w\-.]+", "_", s)[:120]

def download(url):
    r = requests.get(url, headers=HEADERS, timeout=60)
    r.raise_for_status()
    return r.content

def extract_zip(data, dest):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(dest)

def find_yaml(d):
    for p in d.rglob("*"):
        if p.suffix.lower() in (".yml", ".yaml"):
            yield p

def canonical(text):
    try:
        obj = yaml.safe_load(text)
        return yaml.safe_dump(obj, sort_keys=True)
    except Exception:
        return text

def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()

def fetch_repo(repo, tmp):
    owner, name = repo.split("/")
    for br in ("main", "master"):
        try:
            data = download(f"https://github.com/{owner}/{name}/archive/refs/heads/{br}.zip")
            extract_zip(data, tmp)
            return
        except Exception:
            pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunk", type=int, required=True)
    ap.add_argument("--size", type=int, required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    start = args.chunk * args.size
    end = start + args.size
    chunk = SOURCES[start:end]

    written = 0

    for src in chunk:
        tmp = Path(tempfile.mkdtemp())
        try:
            fetch_repo(src["repo"], tmp)
            sid = sanitize(src["repo"])
            for f in find_yaml(tmp):
                text = f.read_text(errors="replace")
                c = canonical(text)
                h = sha(c)
                (out / f"{sid}__{h[:12]}.yaml").write_text(c)
                written += 1
                if written >= MAX_FILES:
                    raise RuntimeError("Chunk too large")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print(f"Wrote {written} files")

if __name__ == "__main__":
    main()
