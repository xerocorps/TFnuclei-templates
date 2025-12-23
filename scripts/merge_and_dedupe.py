#!/usr/bin/env python3
import sys, json, shutil, hashlib
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
INDEX = ROOT / "templates_index.json"

def sha256(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    artifacts = Path(sys.argv[1])
    candidates = []

    for d in artifacts.glob("chunk-*"):
        files = d / "files"
        if files.exists():
            for f in files.glob("*.yaml"):
                candidates.append(f)

    dedup = {}
    for f in candidates:
        h = sha256(f)
        if h not in dedup:
            dedup[h] = f

    if TEMPLATES.exists():
        shutil.rmtree(TEMPLATES)
    TEMPLATES.mkdir()

    index = {}
    for h, f in dedup.items():
        name = f.name
        dest = TEMPLATES / name
        shutil.copyfile(f, dest)
        index[h] = {
            "filename": f"templates/{name}",
            "raw_url": None,
            "added": datetime.utcnow().isoformat() + "Z"
        }

    index_obj = {
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "count": len(index),
        "templates": index
    }

    INDEX.write_text(json.dumps(index_obj, indent=2))

if __name__ == "__main__":
    main()
