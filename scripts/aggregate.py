#!/usr/bin/env python3
import json, hashlib, shutil
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
INDEX = ROOT / "templates_index.json"

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    artifacts = Path("artifacts")
    files = list(artifacts.glob("**/*.yaml"))

    unique = {}
    for f in files:
        h = sha(f)
        unique[h] = f

    if TEMPLATES.exists():
        shutil.rmtree(TEMPLATES)
    TEMPLATES.mkdir()

    index = {}
    for h, f in unique.items():
        dest = TEMPLATES / f.name
        shutil.copyfile(f, dest)
        index[h] = {
            "filename": f"templates/{f.name}",
            "raw_url": None
        }

    out = {
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "count": len(index),
        "templates": index
    }

    INDEX.write_text(json.dumps(out, indent=2))
    print(f"Saved {len(index)} templates")

if __name__ == "__main__":
    main()
