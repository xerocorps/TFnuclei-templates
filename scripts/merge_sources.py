#!/usr/bin/env python3
"""
Merge newly discovered sources into existing sources.json.

Handles:
- Deduplication by repo/URL
- Preserves existing skip/priority flags
- Adds discovered_at timestamp to new entries

Usage:
    python merge_sources.py sources.json new_sources.json
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Set


def log(message: str, level: str = "INFO") -> None:
    """Print log message."""
    print(f"[{level}] {message}", file=sys.stderr)


def get_source_key(source: Dict[str, Any]) -> str:
    """Get unique key for a source."""
    if source.get("type") == "github_repo":
        return f"repo:{source.get('repo', '').lower()}"
    elif source.get("type") == "zip":
        return f"zip:{source.get('url', '').lower()}"
    elif source.get("type") == "raw":
        return f"raw:{source.get('url', '').lower()}"
    return ""


def merge_sources(existing_path: Path, new_path: Path) -> List[Dict[str, Any]]:
    """
    Merge new sources into existing sources.
    
    Returns merged list.
    """
    # Load existing sources
    existing_sources = []
    if existing_path.exists():
        existing_sources = json.loads(existing_path.read_text())
    
    # Build index of existing sources
    existing_keys: Set[str] = set()
    for source in existing_sources:
        key = get_source_key(source)
        if key:
            existing_keys.add(key)
    
    log(f"Loaded {len(existing_sources)} existing sources")
    
    # Load new sources
    new_sources = []
    if new_path.exists():
        new_sources = json.loads(new_path.read_text())
    
    log(f"Found {len(new_sources)} newly discovered sources")
    
    # Filter and merge
    added_count = 0
    for source in new_sources:
        key = get_source_key(source)
        if not key:
            continue
        
        if key in existing_keys:
            log(f"  Skipping duplicate: {key}")
            continue
        
        # Add to existing sources
        existing_sources.append(source)
        existing_keys.add(key)
        added_count += 1
        
        repo_or_url = source.get("repo") or source.get("url", "")
        log(f"  Added: {repo_or_url}")
    
    log(f"\nMerge complete: {added_count} new sources added")
    log(f"Total sources: {len(existing_sources)}")
    
    return existing_sources


def main():
    if len(sys.argv) < 3:
        print("Usage: python merge_sources.py <sources.json> <new_sources.json>", file=sys.stderr)
        sys.exit(1)
    
    existing_path = Path(sys.argv[1])
    new_path = Path(sys.argv[2])
    
    if not new_path.exists():
        log(f"No new sources file found: {new_path}")
        sys.exit(0)
    
    merged = merge_sources(existing_path, new_path)
    
    # Save merged sources
    existing_path.write_text(json.dumps(merged, indent=2))
    log(f"Saved merged sources to {existing_path}")


if __name__ == "__main__":
    main()
