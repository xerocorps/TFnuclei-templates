#!/usr/bin/env python3
"""
Merge and deduplicate nuclei templates from all chunks.

Deduplication strategy (two-pass):
1. Primary: By content SHA256 hash (byte-exact matching)
2. Secondary: By semantic fingerprint (catches near-duplicates)
3. Tertiary: By normalized template ID (catches renamed variants)

Priority scoring:
- Templates are scored by severity + CVE age
- When duplicates exist, highest priority template wins

Usage:
    python merge_templates.py <artifacts_dir>
"""

import hashlib
import json
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timezone, date
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

import yaml

from semantic_fingerprint import (
    normalize_template_id,
    get_semantic_fingerprint,
    calculate_template_priority,
    extract_cve_year,
    choose_best_duplicate,
)

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = ROOT / "templates"
INDEX_FILE = ROOT / "templates_index.json"
STATS_FILE = ROOT / "stats.json"


def content_hash(content: bytes) -> str:
    """Generate SHA256 hash of content."""
    return hashlib.sha256(content).hexdigest()


def get_template_metadata(content: str) -> Dict[str, Any]:
    """Extract metadata from YAML template content."""
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return {}
        
        info = data.get("info", {})
        return {
            "id": data.get("id"),
            "name": info.get("name"),
            "author": info.get("author"),
            "severity": info.get("severity"),
            "description": info.get("description"),
            "tags": info.get("tags"),
            "reference": info.get("reference"),
            "_raw_data": data,  # Keep raw data for priority calculation
        }
    except yaml.YAMLError:
        return {}


def merge_reports(artifacts_dir: Path) -> Dict[str, Any]:
    """Merge all fetch reports from chunks."""
    merged = {
        "total_sources": 0,
        "successful": 0,
        "failed": 0,
        "skipped": 0,
        "total_templates_found": 0,
        "total_templates_saved": 0,
        "failed_sources": [],
    }
    
    for report_file in artifacts_dir.rglob("fetch_report.json"):
        try:
            report = json.loads(report_file.read_text())
            merged["total_sources"] += report.get("total_sources", 0)
            merged["successful"] += report.get("successful", 0)
            merged["failed"] += report.get("failed", 0)
            merged["skipped"] += report.get("skipped", 0)
            merged["total_templates_found"] += report.get("total_templates_found", 0)
            merged["total_templates_saved"] += report.get("total_templates_saved", 0)
            
            # Collect failed sources
            for result in report.get("results", []):
                if result.get("status") == "error":
                    merged["failed_sources"].append({
                        "source": result.get("source"),
                        "error": result.get("error"),
                    })
        except Exception as e:
            print(f"Warning: Could not parse {report_file}: {e}", file=sys.stderr)
    
    return merged


def main():
    if len(sys.argv) < 2:
        print("Usage: python merge_templates.py <artifacts_dir>", file=sys.stderr)
        sys.exit(1)
    
    artifacts_dir = Path(sys.argv[1])
    if not artifacts_dir.exists():
        print(f"Error: Artifacts directory not found: {artifacts_dir}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Merging templates from {artifacts_dir}")
    today = date.today()
    
    # Find all YAML files in artifacts
    yaml_files = list(artifacts_dir.rglob("*.yaml"))
    yaml_files = [f for f in yaml_files if f.name != "fetch_report.json"]
    
    print(f"Found {len(yaml_files)} YAML files")
    
    # === PASS 1: Exact content hash deduplication ===
    print("\n=== Pass 1: Exact content hash deduplication ===")
    exact_templates: Dict[str, Dict[str, Any]] = {}
    
    for yaml_file in yaml_files:
        try:
            content = yaml_file.read_bytes()
            hash_key = content_hash(content)
            
            if hash_key in exact_templates:
                continue
            
            text_content = content.decode("utf-8", errors="replace")
            metadata = get_template_metadata(text_content)
            
            exact_templates[hash_key] = {
                "file": yaml_file,
                "content": content,
                "text": text_content,
                "metadata": metadata,
                "hash": hash_key,
            }
            
        except Exception as e:
            print(f"Warning: Could not process {yaml_file}: {e}", file=sys.stderr)
    
    print(f"After exact dedup: {len(exact_templates)} templates")
    
    # === PASS 2: Semantic fingerprint deduplication ===
    print("\n=== Pass 2: Semantic fingerprint deduplication ===")
    semantic_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    for hash_key, data in exact_templates.items():
        raw_data = data["metadata"].get("_raw_data", {})
        if raw_data:
            fingerprint = get_semantic_fingerprint(raw_data)
            data["semantic_fingerprint"] = fingerprint
            semantic_groups[fingerprint].append(data)
        else:
            # If no raw data, use content hash as fingerprint
            data["semantic_fingerprint"] = hash_key
            semantic_groups[hash_key].append(data)
    
    # For each semantic group, choose the best template
    semantic_templates: Dict[str, Dict[str, Any]] = {}
    duplicates_removed_semantic = 0
    
    for fingerprint, group in semantic_groups.items():
        if len(group) == 1:
            semantic_templates[fingerprint] = group[0]
        else:
            # Multiple templates with same semantic fingerprint
            # Calculate priority for each and choose best
            for t in group:
                raw_data = t["metadata"].get("_raw_data", {})
                priority, priority_meta = calculate_template_priority(raw_data, today)
                t["priority"] = priority
                t["priority_meta"] = priority_meta
            
            # Sort by priority (descending) and pick best
            group.sort(key=lambda x: x.get("priority", 0), reverse=True)
            semantic_templates[fingerprint] = group[0]
            duplicates_removed_semantic += len(group) - 1
    
    print(f"After semantic dedup: {len(semantic_templates)} templates ({duplicates_removed_semantic} removed)")
    
    # === PASS 3: Normalized ID deduplication ===
    print("\n=== Pass 3: Normalized ID deduplication ===")
    id_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    for fingerprint, data in semantic_templates.items():
        template_id = data["metadata"].get("id")
        if template_id:
            normalized_id = normalize_template_id(str(template_id))
            if normalized_id:
                data["normalized_id"] = normalized_id
                id_groups[normalized_id].append(data)
            else:
                # Empty normalized ID, use fingerprint
                id_groups[fingerprint].append(data)
        else:
            # No ID, use fingerprint
            id_groups[fingerprint].append(data)
    
    # For each ID group, choose the best template
    final_templates: Dict[str, Dict[str, Any]] = {}
    duplicates_removed_id = 0
    
    for norm_id, group in id_groups.items():
        if len(group) == 1:
            final_templates[group[0]["hash"]] = group[0]
        else:
            # Multiple templates with same normalized ID
            for t in group:
                if "priority" not in t:
                    raw_data = t["metadata"].get("_raw_data", {})
                    priority, priority_meta = calculate_template_priority(raw_data, today)
                    t["priority"] = priority
                    t["priority_meta"] = priority_meta
            
            group.sort(key=lambda x: x.get("priority", 0), reverse=True)
            best = group[0]
            final_templates[best["hash"]] = best
            duplicates_removed_id += len(group) - 1
    
    print(f"After ID dedup: {len(final_templates)} templates ({duplicates_removed_id} removed)")
    
    total_duplicates = len(yaml_files) - len(final_templates)
    print(f"\nTotal duplicates removed: {total_duplicates}")
    
    # Prepare output directory
    if TEMPLATES_DIR.exists():
        shutil.rmtree(TEMPLATES_DIR)
    TEMPLATES_DIR.mkdir(parents=True)
    
    # Write templates and build index
    index: Dict[str, Dict[str, Any]] = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    
    for hash_key, data in final_templates.items():
        metadata = data["metadata"]
        template_id = metadata.get("id")
        raw_data = metadata.get("_raw_data", {})
        
        # Calculate priority if not already done
        if "priority" not in data:
            priority, priority_meta = calculate_template_priority(raw_data, today)
            data["priority"] = priority
            data["priority_meta"] = priority_meta
        
        # Generate filename
        if template_id:
            id_str = str(template_id)
            safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in id_str)
            filename = f"{safe_id}.yaml"
        else:
            filename = f"template_{hash_key[:16]}.yaml"
        
        # Handle filename conflicts
        dest = TEMPLATES_DIR / filename
        counter = 1
        while dest.exists():
            stem = dest.stem
            if counter == 1:
                dest = TEMPLATES_DIR / f"{stem}_{counter}.yaml"
            else:
                # Remove previous counter suffix
                base_stem = stem.rsplit('_', 1)[0]
                dest = TEMPLATES_DIR / f"{base_stem}_{counter}.yaml"
            counter += 1
        
        # Write template
        dest.write_bytes(data["content"])
        
        # Track severity
        severity = (metadata.get("severity") or "unknown").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["unknown"] += 1
        
        # Add to index with priority info
        cve_year = extract_cve_year(raw_data)
        index[hash_key] = {
            "filename": f"templates/{dest.name}",
            "id": template_id,
            "name": metadata.get("name"),
            "severity": severity,
            "tags": metadata.get("tags"),
            "priority": data.get("priority", 0),
            "cve_year": cve_year,
        }
    
    # Merge fetch reports for statistics
    fetch_stats = merge_reports(artifacts_dir)
    
    # Generate index file
    now = datetime.now(timezone.utc).isoformat()
    index_data = {
        "last_updated": now,
        "count": len(index),
        "deduplication": {
            "exact_hash": len(exact_templates),
            "after_semantic": len(semantic_templates),
            "final": len(final_templates),
        },
        "templates": index,
    }
    INDEX_FILE.write_text(json.dumps(index_data, indent=2))
    
    # Generate stats file
    stats_data = {
        "last_updated": now,
        "total_templates": len(final_templates),
        "duplicates_removed": total_duplicates,
        "deduplication_breakdown": {
            "exact_content": len(yaml_files) - len(exact_templates),
            "semantic_fingerprint": duplicates_removed_semantic,
            "normalized_id": duplicates_removed_id,
        },
        "sources": {
            "total": fetch_stats["total_sources"],
            "successful": fetch_stats["successful"],
            "failed": fetch_stats["failed"],
            "skipped": fetch_stats["skipped"],
        },
        "severity_breakdown": severity_counts,
        "failed_sources": fetch_stats["failed_sources"][:20],
    }
    STATS_FILE.write_text(json.dumps(stats_data, indent=2))
    
    print(f"\n{'='*50}")
    print(f"✓ Saved {len(final_templates)} unique templates to {TEMPLATES_DIR}")
    print(f"✓ Index saved to {INDEX_FILE}")
    print(f"✓ Stats saved to {STATS_FILE}")
    print(f"\nDeduplication breakdown:")
    print(f"  Exact content:        {len(yaml_files) - len(exact_templates)} removed")
    print(f"  Semantic fingerprint: {duplicates_removed_semantic} removed")
    print(f"  Normalized ID:        {duplicates_removed_id} removed")
    print(f"\nSeverity breakdown:")
    for sev, count in severity_counts.items():
        if count > 0:
            print(f"  {sev}: {count}")
    print(f"\nSource statistics:")
    print(f"  Total sources: {fetch_stats['total_sources']}")
    print(f"  Successful: {fetch_stats['successful']}")
    print(f"  Failed: {fetch_stats['failed']}")
    print(f"  Skipped: {fetch_stats['skipped']}")


if __name__ == "__main__":
    main()
