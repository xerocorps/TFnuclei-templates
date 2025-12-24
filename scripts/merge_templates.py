#!/usr/bin/env python3
"""
Merge and deduplicate nuclei templates from all chunks.

Deduplication strategy:
1. Primary: By template 'id' field (if present and unique)
2. Fallback: By content SHA256 hash

Usage:
    python merge_templates.py <artifacts_dir>
"""

import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

import yaml

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
    
    # Find all YAML files in artifacts
    yaml_files = list(artifacts_dir.rglob("*.yaml"))
    # Exclude fetch_report.json which may have been inadvertently named
    yaml_files = [f for f in yaml_files if f.name != "fetch_report.json"]
    
    print(f"Found {len(yaml_files)} YAML files")
    
    # Deduplicate by content hash and template ID
    # Use hash as primary key, but prefer templates with IDs
    templates: Dict[str, Dict[str, Any]] = {}
    id_to_hash: Dict[str, str] = {}  # Track template IDs to detect conflicts
    
    for yaml_file in yaml_files:
        try:
            content = yaml_file.read_bytes()
            hash_key = content_hash(content)
            
            # Skip if we already have this exact content
            if hash_key in templates:
                continue
            
            text_content = content.decode("utf-8", errors="replace")
            metadata = get_template_metadata(text_content)
            template_id = metadata.get("id")
            
            # If template has an ID, check for ID conflicts
            if template_id:
                if template_id in id_to_hash:
                    # We have a template with the same ID but different content
                    # Keep the existing one (first wins)
                    continue
                id_to_hash[template_id] = hash_key
            
            templates[hash_key] = {
                "file": yaml_file,
                "content": content,
                "metadata": metadata,
            }
            
        except Exception as e:
            print(f"Warning: Could not process {yaml_file}: {e}", file=sys.stderr)
    
    print(f"Deduplicated to {len(templates)} unique templates")
    
    # Prepare output directory
    if TEMPLATES_DIR.exists():
        shutil.rmtree(TEMPLATES_DIR)
    TEMPLATES_DIR.mkdir(parents=True)
    
    # Write templates and build index
    index: Dict[str, Dict[str, Any]] = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    
    for hash_key, data in templates.items():
        metadata = data["metadata"]
        template_id = metadata.get("id")
        
        # Generate filename
        if template_id:
            # Use template ID as filename (sanitized)
            # Convert to string in case ID is an integer
            id_str = str(template_id)
            safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in id_str)
            filename = f"{safe_id}.yaml"
        else:
            # Use hash as filename
            filename = f"template_{hash_key[:16]}.yaml"
        
        # Handle filename conflicts
        dest = TEMPLATES_DIR / filename
        counter = 1
        while dest.exists():
            stem = dest.stem
            dest = TEMPLATES_DIR / f"{stem}_{counter}.yaml"
            counter += 1
        
        # Write template
        dest.write_bytes(data["content"])
        
        # Track severity
        severity = (metadata.get("severity") or "unknown").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["unknown"] += 1
        
        # Add to index
        index[hash_key] = {
            "filename": f"templates/{dest.name}",
            "id": template_id,
            "name": metadata.get("name"),
            "severity": severity,
            "tags": metadata.get("tags"),
        }
    
    # Merge fetch reports for statistics
    fetch_stats = merge_reports(artifacts_dir)
    
    # Generate index file
    now = datetime.now(timezone.utc).isoformat()
    index_data = {
        "last_updated": now,
        "count": len(index),
        "templates": index,
    }
    INDEX_FILE.write_text(json.dumps(index_data, indent=2))
    
    # Generate stats file
    stats_data = {
        "last_updated": now,
        "total_templates": len(templates),
        "duplicates_removed": fetch_stats["total_templates_saved"] - len(templates),
        "sources": {
            "total": fetch_stats["total_sources"],
            "successful": fetch_stats["successful"],
            "failed": fetch_stats["failed"],
            "skipped": fetch_stats["skipped"],
        },
        "severity_breakdown": severity_counts,
        "failed_sources": fetch_stats["failed_sources"][:20],  # Limit to 20
    }
    STATS_FILE.write_text(json.dumps(stats_data, indent=2))
    
    print(f"\n{'='*50}")
    print(f"✓ Saved {len(templates)} unique templates to {TEMPLATES_DIR}")
    print(f"✓ Index saved to {INDEX_FILE}")
    print(f"✓ Stats saved to {STATS_FILE}")
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
