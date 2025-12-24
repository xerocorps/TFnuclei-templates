#!/usr/bin/env python3
"""
Fetch nuclei templates from various sources.

Supports:
- github_repo: Download and extract from GitHub repository
- zip: Direct ZIP archive download
- raw: Single YAML file download

Usage:
    python fetch_sources.py --start 0 --end 50 --out artifacts/chunk-0
"""

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, Generator, Dict, Any, List

import requests
import yaml
import zipfile

from constants import (
    USER_AGENT,
    REQUEST_TIMEOUT,
    MAX_RETRIES,
    RETRY_DELAY,
    RATE_LIMIT_DELAY,
    MAX_TEMPLATE_SIZE,
    MAX_REPO_SIZE,
    YAML_EXTENSIONS,
    GITHUB_BRANCHES,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCES_FILE = ROOT / "sources.json"

# Session for connection pooling
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})


class FetchError(Exception):
    """Custom exception for fetch failures."""
    pass


def log(message: str, level: str = "INFO") -> None:
    """Print log message with timestamp."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}", file=sys.stderr)


def sanitize_filename(s: str) -> str:
    """Create a safe filename from a string."""
    # Replace unsafe characters with underscores
    safe = re.sub(r"[^\w\-.]", "_", s)
    # Collapse multiple underscores
    safe = re.sub(r"_+", "_", safe)
    # Limit length
    return safe[:100]


def content_hash(content: str) -> str:
    """Generate SHA256 hash of content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def download_with_retry(url: str, max_size: int = MAX_REPO_SIZE) -> bytes:
    """
    Download URL content with retry logic.
    
    Args:
        url: URL to download
        max_size: Maximum allowed download size
        
    Returns:
        Downloaded content as bytes
        
    Raises:
        FetchError: If download fails after retries
    """
    last_error = None
    
    for attempt in range(MAX_RETRIES):
        try:
            if attempt > 0:
                delay = RETRY_DELAY * (2 ** (attempt - 1))
                log(f"Retry {attempt}/{MAX_RETRIES} after {delay}s: {url}")
                time.sleep(delay)
            
            response = session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                stream=True,
                allow_redirects=True,
            )
            response.raise_for_status()
            
            # Check content length before downloading
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_size:
                raise FetchError(f"Content too large: {content_length} bytes > {max_size} limit")
            
            # Download with size limit
            chunks = []
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if total_size > max_size:
                    raise FetchError(f"Download exceeded size limit: {max_size} bytes")
                chunks.append(chunk)
            
            return b"".join(chunks)
            
        except requests.exceptions.RequestException as e:
            last_error = e
            continue
        except FetchError:
            raise
    
    raise FetchError(f"Failed after {MAX_RETRIES} attempts: {last_error}")


def extract_zip(data: bytes, dest: Path) -> None:
    """Extract ZIP archive to destination directory."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            # Security: Check for zip bombs and path traversal
            total_size = sum(info.file_size for info in zf.infolist())
            if total_size > MAX_REPO_SIZE * 2:
                raise FetchError(f"ZIP contents too large: {total_size} bytes")
            
            for info in zf.infolist():
                # Skip directories and unsafe paths
                if info.is_dir():
                    continue
                if ".." in info.filename or info.filename.startswith("/"):
                    continue
                    
                zf.extract(info, dest)
    except zipfile.BadZipFile as e:
        raise FetchError(f"Invalid ZIP file: {e}")


def find_yaml_files(directory: Path) -> Generator[Path, None, None]:
    """Find all YAML files in directory recursively."""
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix.lower() in YAML_EXTENSIONS:
            yield path


def normalize_yaml(content: str) -> Optional[str]:
    """
    Normalize YAML content for consistent hashing.
    
    Returns None if YAML is invalid.
    """
    try:
        # Parse YAML
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return None
        
        # Must have at least an 'id' field which is standard for nuclei templates
        # But some templates might not have it, so we'll be lenient
        
        # Re-serialize with sorted keys for consistent hashing
        return yaml.safe_dump(data, sort_keys=True, default_flow_style=False)
    except yaml.YAMLError:
        return None


def get_template_id(content: str) -> Optional[str]:
    """Extract template ID from YAML content."""
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            return data.get("id")
    except yaml.YAMLError:
        pass
    return None


def fetch_github_repo(repo: str, dest: Path) -> None:
    """
    Download and extract a GitHub repository.
    
    Args:
        repo: Repository in "owner/name" format
        dest: Destination directory
    """
    owner, name = repo.split("/", 1)
    
    for branch in GITHUB_BRANCHES:
        url = f"https://github.com/{owner}/{name}/archive/refs/heads/{branch}.zip"
        try:
            log(f"Trying {repo} @ {branch}")
            data = download_with_retry(url)
            extract_zip(data, dest)
            log(f"Successfully downloaded {repo}")
            return
        except FetchError as e:
            log(f"Failed {branch} branch: {e}", "WARN")
            continue
    
    raise FetchError(f"Could not download {repo} from any branch")


def fetch_zip(url: str, dest: Path) -> None:
    """Download and extract a ZIP archive."""
    log(f"Downloading ZIP: {url}")
    data = download_with_retry(url)
    extract_zip(data, dest)
    log(f"Successfully extracted ZIP")


def fetch_raw(url: str) -> tuple[str, str]:
    """
    Download a single YAML file.
    
    Returns:
        Tuple of (filename, content)
    """
    log(f"Downloading raw: {url}")
    data = download_with_retry(url, max_size=MAX_TEMPLATE_SIZE)
    content = data.decode("utf-8", errors="replace")
    
    # Extract filename from URL
    filename = url.split("/")[-1]
    if not filename.lower().endswith(YAML_EXTENSIONS):
        filename = filename + ".yaml"
    
    return filename, content


def process_source(source: Dict[str, Any], output_dir: Path) -> Dict[str, Any]:
    """
    Process a single source and save templates.
    
    Args:
        source: Source configuration dict
        output_dir: Output directory for templates
        
    Returns:
        Result dict with status and counts
    """
    source_type = source.get("type", "github_repo")
    result = {
        "source": source,
        "status": "success",
        "templates_found": 0,
        "templates_saved": 0,
        "error": None,
    }
    
    # Check if source is disabled
    if source.get("skip"):
        result["status"] = "skipped"
        return result
    
    # Rate limiting
    time.sleep(RATE_LIMIT_DELAY)
    
    try:
        if source_type == "github_repo":
            repo = source.get("repo")
            if not repo or "/" not in repo:
                raise FetchError(f"Invalid repo format: {repo}")
            
            with tempfile.TemporaryDirectory() as tmpdir:
                tmppath = Path(tmpdir)
                fetch_github_repo(repo, tmppath)
                
                # Process YAML files
                source_id = sanitize_filename(repo)
                for yaml_file in find_yaml_files(tmppath):
                    result["templates_found"] += 1
                    
                    try:
                        # Check file size
                        if yaml_file.stat().st_size > MAX_TEMPLATE_SIZE:
                            continue
                        
                        content = yaml_file.read_text(errors="replace")
                        normalized = normalize_yaml(content)
                        if not normalized:
                            continue
                        
                        # Generate unique filename
                        file_hash = content_hash(normalized)[:12]
                        stem = sanitize_filename(yaml_file.stem)
                        out_name = f"{source_id}__{stem}__{file_hash}.yaml"
                        
                        (output_dir / out_name).write_text(normalized)
                        result["templates_saved"] += 1
                        
                    except Exception as e:
                        log(f"Error processing {yaml_file}: {e}", "WARN")
                        continue
        
        elif source_type == "zip":
            url = source.get("url")
            if not url:
                raise FetchError("Missing URL for zip source")
            
            with tempfile.TemporaryDirectory() as tmpdir:
                tmppath = Path(tmpdir)
                fetch_zip(url, tmppath)
                
                # Process YAML files
                source_id = sanitize_filename(url.split("/")[-1].replace(".zip", ""))
                for yaml_file in find_yaml_files(tmppath):
                    result["templates_found"] += 1
                    
                    try:
                        if yaml_file.stat().st_size > MAX_TEMPLATE_SIZE:
                            continue
                        
                        content = yaml_file.read_text(errors="replace")
                        normalized = normalize_yaml(content)
                        if not normalized:
                            continue
                        
                        file_hash = content_hash(normalized)[:12]
                        stem = sanitize_filename(yaml_file.stem)
                        out_name = f"{source_id}__{stem}__{file_hash}.yaml"
                        
                        (output_dir / out_name).write_text(normalized)
                        result["templates_saved"] += 1
                        
                    except Exception as e:
                        log(f"Error processing {yaml_file}: {e}", "WARN")
                        continue
        
        elif source_type == "raw":
            url = source.get("url")
            if not url:
                raise FetchError("Missing URL for raw source")
            
            filename, content = fetch_raw(url)
            result["templates_found"] = 1
            
            normalized = normalize_yaml(content)
            if normalized:
                source_id = sanitize_filename(url.split("/")[-2] if "/" in url else "raw")
                file_hash = content_hash(normalized)[:12]
                stem = sanitize_filename(Path(filename).stem)
                out_name = f"{source_id}__{stem}__{file_hash}.yaml"
                
                (output_dir / out_name).write_text(normalized)
                result["templates_saved"] = 1
        
        else:
            raise FetchError(f"Unknown source type: {source_type}")
    
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        log(f"Source failed: {e}", "ERROR")
    
    return result


def main():
    parser = argparse.ArgumentParser(description="Fetch nuclei templates from sources")
    parser.add_argument("--start", type=int, required=True, help="Start index in sources.json")
    parser.add_argument("--end", type=int, required=True, help="End index in sources.json (exclusive)")
    parser.add_argument("--out", type=str, required=True, help="Output directory")
    args = parser.parse_args()
    
    # Load sources
    sources: List[Dict[str, Any]] = json.loads(SOURCES_FILE.read_text())
    chunk = sources[args.start:args.end]
    
    log(f"Processing sources {args.start} to {args.end} ({len(chunk)} sources)")
    
    # Create output directory
    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Process each source
    results = []
    for i, source in enumerate(chunk):
        log(f"Processing source {args.start + i + 1}/{args.start + len(chunk)}: {source}")
        result = process_source(source, output_dir)
        results.append(result)
        log(f"  -> {result['status']}: {result['templates_saved']}/{result['templates_found']} templates")
    
    # Save results report
    report = {
        "chunk_start": args.start,
        "chunk_end": args.end,
        "total_sources": len(chunk),
        "successful": sum(1 for r in results if r["status"] == "success"),
        "failed": sum(1 for r in results if r["status"] == "error"),
        "skipped": sum(1 for r in results if r["status"] == "skipped"),
        "total_templates_found": sum(r["templates_found"] for r in results),
        "total_templates_saved": sum(r["templates_saved"] for r in results),
        "results": results,
    }
    
    report_path = output_dir / "fetch_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    
    log(f"Chunk complete: {report['successful']} succeeded, {report['failed']} failed, {report['skipped']} skipped")
    log(f"Templates: {report['total_templates_saved']} saved from {report['total_templates_found']} found")
    
    # Exit with success even if some sources failed (graceful degradation)
    print(f"✓ Saved {report['total_templates_saved']} templates to {output_dir}")


if __name__ == "__main__":
    main()
