#!/usr/bin/env python3
"""
Discover new nuclei template sources from GitHub.

Searches GitHub repositories for nuclei templates,
validates them, and outputs new sources to add.

IMPORTANT: Uses GitHub Contents API (not Code Search) to avoid
the strict 10 req/min rate limit on Code Search API.

Usage:
    python discover_sources.py --days 7 --out new_sources.json
    python discover_sources.py --days 30 --dry-run
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

import requests
import yaml

# Configuration
GITHUB_API_BASE = "https://api.github.com"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

# Rate limits - be conservative
SEARCH_DELAY = 3  # Seconds between search API calls
CONTENTS_DELAY = 0.5  # Seconds between contents API calls (more generous limit)

DISCOVERY_MIN_STARS = 2
DISCOVERY_MAX_AGE_DAYS = 365
DISCOVERY_SAMPLE_FILES = 3  # Number of files to sample for validation

ROOT = Path(__file__).resolve().parents[1]
SOURCES_FILE = ROOT / "sources.json"
BLACKLIST_FILE = ROOT / "blacklist.json"

# Session for connection pooling
session = requests.Session()


def log(message: str, level: str = "INFO") -> None:
    """Print log message with timestamp."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}", file=sys.stderr)


def setup_auth() -> None:
    """Configure GitHub authentication."""
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "TFnuclei-templates-discovery/1.0",
        })
        log("Using authenticated GitHub API (5000 req/hr limit)")
    else:
        session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "TFnuclei-templates-discovery/1.0",
        })
        log("Warning: No GITHUB_TOKEN - rate limit is 60 req/hr", "WARN")


def check_rate_limit() -> int:
    """Check current rate limit status and return remaining requests."""
    try:
        response = session.get(f"{GITHUB_API_BASE}/rate_limit", timeout=10)
        if response.status_code == 200:
            data = response.json()
            core = data.get("resources", {}).get("core", {})
            remaining = core.get("remaining", 0)
            reset_time = core.get("reset", 0)
            
            if remaining < 100:
                wait_time = max(0, reset_time - time.time()) + 5
                log(f"Rate limit low ({remaining}), waiting {wait_time:.0f}s", "WARN")
                time.sleep(min(wait_time, 120))
            
            return remaining
    except Exception as e:
        log(f"Could not check rate limit: {e}", "WARN")
    return 1000  # Assume OK


def api_request(url: str, params: Optional[Dict] = None, delay: float = CONTENTS_DELAY) -> Optional[Dict]:
    """Make GitHub API request with retry logic."""
    time.sleep(delay)
    
    try:
        response = session.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            # Rate limited
            reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
            wait_time = max(0, reset_time - time.time()) + 5
            log(f"Rate limited, waiting {wait_time:.0f}s", "WARN")
            time.sleep(min(wait_time, 120))
            # Retry once
            response = session.get(url, params=params, timeout=30)
            if response.status_code == 200:
                return response.json()
        elif response.status_code == 404:
            return None  # Not found is expected sometimes
            
    except Exception as e:
        log(f"Request failed: {e}", "ERROR")
    
    return None


def is_valid_nuclei_template(content: str) -> bool:
    """
    Check if YAML content is a valid nuclei template.
    
    Requirements:
    - Must be valid YAML dict
    - Must have 'id' field
    - Must have 'info' section with 'severity'
    - Must have at least one protocol (http, network, dns, file, etc.)
    """
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return False
        
        # Required: id field
        if "id" not in data:
            return False
        
        # Required: info section
        info = data.get("info", {})
        if not isinstance(info, dict):
            return False
        
        # Required: severity in info
        if "severity" not in info:
            return False
        
        # Valid severity values
        valid_severities = {"critical", "high", "medium", "low", "info", "unknown"}
        severity = str(info.get("severity", "")).lower()
        if severity not in valid_severities:
            return False
        
        # Must have at least one protocol
        protocols = ["http", "network", "dns", "file", "headless", "ssl", "websocket", "whois", "code", "javascript"]
        if not any(p in data for p in protocols):
            return False
        
        return True
        
    except yaml.YAMLError:
        return False
    except Exception:
        return False


def load_existing_sources() -> Set[str]:
    """Load existing source repos from sources.json."""
    existing = set()
    try:
        if SOURCES_FILE.exists():
            sources = json.loads(SOURCES_FILE.read_text())
            for source in sources:
                if source.get("type") == "github_repo":
                    repo = source.get("repo", "").lower()
                    existing.add(repo)
                elif source.get("type") == "raw":
                    url = source.get("url", "").lower()
                    existing.add(url)
    except Exception as e:
        log(f"Error loading sources: {e}", "WARN")
    return existing


def load_blacklist() -> Dict[str, Any]:
    """Load blacklist configuration."""
    default_blacklist = {
        "repos": [],
        "patterns": [
            "^test[-_]", "[-_]test$",
            "^backup[-_]", "[-_]backup$",
            "^fork[-_]", "[-_]fork$",
            "^example[-_]", "[-_]example$",
            "^sample[-_]", "[-_]sample$",
            "^stars$", "[-_]stars$", "^my[-_]stars$",
            "trending", "awesome-",
        ],
        "users": [],
    }
    
    try:
        if BLACKLIST_FILE.exists():
            loaded = json.loads(BLACKLIST_FILE.read_text())
            # Merge patterns
            default_blacklist["repos"] = loaded.get("repos", [])
            default_blacklist["patterns"].extend(loaded.get("patterns", []))
            default_blacklist["users"] = loaded.get("users", [])
    except Exception as e:
        log(f"Error loading blacklist: {e}", "WARN")
    
    return default_blacklist


def is_blacklisted(repo: str, blacklist: Dict[str, Any]) -> bool:
    """Check if repo matches blacklist."""
    repo_lower = repo.lower()
    
    # Check exact repo matches
    if repo_lower in [r.lower() for r in blacklist.get("repos", [])]:
        return True
    
    # Check user matches
    user = repo.split("/")[0].lower() if "/" in repo else ""
    if user in [u.lower() for u in blacklist.get("users", [])]:
        return True
    
    # Check patterns
    repo_name = repo.split("/")[1] if "/" in repo else repo
    for pattern in blacklist.get("patterns", []):
        if re.search(pattern, repo_name, re.IGNORECASE):
            return True
    
    return False


def find_yaml_files_in_repo(owner: str, repo: str, path: str = "", depth: int = 0) -> List[str]:
    """
    Find YAML files in a repo using Contents API (NOT Code Search).
    Returns list of raw file URLs.
    
    This avoids the 10 req/min Code Search rate limit.
    """
    if depth > 2:  # Don't go too deep
        return []
    
    yaml_files = []
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}"
    
    result = api_request(url)
    if not result:
        return []
    
    if not isinstance(result, list):
        return []
    
    for item in result:
        if len(yaml_files) >= DISCOVERY_SAMPLE_FILES * 2:  # Get a few extra
            break
            
        name = item.get("name", "")
        item_type = item.get("type", "")
        item_path = item.get("path", "")
        
        if item_type == "file" and (name.endswith(".yaml") or name.endswith(".yml")):
            # Construct raw URL directly (no API call needed)
            raw_url = f"{GITHUB_RAW_BASE}/{owner}/{repo}/HEAD/{item_path}"
            yaml_files.append(raw_url)
            
        elif item_type == "dir" and depth < 2:
            # Check subdirectory, but limit depth
            subdir_name = name.lower()
            # Only recurse into likely template directories
            if any(kw in subdir_name for kw in ["template", "nuclei", "cve", "poc", "vuln", "scan"]):
                yaml_files.extend(find_yaml_files_in_repo(owner, repo, item_path, depth + 1))
    
    return yaml_files


def validate_repo(repo: str) -> bool:
    """
    Validate that a repo contains actual nuclei templates.
    Uses Contents API instead of Code Search to avoid rate limits.
    """
    log(f"  Validating: {repo}")
    
    owner, repo_name = repo.split("/", 1)
    
    # Find YAML files using Contents API
    yaml_files = find_yaml_files_in_repo(owner, repo_name)
    
    if not yaml_files:
        log(f"    No YAML files found")
        return False
    
    log(f"    Found {len(yaml_files)} YAML files, sampling...")
    
    # Sample and validate files (using raw URLs, no API call needed)
    valid_count = 0
    for raw_url in yaml_files[:DISCOVERY_SAMPLE_FILES]:
        try:
            time.sleep(0.2)  # Brief delay for raw fetches
            response = session.get(raw_url, timeout=10)
            if response.status_code == 200:
                if is_valid_nuclei_template(response.text):
                    valid_count += 1
        except Exception:
            continue
    
    is_valid = valid_count > 0
    log(f"    Result: {valid_count}/{min(len(yaml_files), DISCOVERY_SAMPLE_FILES)} valid templates")
    return is_valid


def search_repositories(days: int, existing: Set[str], blacklist: Dict) -> List[Dict[str, Any]]:
    """Search GitHub for nuclei template repositories."""
    discovered = []
    since_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    
    # Search queries - ordered by most likely to find good results
    queries = [
        f"topic:nuclei-templates pushed:>{since_date}",
        f"nuclei-templates in:name pushed:>{since_date}",
        f"nuclei-template in:name pushed:>{since_date}",
        f"topic:nuclei-template pushed:>{since_date}",
    ]
    
    seen_repos = set()
    
    # Check rate limit before starting
    check_rate_limit()
    
    for query in queries:
        log(f"Searching: {query}")
        time.sleep(SEARCH_DELAY)
        
        url = f"{GITHUB_API_BASE}/search/repositories"
        params = {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": 30,  # Reduced to save API calls
        }
        
        result = api_request(url, params, delay=SEARCH_DELAY)
        if not result:
            continue
        
        items = result.get("items", [])
        log(f"  Found {len(items)} repos")
        
        for repo_data in items:
            full_name = repo_data.get("full_name", "")
            
            if not full_name:
                continue
            
            repo_lower = full_name.lower()
            
            # Skip if already seen
            if repo_lower in seen_repos:
                continue
            seen_repos.add(repo_lower)
            
            # Skip existing sources
            if repo_lower in existing:
                log(f"  Skip (exists): {full_name}")
                continue
            
            # Skip blacklisted
            if is_blacklisted(full_name, blacklist):
                log(f"  Skip (blacklist): {full_name}")
                continue
            
            # Check minimum stars
            stars = repo_data.get("stargazers_count", 0)
            if stars < DISCOVERY_MIN_STARS:
                log(f"  Skip (stars={stars}): {full_name}")
                continue
            
            # Check not archived
            if repo_data.get("archived", False):
                log(f"  Skip (archived): {full_name}")
                continue
            
            # Check recent activity
            pushed_at = repo_data.get("pushed_at", "")
            if pushed_at:
                try:
                    pushed_date = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - pushed_date).days
                    if age_days > DISCOVERY_MAX_AGE_DAYS:
                        log(f"  Skip (inactive {age_days}d): {full_name}")
                        continue
                except:
                    pass
            
            # Validate contains actual templates
            if not validate_repo(full_name):
                log(f"  Skip (invalid): {full_name}")
                continue
            
            log(f"  ✓ Discovered: {full_name} (⭐ {stars})")
            discovered.append({
                "type": "github_repo",
                "repo": full_name,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "stars": stars,
            })
            
            # Limit discoveries per run to avoid too many API calls
            if len(discovered) >= 10:
                log("Reached discovery limit (10), stopping")
                return discovered
    
    return discovered


def main():
    parser = argparse.ArgumentParser(description="Discover new nuclei template sources")
    parser.add_argument("--days", type=int, default=7, help="Search repos pushed within N days")
    parser.add_argument("--out", type=str, default="new_sources.json", help="Output file")
    parser.add_argument("--dry-run", action="store_true", help="Print results without saving")
    args = parser.parse_args()
    
    setup_auth()
    
    log(f"Discovering sources from last {args.days} days")
    
    # Load existing sources and blacklist
    existing = load_existing_sources()
    blacklist = load_blacklist()
    
    log(f"Loaded {len(existing)} existing sources")
    
    # Search repositories
    discovered = search_repositories(args.days, existing, blacklist)
    
    log(f"\n{'='*50}")
    log(f"Discovery complete!")
    log(f"  New sources found: {len(discovered)}")
    
    if args.dry_run:
        log("\nDry run - not saving. Results:")
        for source in discovered:
            print(json.dumps(source, indent=2))
    else:
        # Save results
        output_path = Path(args.out)
        output_path.write_text(json.dumps(discovered, indent=2))
        log(f"Saved to {output_path}")


if __name__ == "__main__":
    main()
