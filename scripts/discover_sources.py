#!/usr/bin/env python3
"""
Discover new nuclei template sources from GitHub.

Searches GitHub repositories and gists for nuclei templates,
validates them, and outputs new sources to add.

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
from urllib.parse import quote

import requests
import yaml

# Configuration
GITHUB_API_BASE = "https://api.github.com"
GITHUB_SEARCH_DELAY = 2  # Seconds between API calls to avoid rate limiting
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
        })
        log("Using authenticated GitHub API")
    else:
        session.headers.update({
            "Accept": "application/vnd.github.v3+json",
        })
        log("Warning: No GITHUB_TOKEN - rate limit is 60 req/hr", "WARN")


def api_request(url: str, params: Optional[Dict] = None) -> Optional[Dict]:
    """Make GitHub API request with rate limit handling."""
    try:
        response = session.get(url, params=params, timeout=30)
        
        # Check rate limit
        remaining = int(response.headers.get("X-RateLimit-Remaining", 1))
        if remaining < 10:
            reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
            wait_time = max(0, reset_time - time.time()) + 1
            log(f"Rate limit low ({remaining}), waiting {wait_time:.0f}s", "WARN")
            time.sleep(min(wait_time, 60))
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            log(f"Rate limited: {response.json().get('message', '')}", "ERROR")
            return None
        elif response.status_code == 422:
            log(f"Validation failed: {response.json().get('message', '')}", "WARN")
            return None
        else:
            log(f"API error {response.status_code}: {url}", "ERROR")
            return None
            
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
            "^test[-_]",
            "[-_]test$",
            "^backup[-_]",
            "[-_]backup$",
            "^fork[-_]",
            "[-_]fork$",
            "^example[-_]",
            "[-_]example$",
            "^sample[-_]",
            "[-_]sample$",
        ],
        "users": [],
    }
    
    try:
        if BLACKLIST_FILE.exists():
            return json.loads(BLACKLIST_FILE.read_text())
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


def validate_repo(repo: str) -> bool:
    """
    Validate that a repo contains actual nuclei templates.
    
    Samples a few YAML files and checks if they're valid templates.
    """
    log(f"Validating repo: {repo}")
    time.sleep(GITHUB_SEARCH_DELAY)
    
    # Search for YAML files in the repo
    url = f"{GITHUB_API_BASE}/search/code"
    params = {
        "q": f"repo:{repo} extension:yaml",
        "per_page": DISCOVERY_SAMPLE_FILES,
    }
    
    result = api_request(url, params)
    if not result or not result.get("items"):
        # Try alternate search
        params["q"] = f"repo:{repo} extension:yml"
        result = api_request(url, params)
        if not result or not result.get("items"):
            log(f"  No YAML files found in {repo}", "WARN")
            return False
    
    # Sample and validate files
    valid_count = 0
    for item in result.get("items", [])[:DISCOVERY_SAMPLE_FILES]:
        try:
            # Get raw file content
            raw_url = item.get("html_url", "").replace(
                "github.com", "raw.githubusercontent.com"
            ).replace("/blob/", "/")
            
            if not raw_url:
                continue
                
            time.sleep(0.5)  # Brief delay between file fetches
            response = session.get(raw_url, timeout=10)
            if response.status_code == 200:
                if is_valid_nuclei_template(response.text):
                    valid_count += 1
                    
        except Exception as e:
            log(f"  Error checking file: {e}", "WARN")
            continue
    
    is_valid = valid_count > 0
    log(f"  Validation result: {valid_count}/{DISCOVERY_SAMPLE_FILES} valid templates")
    return is_valid


def search_repositories(days: int, existing: Set[str], blacklist: Dict) -> List[Dict[str, Any]]:
    """Search GitHub for nuclei template repositories."""
    discovered = []
    since_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    
    # Search queries
    queries = [
        f"nuclei-templates in:name pushed:>{since_date}",
        f"nuclei-template in:name pushed:>{since_date}",
        f"nuclei template in:description language:YAML pushed:>{since_date}",
        f"topic:nuclei-templates pushed:>{since_date}",
        f"topic:nuclei-template pushed:>{since_date}",
        f'"nuclei" "template" "yaml" in:readme pushed:>{since_date}',
    ]
    
    seen_repos = set()
    
    for query in queries:
        log(f"Searching: {query}")
        time.sleep(GITHUB_SEARCH_DELAY)
        
        url = f"{GITHUB_API_BASE}/search/repositories"
        params = {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": 50,
        }
        
        result = api_request(url, params)
        if not result:
            continue
        
        for repo_data in result.get("items", []):
            full_name = repo_data.get("full_name", "")
            
            if not full_name:
                continue
            
            repo_lower = full_name.lower()
            
            # Skip if already seen in this search
            if repo_lower in seen_repos:
                continue
            seen_repos.add(repo_lower)
            
            # Skip existing sources
            if repo_lower in existing:
                log(f"  Skipping (already exists): {full_name}")
                continue
            
            # Skip blacklisted
            if is_blacklisted(full_name, blacklist):
                log(f"  Skipping (blacklisted): {full_name}")
                continue
            
            # Check minimum stars
            stars = repo_data.get("stargazers_count", 0)
            if stars < DISCOVERY_MIN_STARS:
                log(f"  Skipping (low stars: {stars}): {full_name}")
                continue
            
            # Check not archived
            if repo_data.get("archived", False):
                log(f"  Skipping (archived): {full_name}")
                continue
            
            # Check recent activity
            pushed_at = repo_data.get("pushed_at", "")
            if pushed_at:
                try:
                    pushed_date = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - pushed_date).days
                    if age_days > DISCOVERY_MAX_AGE_DAYS:
                        log(f"  Skipping (inactive: {age_days} days): {full_name}")
                        continue
                except:
                    pass
            
            # Validate contains actual templates
            if not validate_repo(full_name):
                log(f"  Skipping (no valid templates): {full_name}")
                continue
            
            log(f"  ✓ Discovered: {full_name} (⭐ {stars})")
            discovered.append({
                "type": "github_repo",
                "repo": full_name,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "stars": stars,
            })
    
    return discovered


def search_gists(days: int, existing: Set[str]) -> List[Dict[str, Any]]:
    """Search GitHub Gists for nuclei templates."""
    discovered = []
    since_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    log("Searching gists for nuclei templates...")
    
    # Gist search is limited - we search via code search API
    url = f"{GITHUB_API_BASE}/search/code"
    params = {
        "q": 'nuclei id: info: severity: extension:yaml',
        "per_page": 30,
    }
    
    time.sleep(GITHUB_SEARCH_DELAY)
    result = api_request(url, params)
    
    if not result:
        return discovered
    
    seen_gists = set()
    
    for item in result.get("items", []):
        html_url = item.get("html_url", "")
        
        # Only process gist URLs
        if "gist.github.com" not in html_url:
            continue
        
        # Extract raw URL
        raw_url = item.get("git_url", "")
        if not raw_url:
            continue
        
        # Dedupe by gist ID
        gist_parts = html_url.split("/")
        if len(gist_parts) < 5:
            continue
        gist_id = gist_parts[4].split("#")[0]
        
        if gist_id in seen_gists:
            continue
        seen_gists.add(gist_id)
        
        # Check if already exists
        if html_url.lower() in existing:
            continue
        
        # Validate the gist content
        try:
            time.sleep(0.5)
            # Construct raw URL for gist
            file_name = item.get("name", "")
            gist_raw_url = f"https://gist.githubusercontent.com/{gist_parts[3]}/{gist_id}/raw/{file_name}"
            
            response = session.get(gist_raw_url, timeout=10)
            if response.status_code == 200:
                if is_valid_nuclei_template(response.text):
                    log(f"  ✓ Discovered gist: {gist_id}/{file_name}")
                    discovered.append({
                        "type": "raw",
                        "url": gist_raw_url,
                        "discovered_at": datetime.now(timezone.utc).isoformat(),
                    })
        except Exception as e:
            log(f"  Error validating gist: {e}", "WARN")
            continue
    
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
    repo_sources = search_repositories(args.days, existing, blacklist)
    
    # Search gists
    gist_sources = search_gists(args.days, existing)
    
    # Combine results
    all_sources = repo_sources + gist_sources
    
    log(f"\n{'='*50}")
    log(f"Discovery complete!")
    log(f"  Repositories found: {len(repo_sources)}")
    log(f"  Gists found: {len(gist_sources)}")
    log(f"  Total new sources: {len(all_sources)}")
    
    if args.dry_run:
        log("\nDry run - not saving. Results:")
        for source in all_sources:
            print(json.dumps(source, indent=2))
    else:
        # Save results
        output_path = Path(args.out)
        output_path.write_text(json.dumps(all_sources, indent=2))
        log(f"\nSaved to {output_path}")


if __name__ == "__main__":
    main()
