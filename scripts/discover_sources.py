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

import requests
import yaml

# Configuration
GITHUB_API_BASE = "https://api.github.com"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

# Rate limits
SEARCH_DELAY = 2  # Seconds between search API calls
API_DELAY = 0.5  # Seconds between other API calls

DISCOVERY_MIN_STARS = 1  # Lowered to catch more repos
DISCOVERY_MAX_AGE_DAYS = 365
DISCOVERY_SAMPLE_FILES = 3

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
        log("Using authenticated GitHub API")
    else:
        session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "TFnuclei-templates-discovery/1.0",
        })
        log("Warning: No GITHUB_TOKEN - rate limit is 60 req/hr", "WARN")


def api_get(url: str, params: Optional[Dict] = None, delay: float = API_DELAY) -> Optional[Any]:
    """Make GitHub API GET request."""
    time.sleep(delay)
    
    for attempt in range(3):
        try:
            response = session.get(url, params=params, timeout=30)
            
            # Check rate limit headers
            remaining = int(response.headers.get("X-RateLimit-Remaining", 100))
            if remaining < 50:
                reset_ts = int(response.headers.get("X-RateLimit-Reset", 0))
                wait = max(0, reset_ts - time.time()) + 5
                log(f"Rate limit low ({remaining}), waiting {min(wait, 60):.0f}s", "WARN")
                time.sleep(min(wait, 60))
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                log(f"Rate limited, waiting 60s...", "WARN")
                time.sleep(60)
                continue
            elif response.status_code == 404:
                return None
            else:
                log(f"API error {response.status_code}: {url}", "WARN")
                return None
                
        except Exception as e:
            log(f"Request error: {e}", "WARN")
            time.sleep(5)
    
    return None


def is_valid_nuclei_template(content: str) -> bool:
    """Check if content is a valid nuclei template."""
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return False
        
        # Must have id
        if "id" not in data:
            return False
        
        # Must have info with severity
        info = data.get("info", {})
        if not isinstance(info, dict) or "severity" not in info:
            return False
        
        # Must have a protocol
        protocols = ["http", "network", "dns", "file", "headless", "ssl", "websocket", "whois", "code", "javascript", "tcp", "udp"]
        if not any(p in data for p in protocols):
            return False
        
        return True
        
    except:
        return False


def load_existing_sources() -> Set[str]:
    """Load existing source repos/URLs."""
    existing = set()
    try:
        if SOURCES_FILE.exists():
            sources = json.loads(SOURCES_FILE.read_text())
            for s in sources:
                if s.get("type") == "github_repo":
                    existing.add(s.get("repo", "").lower())
                elif s.get("type") in ("raw", "zip"):
                    existing.add(s.get("url", "").lower())
    except Exception as e:
        log(f"Error loading sources: {e}", "WARN")
    return existing


def load_blacklist() -> Dict[str, Any]:
    """Load blacklist configuration."""
    blacklist = {
        "repos": [],
        "patterns": [
            "^test[-_]", "[-_]test$",
            "^backup[-_]", "[-_]backup$",
            "^fork[-_]", "[-_]fork$",
            "^stars$", "[-_]stars$",
            "^awesome[-_]",
        ],
        "users": [],
    }
    
    try:
        if BLACKLIST_FILE.exists():
            loaded = json.loads(BLACKLIST_FILE.read_text())
            blacklist["repos"] = loaded.get("repos", [])
            blacklist["patterns"] = loaded.get("patterns", [])
            blacklist["users"] = loaded.get("users", [])
    except:
        pass
    
    return blacklist


def is_blacklisted(repo: str, blacklist: Dict) -> bool:
    """Check if repo is blacklisted."""
    repo_lower = repo.lower()
    
    if repo_lower in [r.lower() for r in blacklist.get("repos", [])]:
        return True
    
    user = repo.split("/")[0].lower() if "/" in repo else ""
    if user in [u.lower() for u in blacklist.get("users", [])]:
        return True
    
    repo_name = repo.split("/")[1].lower() if "/" in repo else repo.lower()
    for pattern in blacklist.get("patterns", []):
        if re.search(pattern, repo_name, re.IGNORECASE):
            return True
    
    return False


def get_default_branch(owner: str, repo: str) -> str:
    """Get default branch for a repo."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    data = api_get(url)
    if data:
        return data.get("default_branch", "main")
    return "main"


def find_yaml_files(owner: str, repo: str, branch: str, path: str = "", depth: int = 0) -> List[str]:
    """Find YAML files in repo using Contents API."""
    if depth > 2:
        return []
    
    yaml_files = []
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}"
    params = {"ref": branch}
    
    result = api_get(url, params)
    if not result or not isinstance(result, list):
        return []
    
    for item in result:
        if len(yaml_files) >= 10:
            break
            
        name = item.get("name", "")
        item_type = item.get("type", "")
        item_path = item.get("path", "")
        
        if item_type == "file" and name.endswith((".yaml", ".yml")):
            raw_url = f"{GITHUB_RAW_BASE}/{owner}/{repo}/{branch}/{item_path}"
            yaml_files.append(raw_url)
            
        elif item_type == "dir" and depth < 2:
            # Check promising directories
            if any(k in name.lower() for k in ["template", "nuclei", "cve", "poc", "vuln"]):
                yaml_files.extend(find_yaml_files(owner, repo, branch, item_path, depth + 1))
    
    return yaml_files


def validate_repo(repo: str) -> bool:
    """Validate repo contains nuclei templates."""
    log(f"  Validating: {repo}")
    
    parts = repo.split("/")
    if len(parts) != 2:
        return False
    owner, repo_name = parts
    
    # Get default branch
    branch = get_default_branch(owner, repo_name)
    
    # Find YAML files
    yaml_files = find_yaml_files(owner, repo_name, branch)
    
    if not yaml_files:
        log(f"    No YAML files found")
        return False
    
    log(f"    Found {len(yaml_files)} YAML files")
    
    # Sample and validate
    valid_count = 0
    for url in yaml_files[:DISCOVERY_SAMPLE_FILES]:
        try:
            time.sleep(0.2)
            resp = session.get(url, timeout=10)
            if resp.status_code == 200 and is_valid_nuclei_template(resp.text):
                valid_count += 1
        except:
            pass
    
    log(f"    Valid: {valid_count}/{min(len(yaml_files), DISCOVERY_SAMPLE_FILES)}")
    return valid_count > 0


def search_repositories(days: int, existing: Set[str], blacklist: Dict) -> List[Dict]:
    """Search for nuclei template repositories."""
    discovered = []
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    seen = set()
    
    # Multiple search strategies
    queries = [
        f"nuclei-templates in:name",
        f"nuclei-template in:name", 
        f"nuclei template in:name fork:false",
        f"topic:nuclei-templates",
        f"topic:nuclei-template",
        f"nuclei poc in:name language:YAML",
        f"nuclei cve in:name language:YAML",
    ]
    
    for query in queries:
        if len(discovered) >= 15:  # Limit per run
            break
            
        log(f"Search: {query}")
        time.sleep(SEARCH_DELAY)
        
        url = f"{GITHUB_API_BASE}/search/repositories"
        params = {"q": query, "sort": "updated", "order": "desc", "per_page": 50}
        
        result = api_get(url, params, delay=SEARCH_DELAY)
        if not result:
            continue
        
        log(f"  Found {result.get('total_count', 0)} results")
        
        for repo_data in result.get("items", []):
            full_name = repo_data.get("full_name", "")
            if not full_name:
                continue
            
            repo_lower = full_name.lower()
            
            if repo_lower in seen:
                continue
            seen.add(repo_lower)
            
            if repo_lower in existing:
                log(f"  Skip (exists): {full_name}")
                continue
            
            if is_blacklisted(full_name, blacklist):
                log(f"  Skip (blacklist): {full_name}")
                continue
            
            stars = repo_data.get("stargazers_count", 0)
            if stars < DISCOVERY_MIN_STARS:
                log(f"  Skip (stars={stars}): {full_name}")
                continue
            
            if repo_data.get("archived"):
                log(f"  Skip (archived): {full_name}")
                continue
            
            # Validate
            if not validate_repo(full_name):
                log(f"  Skip (no templates): {full_name}")
                continue
            
            log(f"  ✓ DISCOVERED: {full_name} (⭐ {stars})")
            discovered.append({
                "type": "github_repo",
                "repo": full_name,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "stars": stars,
            })
    
    return discovered


def search_gists(days: int, existing: Set[str]) -> List[Dict]:
    """Search for nuclei template gists."""
    discovered = []
    log("Searching gists...")
    
    # Search for gists with nuclei-related names
    queries = ["nuclei template", "nuclei yaml", "nuclei poc"]
    
    for query in queries:
        if len(discovered) >= 5:
            break
            
        time.sleep(SEARCH_DELAY)
        
        # Search code for gists
        url = f"{GITHUB_API_BASE}/search/code"
        params = {"q": f"{query} extension:yaml", "per_page": 20}
        
        result = api_get(url, params, delay=SEARCH_DELAY)
        if not result:
            continue
        
        for item in result.get("items", []):
            html_url = item.get("html_url", "")
            
            if "gist.github.com" not in html_url:
                continue
            
            # Extract gist info
            try:
                parts = html_url.split("/")
                user = parts[3]
                gist_id = parts[4].split("#")[0]
                filename = item.get("name", "")
                
                raw_url = f"https://gist.githubusercontent.com/{user}/{gist_id}/raw/{filename}"
                
                if raw_url.lower() in existing:
                    continue
                
                # Validate
                time.sleep(0.3)
                resp = session.get(raw_url, timeout=10)
                if resp.status_code == 200 and is_valid_nuclei_template(resp.text):
                    log(f"  ✓ GIST: {gist_id}/{filename}")
                    discovered.append({
                        "type": "raw",
                        "url": raw_url,
                        "discovered_at": datetime.now(timezone.utc).isoformat(),
                    })
            except:
                continue
    
    return discovered


def main():
    parser = argparse.ArgumentParser(description="Discover nuclei template sources")
    parser.add_argument("--days", type=int, default=7, help="Search within N days")
    parser.add_argument("--out", type=str, default="new_sources.json", help="Output file")
    parser.add_argument("--dry-run", action="store_true", help="Don't save")
    args = parser.parse_args()
    
    setup_auth()
    log(f"Discovering sources (last {args.days} days)")
    
    existing = load_existing_sources()
    blacklist = load_blacklist()
    log(f"Loaded {len(existing)} existing sources")
    
    # Search
    repos = search_repositories(args.days, existing, blacklist)
    gists = search_gists(args.days, existing)
    
    all_sources = repos + gists
    
    log(f"\n{'='*50}")
    log(f"Discovery complete!")
    log(f"  Repos: {len(repos)}")
    log(f"  Gists: {len(gists)}")
    log(f"  Total: {len(all_sources)}")
    
    if args.dry_run:
        log("Dry run - not saving")
        for s in all_sources:
            print(json.dumps(s))
    else:
        Path(args.out).write_text(json.dumps(all_sources, indent=2))
        log(f"Saved to {args.out}")


if __name__ == "__main__":
    main()
