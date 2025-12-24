"""
Semantic fingerprinting for nuclei templates.

Creates normalized fingerprints based on functional elements only:
- Template ID (normalized: strip CVE prefixes, UUIDs)
- HTTP path patterns
- Matcher conditions
- Extractor patterns

This catches "near-duplicates" that differ only in metadata.
"""

import hashlib
import re
from datetime import date
from typing import Any, Dict, Optional, Tuple

# UUID pattern for stripping
UUID_PATTERN = re.compile(r'-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)
# CVE prefix pattern
CVE_PREFIX_PATTERN = re.compile(r'^CVE-\d{4}-\d+[-_]', re.IGNORECASE)
# Version suffix pattern (like _1, _2, -v2)
VERSION_SUFFIX_PATTERN = re.compile(r'[-_]v?\d+$', re.IGNORECASE)
# Hash suffix pattern
HASH_SUFFIX_PATTERN = re.compile(r'-[a-f0-9]{16,}$', re.IGNORECASE)

# Severity weights for priority scoring
SEVERITY_WEIGHTS = {
    'critical': 100,
    'high': 80,
    'medium': 50,
    'low': 20,
    'info': 10,
    'unknown': 5
}

# CVE age scoring
CVE_AGE_PENALTY = 5  # Points lost per year
MAX_CVE_AGE_PENALTY = 50  # Max penalty for old CVEs


def normalize_template_id(template_id: str) -> str:
    """
    Normalize template ID by:
    1. Lowercasing
    2. Stripping CVE prefixes (CVE-2024-1234-)
    3. Removing UUIDs
    4. Removing version suffixes
    5. Removing hash suffixes
    
    Examples:
        CVE-2022-2933-0mk_shortener-3b798c64-... -> 0mk_shortener
        0mk_shortener-de9f3b83-4575-4566-9731-0af9107c7c30 -> 0mk_shortener
    """
    if not template_id:
        return ""
    
    # Convert to string (in case of int)
    normalized = str(template_id).lower().strip()
    
    # Strip CVE prefix
    normalized = CVE_PREFIX_PATTERN.sub('', normalized)
    
    # Strip UUID suffix
    normalized = UUID_PATTERN.sub('', normalized)
    
    # Strip hash suffix
    normalized = HASH_SUFFIX_PATTERN.sub('', normalized)
    
    # Strip version suffix
    normalized = VERSION_SUFFIX_PATTERN.sub('', normalized)
    
    # Clean up multiple underscores/dashes
    normalized = re.sub(r'[-_]+', '_', normalized)
    normalized = normalized.strip('_-')
    
    return normalized


def extract_functional_elements(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract only the functional elements of a template.
    Ignores metadata like author, tags, references.
    """
    functional = {}
    
    # Template ID (normalized)
    if 'id' in data:
        functional['id'] = normalize_template_id(data['id'])
    
    # HTTP request patterns
    if 'http' in data:
        http_elements = []
        http_section = data['http']
        if isinstance(http_section, list):
            for req in http_section:
                elem = {}
                if 'path' in req:
                    elem['path'] = req['path']
                if 'method' in req:
                    elem['method'] = req['method']
                if 'matchers' in req:
                    elem['matchers'] = req['matchers']
                if 'extractors' in req:
                    elem['extractors'] = req['extractors']
                if 'raw' in req:
                    elem['raw'] = req['raw']
                http_elements.append(elem)
        functional['http'] = http_elements
    
    # Network patterns
    if 'network' in data:
        functional['network'] = data['network']
    
    # DNS patterns
    if 'dns' in data:
        functional['dns'] = data['dns']
    
    # File patterns
    if 'file' in data:
        functional['file'] = data['file']
    
    # Headless patterns
    if 'headless' in data:
        functional['headless'] = data['headless']
    
    return functional


def get_semantic_fingerprint(data: Dict[str, Any]) -> str:
    """
    Generate semantic fingerprint from template data.
    Only includes functional elements, not metadata.
    
    Returns SHA256 hash of normalized functional elements.
    """
    import json
    
    functional = extract_functional_elements(data)
    
    # Serialize with sorted keys for consistency
    serialized = json.dumps(functional, sort_keys=True, separators=(',', ':'))
    
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()


def extract_cve_year(data: Dict[str, Any]) -> Optional[int]:
    """
    Extract CVE year from template data.
    Checks template ID, name, tags, and references.
    """
    cve_year_pattern = re.compile(r'CVE-(\d{4})-\d+', re.IGNORECASE)
    
    # Check template ID
    template_id = str(data.get('id', ''))
    match = cve_year_pattern.search(template_id)
    if match:
        return int(match.group(1))
    
    # Check info section
    info = data.get('info', {})
    
    # Check name
    name = str(info.get('name', ''))
    match = cve_year_pattern.search(name)
    if match:
        return int(match.group(1))
    
    # Check tags
    tags = info.get('tags', '')
    if isinstance(tags, str):
        match = cve_year_pattern.search(tags)
        if match:
            return int(match.group(1))
    
    # Check references
    references = info.get('reference', [])
    if isinstance(references, list):
        for ref in references:
            if isinstance(ref, str):
                match = cve_year_pattern.search(ref)
                if match:
                    return int(match.group(1))
    
    # Check classification
    classification = info.get('classification', {})
    if isinstance(classification, dict):
        cve_id = classification.get('cve-id', '')
        if cve_id:
            match = cve_year_pattern.search(str(cve_id))
            if match:
                return int(match.group(1))
    
    return None


def calculate_template_priority(data: Dict[str, Any], today: Optional[date] = None) -> Tuple[int, Dict[str, Any]]:
    """
    Calculate priority score based on:
    - Severity weight (critical=100, high=80, etc.)
    - CVE age (newer = higher priority, -5 points per year)
    - Has working matchers (bonus)
    
    Returns:
        Tuple of (priority_score, metadata_dict)
    """
    if today is None:
        today = date.today()
    
    info = data.get('info', {})
    
    # Base score from severity
    severity = str(info.get('severity', 'unknown')).lower()
    score = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS['unknown'])
    
    metadata = {
        'severity': severity,
        'cve_year': None,
        'age_penalty': 0,
    }
    
    # CVE age penalty
    cve_year = extract_cve_year(data)
    if cve_year:
        metadata['cve_year'] = cve_year
        years_old = today.year - cve_year
        age_penalty = min(years_old * CVE_AGE_PENALTY, MAX_CVE_AGE_PENALTY)
        score -= age_penalty
        metadata['age_penalty'] = age_penalty
    
    # Bonus for having matchers (functional template)
    http_section = data.get('http', [])
    if isinstance(http_section, list):
        for req in http_section:
            if req.get('matchers'):
                score += 5
                break
    
    # Ensure minimum score
    score = max(score, 1)
    
    return score, metadata


def choose_best_duplicate(templates: list) -> Dict[str, Any]:
    """
    Given a list of duplicate templates, choose the best one.
    
    Criteria (in order):
    1. Higher priority score
    2. More complete metadata
    3. First encountered (stable sort)
    """
    if not templates:
        return {}
    
    if len(templates) == 1:
        return templates[0]
    
    def template_score(t):
        data = t.get('data', {})
        priority, _ = calculate_template_priority(data)
        
        # Count metadata completeness
        info = data.get('info', {})
        metadata_score = 0
        if info.get('name'):
            metadata_score += 1
        if info.get('description'):
            metadata_score += 1
        if info.get('reference'):
            metadata_score += 1
        if info.get('tags'):
            metadata_score += 1
        
        return (priority, metadata_score)
    
    # Sort by score (descending)
    sorted_templates = sorted(templates, key=template_score, reverse=True)
    return sorted_templates[0]
