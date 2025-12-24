"""
Constants and configuration for TFnuclei-templates scripts.
"""

# HTTP settings
USER_AGENT = "TFnuclei-templates/2.0 (+https://github.com/xerocorps/TFnuclei-templates)"
REQUEST_TIMEOUT = 60  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds (exponential backoff base)

# Rate limiting
RATE_LIMIT_DELAY = 0.5  # seconds between requests

# File limits
MAX_TEMPLATE_SIZE = 1_000_000  # 1MB max per template file
MAX_REPO_SIZE = 100_000_000  # 100MB max per repo download

# Allowed extensions
YAML_EXTENSIONS = ('.yaml', '.yml')

# GitHub archive branches to try
GITHUB_BRANCHES = ('main', 'master')

# Default chunk size for parallel processing
DEFAULT_CHUNK_SIZE = 50
