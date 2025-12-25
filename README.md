# TFnuclei-templates

<div align="center">

![Nuclei](https://img.shields.io/badge/Nuclei-Templates-blue?style=for-the-badge)
![Auto Update](https://img.shields.io/badge/Auto-Updated%20Daily-green?style=for-the-badge)
![Auto Discovery](https://img.shields.io/badge/Auto-Discovery-purple?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A curated, deduplicated collection of Nuclei templates aggregated from 400+ public sources.**

[View Templates](#using-the-templates) • [Add Sources](#adding-new-sources) • [Statistics](#statistics)

</div>

---

## 🚀 Features

- **400+ Sources**: Aggregates templates from GitHub repos, ZIP archives, and raw gists
- **🔍 Auto-Discovery**: Automatically finds new nuclei template repos on GitHub daily
- **Smart Deduplication**: 3-pass dedup using content hash, semantic fingerprint, and normalized IDs
- **Priority Scoring**: Templates ranked by severity + CVE age (newer = higher priority)
- **Daily Updates**: Automatically synced every day at 4 AM UTC
- **Ready to Use**: No downloading or unzipping required - just clone and go!

## 📦 Using the Templates

### Option 1: Clone and use directly

```bash
# Clone the repository
git clone https://github.com/xerocorps/TFnuclei-templates.git

# Use with nuclei
nuclei -t TFnuclei-templates/templates/ -u https://example.com

# Use only high-priority templates (critical/high severity)
nuclei -t TFnuclei-templates/templates/ -severity critical,high -u https://example.com
```

### Option 2: Pull specific templates

```bash
# Download the index to see available templates
curl -sL https://raw.githubusercontent.com/xerocorps/TFnuclei-templates/main/templates_index.json | jq '.count'

# Download a specific template
curl -sLO https://raw.githubusercontent.com/xerocorps/TFnuclei-templates/main/templates/<template-name>.yaml
```

### Option 3: Use with nuclei's -tu flag

```bash
nuclei -tu https://github.com/xerocorps/TFnuclei-templates -u https://example.com
```

## ➕ Adding New Sources

Edit `sources.json` to add new template sources:

### GitHub Repository

```json
{ "type": "github_repo", "repo": "owner/repo-name" }
```

### ZIP Archive

```json
{ "type": "zip", "url": "https://example.com/templates.zip" }
```

### Raw YAML File

```json
{ "type": "raw", "url": "https://gist.githubusercontent.com/.../template.yaml" }
```

### Skip a Source (without deleting)

```json
{
  "type": "github_repo",
  "repo": "owner/repo-name",
  "skip": true,
  "skip_reason": "repo_not_found"
}
```

After editing, either:

1. Create a pull request, or
2. Manually trigger the workflow from the Actions tab

## 🔍 Auto-Discovery

The repository automatically discovers new nuclei template sources from GitHub:

- **Schedule**: Runs daily at 2 AM UTC (before template update at 4 AM)
- **Search**: Finds repos with `nuclei-templates` in name, topic, or description
- **Validation**: Only adds repos that contain valid nuclei templates
- **Quality Control**: Requires ≥2 stars, recent activity, not blacklisted

### Blacklist

Edit `blacklist.json` to block specific repos, users, or patterns:

```json
{
  "repos": ["spam/nuclei-templates"],
  "patterns": ["^test[-_]", "[-_]backup$"],
  "users": ["known-spam-user"]
}
```

## 📊 Statistics

View `stats.json` for detailed statistics including:

- Total template count
- Severity breakdown (critical, high, medium, low, info)
- Deduplication breakdown (exact hash, semantic, normalized ID)
- Source success/failure/skipped counts
- Failed sources list

View `templates_index.json` for template metadata including:

- Priority score (higher = more important)
- CVE year (when applicable)
- Severity level

## 🏗️ Architecture

```
.github/workflows/
  ├── discover.yml            # Auto-discovery workflow (2 AM UTC)
  └── update.yml              # Template update workflow (4 AM UTC)
scripts/
  ├── constants.py            # Configuration
  ├── discover_sources.py     # GitHub search & validation
  ├── merge_sources.py        # Merge discovered sources
  ├── fetch_sources.py        # Download and extract templates
  ├── merge_templates.py      # Deduplicate and merge
  └── semantic_fingerprint.py # Smart deduplication logic
sources.json                  # List of template sources
blacklist.json                # Blocked repos/patterns
templates/                    # Deduplicated templates (output)
templates_index.json          # Template index with metadata
stats.json                    # Fetch statistics
```

### How it works

1. **Discover** (2 AM UTC): Search GitHub for new nuclei template repos
2. **Setup**: Calculate number of parallel jobs based on source count
3. **Fetch**: Download templates in parallel chunks (50 sources each)
4. **Merge**: 3-pass deduplication:
   - Pass 1: Exact content hash (byte-for-byte duplicates)
   - Pass 2: Semantic fingerprint (same functionality, different metadata)
   - Pass 3: Normalized ID (CVE-2024-1234-template → template)
5. **Score**: Rank templates by severity weight and CVE age
6. **Commit**: Push changes to the repository

## 📝 License

This repository aggregates templates from various public sources. Each template retains its original license. The aggregation scripts are MIT licensed.

## ⭐ Acknowledgments

Thanks to all the security researchers who create and share nuclei templates!
