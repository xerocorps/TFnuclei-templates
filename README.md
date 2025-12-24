# TFnuclei-templates

<div align="center">

![Nuclei](https://img.shields.io/badge/Nuclei-Templates-blue?style=for-the-badge)
![Auto Update](https://img.shields.io/badge/Auto-Updated%20Daily-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A curated, deduplicated collection of Nuclei templates aggregated from 400+ public sources.**

[View Templates](#using-the-templates) • [Add Sources](#adding-new-sources) • [Statistics](#statistics)

</div>

---

## 🚀 Features

- **400+ Sources**: Aggregates templates from GitHub repos, ZIP archives, and raw gists
- **Auto-Deduplicated**: Removes duplicates by template ID and content hash
- **Daily Updates**: Automatically synced every day at 4 AM UTC
- **Ready to Use**: No downloading or unzipping required - just clone and go!

## 📦 Using the Templates

### Option 1: Clone and use directly

```bash
# Clone the repository
git clone https://github.com/xerocorps/TFnuclei-templates.git

# Use with nuclei
nuclei -t TFnuclei-templates/templates/ -u https://example.com
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
{ "type": "github_repo", "repo": "owner/repo-name", "skip": true }
```

After editing, either:

1. Create a pull request, or
2. Manually trigger the workflow from the Actions tab

## 📊 Statistics

View `stats.json` for detailed statistics including:

- Total template count
- Severity breakdown (critical, high, medium, low, info)
- Source success/failure counts
- Failed sources list

## 🏗️ Architecture

```
.github/workflows/update.yml  # GitHub Actions workflow
scripts/
  ├── constants.py            # Configuration
  ├── fetch_sources.py        # Download and extract templates
  └── merge_templates.py      # Deduplicate and merge
sources.json                  # List of template sources
templates/                    # Deduplicated templates (output)
templates_index.json          # Template index with metadata
stats.json                    # Fetch statistics
```

### How it works

1. **Setup**: Calculate number of parallel jobs based on source count
2. **Fetch**: Download templates in parallel chunks (50 sources each)
3. **Merge**: Deduplicate by template ID and content hash
4. **Commit**: Push changes to the repository

## 📝 License

This repository aggregates templates from various public sources. Each template retains its original license. The aggregation scripts are MIT licensed.

## ⭐ Acknowledgments

Thanks to all the security researchers who create and share nuclei templates!
