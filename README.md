# TFnuclei-templates

A curated, deduplicated collection of Nuclei templates (YAML files) aggregated from many public sources.
This repository automatically fetches public repos, zips, and gists and stores templates as `.yaml` files in `templates/`.

## How it works

- The workflow runs daily (and can be triggered manually).
- It reads `sources.json` for sources to fetch.
- `scripts/fetch_and_process.py` downloads archives or raw YAMLs, extracts templates, canonicalizes YAML, deduplicates (by `id` when available), and writes `templates/`.
- If there are changes, the action commits and pushes them.
