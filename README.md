# AdGuard Rules Merger

This repository downloads multiple AdGuard / Adblock rule sources, merges and deduplicates them, then publishes:

- `merged_all.txt` for the full list
- `merged_lite.txt` for the lighter list

The project now includes real configuration loading, per-script log files, regression tests, and safer rule parsing so metadata or failed download markers do not leak into the final output.

## Quick Start

```bash
python -m pip install -r requirements.txt
python -m pip install pytest

python scripts/fetch_rules.py
python scripts/merge_rules.py
python scripts/optimize_rules.py
python -m pytest
```

## Published Paths

GitHub Actions publishes generated files to the `rules` branch:

- `latest/full/merged_all.txt`
- `latest/lite/merged_lite.txt`
- `archive/YYYY-MM-DD/...`

For AdGuard Home subscriptions, use raw URLs:

```text
https://raw.githubusercontent.com/<your-user>/<your-repo>/rules/latest/lite/merged_lite.txt
https://raw.githubusercontent.com/<your-user>/<your-repo>/rules/latest/full/merged_all.txt
```

## Notes

- `config.yml` controls download and optimization behavior.
- The workflow fails instead of publishing when too many sources fail or the optimized output falls below `optimization.min_rules`.
- `logs/` is created automatically.
- Optional local rules can be placed in `rules/my_rules.txt`.

For the Chinese guide, see [README_CN.md](./README_CN.md).
