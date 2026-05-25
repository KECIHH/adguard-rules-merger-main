# Contributing

## Add or Update Rule Sources

1. Edit `sources/sources.txt`.
2. Keep one source URL per line.
3. Prefer stable raw file URLs over HTML pages.
4. Remove duplicate or dead sources when possible.

## Local Validation

```bash
python -m pip install -r requirements.txt
python -m pip install pytest
python -m pytest
python scripts/fetch_rules.py
python scripts/merge_rules.py
python scripts/optimize_rules.py
```

## Expectations

- Keep generated files out of the main branch unless you intentionally want them there.
- If you change parsing or scoring logic, add or update tests in `tests/`.
- When documenting subscription links, use `raw.githubusercontent.com` examples.
