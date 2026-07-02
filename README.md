# sqlite-privacy-boundary

Small, dependency-free experiments for privacy-preserving SQLite releases.

The package demonstrates a compact pattern:

- redact common personal identifiers before storage
- cluster text records into deterministic topics
- expose only k-anonymous public views
- run browser/user SQL through SQLite's authorizer
- publish a portable extract that omits private base tables
- verify integrity with a hash-chained audit log

This is a research prototype, not a compliance guarantee.

## Install

```bash
python3 -m pip install -e .
```

## Verify

```bash
python3 -m unittest discover -s tests -v
python3 -m sqlite_privacy_boundary.selfcheck
```

Expected self-checks:

- deterministic topics
- k-anonymity, including duplicate-flood resistance
- redaction at rest
- read-only SQL guard
- tamper-evident audit log
- PII-safe public extract

## Minimal Use

```python
from pathlib import Path

from sqlite_privacy_boundary.boundary import add_record, init_db, publish_extract, run_readonly_query

db = Path("demo.sqlite3")
init_db(db)

for text in [
    "Rent keeps rising and housing is unaffordable.",
    "Housing costs keep rising near transit.",
    "Affordable housing would help my family.",
    "Rent takes too much of my paycheck.",
    "We need more affordable housing options.",
]:
    add_record(db, {"group_key": "A", "category": "housing", "note": text})

print(run_readonly_query(db, "select label, size from public_topics").rows)
publish_extract(db, "public.sqlite3")
```

