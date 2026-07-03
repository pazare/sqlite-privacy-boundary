# sqlite-privacy-boundary

Small, dependency-free experiments for inspectable SQLite release boundaries.

## Question

Can a SQLite-backed text dataset expose useful public structure without exposing
raw records or private base tables?

## Mechanism

- redact common personal identifiers before storage
- cluster text records into deterministic topics
- expose only k-anonymous public views for topics and aggregate cells
- run user SQL through SQLite's authorizer
- publish a portable extract that omits private base tables and row-level text
- verify integrity with a hash-chained audit log

## Known Limits

This is a research prototype, not a compliance tool. Redaction is pattern-based,
topics are deterministic but lightweight, and the k-anonymity floor counts
distinct normalized text rather than identities.

## Install

```bash
python3 -m pip install -e .
```

## Verify

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m sqlite_privacy_boundary.selfcheck
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B examples/minimal.py
```

Expected self-checks:

- deterministic topics
- k-anonymity, including duplicate-flood resistance
- redaction at rest
- read-only SQL guard
- tamper-evident audit log
- pattern-redacted public extract with no private base tables

## Minimal Use

```python
from pathlib import Path

from sqlite_privacy_boundary import add_record, init_db, publish_extract, run_readonly_query

db = Path("demo.sqlite3")
init_db(db)

for text in [
    "Alpha sensor drift exceeded the baseline threshold.",
    "The alpha sensor baseline drift increased again.",
    "Baseline drift in alpha sensor readings is persistent.",
    "Alpha measurements show drift above the threshold.",
    "Sensor alpha drift remains above baseline.",
]:
    add_record(db, {"group_key": "cohort_a", "category": "topic_a", "note": text})

print(run_readonly_query(db, "select label, size from public_topics").rows)
publish_extract(db, "public.sqlite3")
```
