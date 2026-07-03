# Method

This repository is a small reference implementation for an inspectable SQLite
release boundary around free-text datasets.

For the compact invariant model, see [Formal Boundary Notes](formal_boundary.md).

The core idea is deliberately simple:

1. Minimize free text before storage with pattern-based redaction.
2. Group similar records into deterministic topics.
3. Surface topic-level rows only after at least `k` distinct normalized records
   support them.
4. Surface aggregate cells only when each cell independently reaches the same
   distinct-text floor.
5. Expose query access only through named public views.
6. Use SQLite's parsed-statement authorizer to deny private base tables,
   sensitive columns, non-read actions, internal schema tables, and unapproved
   functions.
7. Publish a separate SQLite extract whose schema physically omits private base
   tables and row-level text.
8. Attach a source audit head and row count to each extract for external pinning.

## Limits

This is a research prototype. It is not a compliance tool.

The redaction layer is pattern-based. It catches common identifiers such as
emails, links, phone numbers, handles, street addresses, ZIP-like values, and long
number runs. It cannot understand every self-identifying sentence.

The topic layer is deterministic and lightweight. It is designed for
reproducibility and inspection, not state-of-the-art language understanding.

The k-anonymity floor counts distinct normalized text. It blocks exact duplicate
flooding, but it is not an identity system. Public topic rows and public
aggregate cells are checked separately, so a public topic does not make a small
group/category cell public.

## Verification

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m sqlite_privacy_boundary.selfcheck
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B examples/minimal.py
```
