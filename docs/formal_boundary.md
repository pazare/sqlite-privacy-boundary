# Formal Boundary Notes

This note states the release boundary in implementation-level mathematical
terms. It is intentionally small: the repository implements hard gates over a
SQLite database, not a general decision system.

## Objects

Let `D` be the private SQLite database after storage-time minimization. The
private base tables are:

```text
B = {records, topics, record_topic, audit}
```

The public query surface is:

```text
P = {public_topics, aggregate_cells}
```

The public extract schema is:

```text
E = {public_topics, aggregate_cells, meta}
```

A query is admissible only if all of the following hold:

1. The SQL begins with `SELECT` or `WITH`.
2. SQLite reports only read/select/function actions to the authorizer.
3. Every function is in the explicit function allowlist.
4. Internal SQLite objects and sensitive columns are denied.
5. A private base table can be read only through a canonical public view.
6. The canonical public-view definitions match the definitions shipped by this
   package.

Condition 6 matters because a public view name alone is not enough. A stale or
tampered view named `public_topics` must not become trusted merely because the
name is public.

## Storage Transform

For free-text fields, storage uses the transform:

```text
stored_text = truncate(redact(clean(raw_text)), L)
```

Redaction precedes truncation. This order is deliberate: if truncation runs
first, an identifier that starts near the length limit can be split before the
redaction pass sees it.

## Distinct-Text Floor

For a set of candidate records `R`, define:

```text
n(R) = count(distinct normalize(note || detail))
```

A topic or aggregate cell is public only when:

```text
n(R) >= k
```

The repository default is `k = 5`. Because the floor counts distinct normalized
text, exact duplicate flooding does not make a repeated record public.

Topic release and aggregate-cell release are checked separately. A public topic
does not make a small group/category cell public.

## Extract Boundary

Publishing creates a separate SQLite database with schema `E`. The extract does
not include private base tables, audit rows, or row-level text. The source audit
head and row count are copied into `meta` so an external record can pin the
source state used for the extract.

## Audit Pinning

The audit table is a hash chain. Verifying the chain alone detects mutation of
retained rows, but it cannot detect deletion of a valid suffix unless the
expected head and row count are pinned externally.

The stronger check is therefore:

```text
verify_chain(expected_head=h, expected_count=c)
```

where `(h, c)` came from a trusted observation before later inspection. This
detects both row mutation and tail clipping.

## Claim Boundary

The implementation is a research prototype. The verified claims are:

- private base tables are denied through the public query path
- public views must match canonical definitions
- public topics and aggregate cells use a distinct-text floor
- row-level text is omitted from the public extract
- CSV exports neutralize spreadsheet formulas
- audit verification can be pinned by head and row count

These are structural controls. They do not prove semantic anonymity, regulatory
compliance, or safety for arbitrary real-world datasets.
