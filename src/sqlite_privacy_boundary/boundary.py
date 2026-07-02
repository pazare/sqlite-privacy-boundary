"""SQLite public-view boundary with k-anonymous text exposure."""

from __future__ import annotations

import csv
import io
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from . import __version__
from . import audit
from .pii import redact_pii
from .topics import cluster

K_ANON = 5
QUERY_ROW_LIMIT = 500
QUERY_TIME_LIMIT_SECONDS = 1.5
FORMULA_PREFIXES = ("=", "+", "-", "@")

PRIVATE_BASE_TABLES = {"records", "topics", "record_topic", "audit"}
PUBLIC_VIEWS = {"public_topics", "public_documents", "aggregate_cells"}
PUBLIC_SCHEMA_OBJECTS = PUBLIC_VIEWS
SENSITIVE_COLUMNS = {
    "records": {"sensitive_contact", "raw_location"},
}
ALLOWED_SQL_FUNCTIONS = {
    "avg",
    "char",
    "coalesce",
    "count",
    "ifnull",
    "length",
    "lower",
    "max",
    "min",
    "nullif",
    "round",
    "spb_norm",
    "substr",
    "sum",
    "trim",
    "upper",
}
_RECORD_TEXT_SQL = "spb_norm(note || char(31) || detail)"


class BoundaryError(RuntimeError):
    """Raised when an operation would cross the public boundary."""


@dataclass(frozen=True)
class QueryResult:
    columns: list[str]
    rows: list[dict[str, Any]]
    truncated: bool
    elapsed_seconds: float


SCHEMA = f"""
create table if not exists records (
    id integer primary key autoincrement,
    created_at text not null default (datetime('now')),
    group_key text not null default '',
    category text not null default '',
    note text not null default '',
    detail text not null default '',
    pii_redactions integer not null default 0,
    sensitive_contact text not null default '',
    raw_location text not null default ''
);
create table if not exists topics (
    id integer primary key autoincrement,
    label text not null,
    size integer not null,
    sentiment real not null default 0.0,
    is_public integer not null default 0
);
create table if not exists record_topic (
    record_id integer not null references records(id) on delete cascade,
    topic_id integer not null references topics(id) on delete cascade,
    primary key(record_id, topic_id)
);
create view if not exists public_topics as
    select id, label, size, sentiment
    from topics
    where is_public = 1;
create view if not exists public_documents as
    select r.id, r.created_at, r.group_key, r.category,
           trim(r.note || char(10) || r.detail) as content,
           t.label as topic_label
    from records r
    join record_topic rt on rt.record_id = r.id
    join topics t on t.id = rt.topic_id and t.is_public = 1;
create view if not exists aggregate_cells as
    select group_key, category, count(distinct {_RECORD_TEXT_SQL}) as n
    from records
    group by group_key, category
    having count(distinct {_RECORD_TEXT_SQL}) >= {K_ANON};
"""

PUBLIC_EXTRACT_SCHEMA = """
create table public_topics (
    id integer primary key,
    label text not null,
    size integer not null,
    sentiment real not null
);
create table public_documents (
    id integer primary key,
    created_at text not null,
    group_key text not null,
    category text not null,
    content text not null,
    topic_label text not null
);
create table aggregate_cells (
    group_key text not null,
    category text not null,
    n integer not null
);
create table meta (key text primary key, value text not null);
"""


@contextmanager
def connect(db_path: Path | str) -> Iterator[sqlite3.Connection]:
    path = Path(db_path)
    if path.parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.create_function("spb_norm", 1, normalize_text)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: Path | str) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        audit.ensure_audit_table(conn)


def add_record(db_path: Path | str, payload: dict[str, Any]) -> dict[str, Any]:
    init_db(db_path)
    note, n_note = redact_pii(clean_text(payload.get("note"), 2_000))
    detail, n_detail = redact_pii(clean_text(payload.get("detail"), 2_000))
    values = {
        "group_key": clean_text(payload.get("group_key"), 120),
        "category": clean_text(payload.get("category"), 120),
        "note": note,
        "detail": detail,
        "pii_redactions": n_note + n_detail,
        "sensitive_contact": clean_text(payload.get("sensitive_contact"), 240),
        "raw_location": clean_text(payload.get("raw_location"), 240),
    }
    with connect(db_path) as conn:
        cursor = conn.execute(
            "insert into records(group_key, category, note, detail, pii_redactions, "
            "sensitive_contact, raw_location) values(:group_key, :category, :note, :detail, "
            ":pii_redactions, :sensitive_contact, :raw_location)",
            values,
        )
        row_id = int(cursor.lastrowid)
        audit.record(conn, "system", "insert_record", f"record:{row_id}", f"redactions={values['pii_redactions']}")
        recompute_topics(conn)
        topic = conn.execute(
            "select t.id, t.label, t.size, t.is_public "
            "from topics t join record_topic rt on rt.topic_id = t.id "
            "where rt.record_id = ?",
            (row_id,),
        ).fetchone()
    return {
        "id": row_id,
        "pii_redactions": values["pii_redactions"],
        "topic": dict(topic) if topic and topic["is_public"] else None,
    }


def recompute_topics(conn: sqlite3.Connection, k_anon: int = K_ANON) -> dict[str, int]:
    rows = conn.execute(
        "select id, note, detail from records order by id"
    ).fetchall()
    documents = [(int(row["id"]), " ".join([row["note"], row["detail"]]).strip()) for row in rows]
    conn.execute("delete from record_topic")
    conn.execute("delete from topics")
    public_count = 0
    for topic in cluster(documents):
        distinct = distinct_count(topic.texts)
        is_public = int(distinct >= k_anon)
        cursor = conn.execute(
            "insert into topics(label, size, sentiment, is_public) values(?, ?, ?, ?)",
            (topic.label, distinct, topic.sentiment, is_public),
        )
        topic_id = int(cursor.lastrowid)
        if is_public:
            public_count += 1
        for record_id in topic.members:
            conn.execute(
                "insert into record_topic(record_id, topic_id) values(?, ?)",
                (record_id, topic_id),
            )
    audit.record(conn, "system", "recompute_topics", "topics", f"public={public_count}")
    return {"topics": len(documents), "public_topics": public_count}


def run_readonly_query(db_path: Path | str, sql: str, row_limit: int = QUERY_ROW_LIMIT) -> QueryResult:
    query = sql.strip()
    if not query:
        raise BoundaryError("Write a SQL query first.")
    lowered = query.lower().lstrip()
    if not (lowered.startswith("select") or lowered.startswith("with")):
        raise BoundaryError("Only read-only SELECT/WITH queries are allowed.")
    started = time.monotonic()
    with connect(db_path) as conn:
        conn.execute("pragma query_only = on")
        conn.set_authorizer(readonly_authorizer)
        conn.set_progress_handler(lambda: int(time.monotonic() - started > QUERY_TIME_LIMIT_SECONDS), 1_000)
        try:
            cursor = conn.execute(query)
            rows = cursor.fetchmany(row_limit + 1)
        except sqlite3.DatabaseError as exc:
            message = str(exc)
            if "is prohibited" in message:
                raise BoundaryError("That field or object is outside the public boundary.") from exc
            if "interrupted" in message:
                raise BoundaryError("SQL query took too long.") from exc
            raise BoundaryError(f"SQL query failed: {message}") from exc
        finally:
            conn.set_progress_handler(None, 0)
        columns = [description[0] for description in cursor.description or []]
    return QueryResult(
        columns=columns,
        rows=[{column: row[column] for column in columns} for row in rows[:row_limit]],
        truncated=len(rows) > row_limit,
        elapsed_seconds=time.monotonic() - started,
    )


def readonly_authorizer(action: int, arg1: str | None, arg2: str | None, db_name: str | None, trigger: str | None) -> int:
    if action == sqlite3.SQLITE_READ:
        table = (arg1 or "").lower()
        column = (arg2 or "").lower()
        view = (trigger or "").lower()
        if table.startswith("sqlite_") or table == "dbstat":
            return sqlite3.SQLITE_DENY
        if column in SENSITIVE_COLUMNS.get(table, set()):
            return sqlite3.SQLITE_DENY
        if table in PRIVATE_BASE_TABLES and view not in PUBLIC_VIEWS:
            return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION:
        function = (arg2 or arg1 or "").lower()
        if function not in ALLOWED_SQL_FUNCTIONS:
            return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION} else sqlite3.SQLITE_DENY


def export_csv(db_path: Path | str, view: str) -> str:
    if view not in PUBLIC_VIEWS:
        raise BoundaryError("Unknown public view.")
    result = run_readonly_query(db_path, f"select * from {quote_identifier(view)}")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=result.columns)
    writer.writeheader()
    for row in result.rows:
        writer.writerow({column: csv_safe_cell(row[column]) for column in result.columns})
    return output.getvalue()


def publish_extract(db_path: Path | str, out_path: Path | str) -> dict[str, Any]:
    out = Path(out_path)
    tmp = out.with_name(out.name + f".tmp-{os.getpid()}")
    with connect(db_path) as conn:
        topics = conn.execute("select * from public_topics order by size desc, id asc").fetchall()
        documents = conn.execute("select * from public_documents order by id asc").fetchall()
        cells = conn.execute("select * from aggregate_cells order by n desc").fetchall()
        audit_head, audit_count = audit.head(conn)
    try:
        dest = sqlite3.connect(tmp)
        try:
            dest.executescript(PUBLIC_EXTRACT_SCHEMA)
            dest.executemany(
                "insert into public_topics(id, label, size, sentiment) values(?, ?, ?, ?)",
                [(row["id"], row["label"], row["size"], row["sentiment"]) for row in topics],
            )
            dest.executemany(
                "insert into public_documents(id, created_at, group_key, category, content, topic_label) "
                "values(?, ?, ?, ?, ?, ?)",
                [
                    (row["id"], row["created_at"], row["group_key"], row["category"], row["content"], row["topic_label"])
                    for row in documents
                ],
            )
            dest.executemany(
                "insert into aggregate_cells(group_key, category, n) values(?, ?, ?)",
                [(row["group_key"], row["category"], row["n"]) for row in cells],
            )
            dest.executemany(
                "insert into meta(key, value) values(?, ?)",
                [
                    ("schema", "sqlite_privacy_boundary_extract_v1"),
                    ("k_anon", str(K_ANON)),
                    ("topics_public", str(len(topics))),
                    ("documents_public", str(len(documents))),
                    ("audit_head", audit_head),
                    ("audit_count", str(audit_count)),
                    ("generated_by", f"sqlite-privacy-boundary {__version__}"),
                ],
            )
            dest.commit()
        finally:
            dest.close()
        os.replace(tmp, out)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise
    with connect(db_path) as conn:
        audit.record(conn, "system", "publish_extract", str(out), f"topics={len(topics)}")
    return {"out": str(out), "topics": len(topics), "documents": len(documents), "cells": len(cells)}


def schema_catalog(db_path: Path | str) -> dict[str, list[dict[str, Any]]]:
    catalog: dict[str, list[dict[str, Any]]] = {}
    with connect(db_path) as conn:
        names = [
            row["name"]
            for row in conn.execute(
                "select name from sqlite_master where type in ('table', 'view') and name not like 'sqlite_%' order by name"
            )
            if row["name"] in PUBLIC_SCHEMA_OBJECTS
        ]
        for name in names:
            catalog[name] = [dict(row) for row in conn.execute(f"pragma table_info({quote_identifier(name)})")]
    return catalog


def normalize_text(value: str | None) -> str:
    text = "" if value is None else str(value)
    return re.sub(r"\s+", " ", text.lower()).strip()


def distinct_count(texts: list[str]) -> int:
    return len({normalize_text(text) for text in texts if normalize_text(text)})


def clean_text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", " ").strip()
    return text[:limit]


def csv_safe_cell(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'

