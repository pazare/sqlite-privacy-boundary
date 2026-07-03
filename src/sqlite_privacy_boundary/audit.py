"""Tamper-evident audit rows for SQLite transactions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

GENESIS = "0" * 64


def ensure_audit_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        create table if not exists audit (
            id integer primary key autoincrement,
            ts text not null,
            actor text not null,
            action text not null,
            target text not null default '',
            detail text not null default '',
            prev_hash text not null,
            hash text not null
        )
        """
    )


def _digest(*fields: str) -> str:
    payload = json.dumps(list(fields), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def record(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    target: str = "",
    detail: str = "",
    *,
    now: str | None = None,
) -> str:
    ensure_audit_table(conn)
    ts = now or now_iso()
    row = conn.execute("select hash from audit order by id desc limit 1").fetchone()
    prev = row[0] if row else GENESIS
    digest = _digest(prev, ts, actor, action, target, detail)
    conn.execute(
        "insert into audit(ts, actor, action, target, detail, prev_hash, hash) "
        "values(?, ?, ?, ?, ?, ?, ?)",
        (ts, actor, action, target, detail, prev, digest),
    )
    return digest


def head(conn: sqlite3.Connection) -> tuple[str, int]:
    ensure_audit_table(conn)
    row = conn.execute("select hash from audit order by id desc limit 1").fetchone()
    count = conn.execute("select count(*) from audit").fetchone()[0]
    return (row[0] if row else GENESIS), int(count)


def verify_chain(
    conn: sqlite3.Connection,
    *,
    expected_head: str | None = None,
    expected_count: int | None = None,
) -> bool:
    ensure_audit_table(conn)
    prev = GENESIS
    count = 0
    for ts, actor, action, target, detail, prev_hash, row_hash in conn.execute(
        "select ts, actor, action, target, detail, prev_hash, hash from audit order by id asc"
    ):
        count += 1
        if prev_hash != prev:
            return False
        expected = _digest(prev_hash, ts, actor, action, target, detail)
        if expected != row_hash:
            return False
        prev = row_hash
    if expected_head is not None and prev != expected_head:
        return False
    if expected_count is not None and count != expected_count:
        return False
    return True
