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


def verify_chain(conn: sqlite3.Connection) -> bool:
    ensure_audit_table(conn)
    prev = GENESIS
    for row in conn.execute(
        "select ts, actor, action, target, detail, prev_hash, hash from audit order by id asc"
    ):
        if row["prev_hash"] != prev:
            return False
        expected = _digest(
            row["prev_hash"], row["ts"], row["actor"], row["action"], row["target"], row["detail"]
        )
        if expected != row["hash"]:
            return False
        prev = row["hash"]
    return True

