"""Offline checks for the public-boundary claims."""

from __future__ import annotations

import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import audit
from .boundary import BoundaryError, add_record, init_db, publish_extract, run_readonly_query
from .pii import redact_pii

GROUP = [
    "Rent keeps rising and housing is unaffordable.",
    "Housing costs keep rising near transit.",
    "Affordable housing would help my family.",
    "Rent takes too much of my paycheck.",
    "We need more affordable housing options.",
]
FLOOD = "Rent is too high and housing is unaffordable."


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


def run_all() -> list[Check]:
    return [
        check_determinism(),
        check_k_anonymity(),
        check_redaction_at_rest(),
        check_sql_guard(),
        check_audit_chain(),
        check_published_extract(),
    ]


def check_determinism() -> Check:
    signatures = []
    for _ in range(2):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "d.sqlite3"
            init_db(db)
            for text in GROUP:
                add_record(db, {"group_key": "A", "category": "housing", "note": text})
            signatures.append(tuple((r["label"], r["size"]) for r in run_readonly_query(db, "select label, size from public_topics").rows))
    ok = signatures[0] == signatures[1] and len(signatures[0]) == 1
    return Check("determinism", ok, f"identical={signatures[0] == signatures[1]}")


def check_k_anonymity() -> Check:
    with tempfile.TemporaryDirectory() as directory:
        db = Path(directory) / "k.sqlite3"
        init_db(db)
        for text in GROUP:
            add_record(db, {"group_key": "A", "category": "housing", "note": text})
        surfaced = run_readonly_query(db, "select label, size from public_topics").rows

        flood = Path(directory) / "flood.sqlite3"
        init_db(flood)
        for _ in range(5):
            add_record(flood, {"group_key": "A", "category": "housing", "note": FLOOD})
        flooded = run_readonly_query(flood, "select label, size from public_topics").rows
    ok = len(surfaced) == 1 and surfaced[0]["size"] >= 5 and flooded == []
    return Check("k_anonymity", ok, f"distinct={len(surfaced)} duplicate_flood={len(flooded)}")


def check_redaction_at_rest() -> Check:
    with tempfile.TemporaryDirectory() as directory:
        db = Path(directory) / "p.sqlite3"
        init_db(db)
        add_record(
            db,
            {
                "group_key": "A",
                "category": "contact",
                "note": "Email jane@example.com or call 415-555-0199.",
                "sensitive_contact": "jane@example.com",
                "raw_location": "15213",
            },
        )
        stored = run_readonly_query(db, "select content from public_documents").rows
        contact_blocked = _blocked(db, "select sensitive_contact from records")
        location_blocked = _blocked(db, "select raw_location from records")
    text_ok = stored == []
    direct, _ = redact_pii("Reach me at jane．doe＠example．com please.")
    unicode_ok = "[email]" in direct and "@" not in direct
    ok = text_ok and contact_blocked and location_blocked and unicode_ok
    return Check("redaction_at_rest", ok, f"below_floor_hidden={text_ok} sensitive_blocked={contact_blocked and location_blocked}")


def check_sql_guard() -> Check:
    with tempfile.TemporaryDirectory() as directory:
        db = Path(directory) / "s.sqlite3"
        init_db(db)
        for text in GROUP:
            add_record(db, {"group_key": "A", "category": "housing", "note": text})
        safe = not _blocked(db, "select label, size from public_topics")
        blocked = sum(
            _blocked(db, sql)
            for sql in (
                "delete from records",
                "update records set note = 'x'",
                "pragma table_info(records)",
                "select randomblob(8)",
                "select sensitive_contact from records",
                "select * from topics",
                "select sql from sqlite_master",
            )
        )
    ok = safe and blocked == 7
    return Check("sql_guard", ok, f"safe={safe} blocked={blocked}/7")


def check_audit_chain() -> Check:
    with tempfile.TemporaryDirectory() as directory:
        db = Path(directory) / "a.sqlite3"
        init_db(db)
        add_record(db, {"note": GROUP[0]})
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        try:
            intact = audit.verify_chain(conn)
            conn.execute("update audit set detail = 'tampered' where id = 1")
            broken = not audit.verify_chain(conn)
        finally:
            conn.close()
    ok = intact and broken
    return Check("audit_chain", ok, f"intact={intact} tamper_detected={broken}")


def check_published_extract() -> Check:
    with tempfile.TemporaryDirectory() as directory:
        db = Path(directory) / "e.sqlite3"
        init_db(db)
        add_record(db, {"group_key": "A", "category": "housing", "note": "Email jane@example.com about rent."})
        for text in GROUP:
            add_record(db, {"group_key": "A", "category": "housing", "note": text})
        out = Path(directory) / "public.sqlite3"
        publish_extract(db, out)
        conn = sqlite3.connect(out)
        conn.row_factory = sqlite3.Row
        try:
            tables = {r["name"] for r in conn.execute("select name from sqlite_master where type='table'")}
            blob = ""
            for table in tables:
                for row in conn.execute(f"select * from {table}"):
                    blob += " ".join("" if value is None else str(value) for value in dict(row).values())
        finally:
            conn.close()
    no_private = "records" not in tables and "audit" not in tables
    no_pii = "@" not in blob and "jane" not in blob.lower()
    ok = no_private and no_pii and "public_topics" in tables
    return Check("published_extract", ok, f"no_private={no_private} no_pii={no_pii}")


def _blocked(db_path: Path, sql: str) -> bool:
    try:
        run_readonly_query(db_path, sql)
        return False
    except BoundaryError:
        return True


def main() -> int:
    checks = run_all()
    for check in checks:
        mark = "PASS" if check.passed else "FAIL"
        print(f"[{mark}] {check.name}: {check.detail}")
    passed = sum(check.passed for check in checks)
    print(f"{passed}/{len(checks)} checks passed.")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())

