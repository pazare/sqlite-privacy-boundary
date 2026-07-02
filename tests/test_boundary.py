from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from sqlite_privacy_boundary import audit
from sqlite_privacy_boundary.boundary import (
    BoundaryError,
    add_record,
    export_csv,
    init_db,
    publish_extract,
    run_readonly_query,
)
from sqlite_privacy_boundary.pii import redact_pii
from sqlite_privacy_boundary.selfcheck import run_all
from sqlite_privacy_boundary.topics import _hash_term, sentiment_score


GROUP = [
    "Rent keeps rising and housing is unaffordable.",
    "Housing costs keep rising near transit.",
    "Affordable housing would help my family.",
    "Rent takes too much of my paycheck.",
    "We need more affordable housing options.",
]


class BoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.sqlite3"
        init_db(self.db)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_redacts_pii_and_blocks_private_columns(self) -> None:
        result = add_record(
            self.db,
            {
                "group_key": "A",
                "category": "contact",
                "note": "Email jane@example.com or call 415-555-0199.",
                "sensitive_contact": "jane@example.com",
                "raw_location": "15213",
            },
        )
        self.assertGreaterEqual(result["pii_redactions"], 2)
        with self.assertRaises(BoundaryError):
            run_readonly_query(self.db, "select sensitive_contact from records")
        with self.assertRaises(BoundaryError):
            run_readonly_query(self.db, "select raw_location from records")

    def test_unicode_redaction(self) -> None:
        clean, n = redact_pii("Reach me at jane．doe＠example．com or 415\u200b555\u200b0199")
        self.assertGreaterEqual(n, 2)
        self.assertIn("[email]", clean)
        self.assertIn("[phone]", clean)
        self.assertNotIn("@", clean)
        self.assertNotIn("555", clean)

    def test_k_anonymous_public_views_and_duplicate_floor(self) -> None:
        for text in GROUP:
            add_record(self.db, {"group_key": "A", "category": "housing", "note": text})
        rows = run_readonly_query(self.db, "select label, size from public_topics").rows
        self.assertEqual(len(rows), 1)
        self.assertGreaterEqual(rows[0]["size"], 5)
        docs = run_readonly_query(self.db, "select content from public_documents").rows
        self.assertEqual(len(docs), 5)

        db2 = Path(self.tmp.name) / "flood.sqlite3"
        init_db(db2)
        for _ in range(5):
            add_record(db2, {"group_key": "A", "category": "housing", "note": GROUP[0]})
        self.assertEqual(run_readonly_query(db2, "select * from public_topics").rows, [])
        self.assertEqual(run_readonly_query(db2, "select * from aggregate_cells").rows, [])

    def test_sql_guard_blocks_private_objects_and_writes(self) -> None:
        for text in GROUP:
            add_record(self.db, {"group_key": "A", "category": "housing", "note": text})
        run_readonly_query(self.db, "select label from public_topics")
        for sql in (
            "delete from records",
            "update records set note = 'x'",
            "select * from records",
            "select * from topics",
            "select sql from sqlite_master",
            "select randomblob(10)",
        ):
            with self.assertRaises(BoundaryError, msg=sql):
                run_readonly_query(self.db, sql)

    def test_csv_export_is_formula_safe(self) -> None:
        for text in GROUP:
            add_record(self.db, {"group_key": "A", "category": "housing", "note": text})
        add_record(
            self.db,
            {
                "group_key": "A",
                "category": "housing",
                "note": "=HYPERLINK(\"https://example.invalid\",\"x\") affordable housing",
            },
        )
        csv_text = export_csv(self.db, "public_documents")
        self.assertIn("'=HYPERLINK", csv_text)
        self.assertNotIn("https://example.invalid", csv_text)

    def test_extract_omits_private_tables_and_pii(self) -> None:
        add_record(self.db, {"group_key": "A", "category": "housing", "note": "Email jane@example.com about rent."})
        for text in GROUP:
            add_record(self.db, {"group_key": "A", "category": "housing", "note": text})
        out = Path(self.tmp.name) / "public.sqlite3"
        info = publish_extract(self.db, out)
        self.assertGreaterEqual(info["topics"], 1)
        conn = sqlite3.connect(out)
        conn.row_factory = sqlite3.Row
        try:
            tables = {r["name"] for r in conn.execute("select name from sqlite_master where type='table'")}
            blob = ""
            for table in tables:
                for row in conn.execute(f"select * from {table}"):
                    blob += " ".join("" if v is None else str(v) for v in dict(row).values())
        finally:
            conn.close()
        self.assertNotIn("records", tables)
        self.assertNotIn("audit", tables)
        self.assertIn("public_topics", tables)
        self.assertNotIn("@", blob)
        self.assertNotIn("jane", blob.lower())

    def test_audit_chain_detects_tamper(self) -> None:
        add_record(self.db, {"note": GROUP[0]})
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        try:
            self.assertTrue(audit.verify_chain(conn))
            conn.execute("update audit set detail = 'tampered' where id = 1")
            self.assertFalse(audit.verify_chain(conn))
        finally:
            conn.close()

    def test_topic_helpers(self) -> None:
        self.assertLess(sentiment_score("This is not safe."), 0.0)
        mismatches = sum(
            1
            for i in range(600)
            if _hash_term(f"term{i}")[1] != (1 if (_hash_term(f"term{i}")[0] % 256) & 1 else -1)
        )
        self.assertGreater(mismatches, 150)

    def test_self_checks_pass(self) -> None:
        failed = [check.name for check in run_all() if not check.passed]
        self.assertEqual(failed, [])


if __name__ == "__main__":
    unittest.main()
