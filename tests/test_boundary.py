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
    schema_catalog,
)
from sqlite_privacy_boundary.pii import redact_pii
from sqlite_privacy_boundary.selfcheck import run_all
from sqlite_privacy_boundary.topics import _hash_term, sentiment_score


GROUP = [
    "Alpha sensor drift exceeded the baseline threshold.",
    "The alpha sensor baseline drift increased again.",
    "Baseline drift in alpha sensor readings is persistent.",
    "Alpha measurements show drift above the threshold.",
    "Sensor alpha drift remains above baseline.",
]
CONTACT_EMAIL = "jane" + "@" + "example.com"
CONTACT_PHONE = "415" + "-555" + "-0199"


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
                "category": "topic_a",
                "note": f"Email {CONTACT_EMAIL} or call {CONTACT_PHONE}.",
                "sensitive_contact": CONTACT_EMAIL,
                "raw_location": "15213",
            },
        )
        self.assertGreaterEqual(result["pii_redactions"], 2)
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        try:
            stored = conn.execute("select note from records").fetchone()["note"]
        finally:
            conn.close()
        self.assertIn("[email]", stored)
        self.assertIn("[phone]", stored)
        self.assertNotIn("@", stored)
        self.assertNotIn("555", stored)
        with self.assertRaises(BoundaryError):
            run_readonly_query(self.db, "select sensitive_contact from records")
        with self.assertRaises(BoundaryError):
            run_readonly_query(self.db, "select raw_location from records")

    def test_redacts_before_truncating_long_text(self) -> None:
        result = add_record(self.db, {"note": ("x" * 1990) + " " + CONTACT_EMAIL})
        self.assertGreaterEqual(result["pii_redactions"], 1)
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        try:
            stored = conn.execute("select note from records").fetchone()["note"]
        finally:
            conn.close()
        self.assertLessEqual(len(stored), 2_000)
        self.assertIn("[email]", stored)
        self.assertNotIn("@", stored)

    def test_unicode_redaction(self) -> None:
        clean, n = redact_pii("Reach me at jane．doe＠example．com or 415\u200b555\u200b0199")
        self.assertGreaterEqual(n, 2)
        self.assertIn("[email]", clean)
        self.assertIn("[phone]", clean)
        self.assertNotIn("@", clean)
        self.assertNotIn("555", clean)

    def test_k_anonymous_public_views_and_duplicate_floor(self) -> None:
        for text in GROUP:
            add_record(self.db, {"group_key": "cohort_a", "category": "topic_a", "note": text})
        rows = run_readonly_query(self.db, "select label, size from public_topics").rows
        self.assertEqual(len(rows), 1)
        self.assertGreaterEqual(rows[0]["size"], 5)
        with self.assertRaises(BoundaryError):
            run_readonly_query(self.db, "select content from public_documents")

        db2 = Path(self.tmp.name) / "flood.sqlite3"
        init_db(db2)
        for _ in range(5):
            add_record(db2, {"group_key": "cohort_a", "category": "topic_a", "note": GROUP[0]})
        self.assertEqual(run_readonly_query(db2, "select * from public_topics").rows, [])
        self.assertEqual(run_readonly_query(db2, "select * from aggregate_cells").rows, [])

    def test_aggregate_cells_do_not_follow_public_topic_when_cell_is_small(self) -> None:
        for index, text in enumerate(GROUP):
            group = "small_a" if index < 4 else "small_b"
            add_record(self.db, {"group_key": group, "category": "topic_a", "note": text})
        self.assertEqual(len(run_readonly_query(self.db, "select * from public_topics").rows), 1)
        self.assertEqual(run_readonly_query(self.db, "select * from aggregate_cells").rows, [])

    def test_sql_guard_blocks_private_objects_and_writes(self) -> None:
        for text in GROUP:
            add_record(self.db, {"group_key": "cohort_a", "category": "topic_a", "note": text})
        run_readonly_query(self.db, "select label from public_topics")
        for sql in (
            "delete from records",
            "update records set note = 'x'",
            "select * from records",
            "select * from topics",
            "with leaked as (select * from records) select * from leaked",
            "select (select count(*) from records) as n",
            "select sql from sqlite_master",
            "select randomblob(10)",
        ):
            with self.assertRaises(BoundaryError, msg=sql):
                run_readonly_query(self.db, sql)

    def test_stale_public_views_are_rejected_and_repaired(self) -> None:
        for text in GROUP:
            add_record(self.db, {"group_key": "cohort_a", "category": "topic_a", "note": text})
        conn = sqlite3.connect(self.db)
        try:
            conn.executescript(
                """
                drop view public_topics;
                create view public_topics as
                    select note as label, 1 as size, 0.0 as sentiment from records;
                drop view aggregate_cells;
                create view aggregate_cells as
                    select note as group_key, category, 99 as n from records;
                """
            )
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(BoundaryError):
            run_readonly_query(self.db, "select label from public_topics")
        with self.assertRaises(BoundaryError):
            export_csv(self.db, "aggregate_cells")

        init_db(self.db)
        rows = run_readonly_query(self.db, "select label, size from public_topics").rows
        self.assertEqual(len(rows), 1)
        self.assertNotEqual(rows[0]["label"], GROUP[0])

    def test_schema_catalog_lists_only_public_objects(self) -> None:
        catalog = schema_catalog(self.db)
        self.assertEqual(set(catalog), {"aggregate_cells", "public_topics"})
        blob = " ".join(column["name"] for columns in catalog.values() for column in columns)
        self.assertNotIn("sensitive_contact", blob)
        self.assertNotIn("raw_location", blob)

    def test_csv_export_is_formula_safe(self) -> None:
        for text in GROUP:
            add_record(self.db, {"group_key": "=2+2", "category": "topic_a", "note": text})
        csv_text = export_csv(self.db, "aggregate_cells")
        self.assertIn("'=2+2", csv_text)
        with self.assertRaises(BoundaryError):
            export_csv(self.db, "public_documents")

    def test_extract_omits_private_tables_and_pii(self) -> None:
        add_record(self.db, {"group_key": "cohort_a", "category": "topic_a", "note": f"Email {CONTACT_EMAIL} about baseline drift."})
        for text in GROUP:
            add_record(self.db, {"group_key": "cohort_a", "category": "topic_a", "note": text})
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
        self.assertNotIn("public_documents", tables)
        self.assertIn("public_topics", tables)
        self.assertNotIn("@", blob)
        self.assertNotIn("jane", blob.lower())
        self.assertIn("source_audit_head_before_extract", blob)
        self.assertIn("source_audit_count_before_extract", blob)

    def test_audit_chain_detects_tamper(self) -> None:
        add_record(self.db, {"note": GROUP[0]})
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        try:
            head, count = audit.head(conn)
            self.assertTrue(audit.verify_chain(conn, expected_head=head, expected_count=count))
            conn.execute("delete from audit where id = (select max(id) from audit)")
            self.assertTrue(audit.verify_chain(conn))
            self.assertFalse(audit.verify_chain(conn, expected_head=head, expected_count=count))
            conn.rollback()
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
