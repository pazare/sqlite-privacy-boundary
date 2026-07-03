from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from sqlite_privacy_boundary import add_record, init_db, publish_extract, run_readonly_query


def main() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        db = root / "demo.sqlite3"
        out = root / "public.sqlite3"
        init_db(db)

        for text in [
            "Alpha sensor drift exceeded the baseline threshold.",
            "The alpha sensor baseline drift increased again.",
            "Baseline drift in alpha sensor readings is persistent.",
            "Alpha measurements show drift above the threshold.",
            "Sensor alpha drift remains above baseline.",
        ]:
            add_record(db, {"group_key": "cohort_a", "category": "topic_a", "note": text})

        rows = run_readonly_query(db, "select label, size from public_topics").rows
        print(rows)
        print(publish_extract(db, out))


if __name__ == "__main__":
    main()
