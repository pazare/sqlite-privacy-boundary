"""SQLite privacy-boundary experiments."""

__version__ = "0.1.0"

from .audit import head, record, verify_chain
from .boundary import (
    BoundaryError,
    QueryResult,
    add_record,
    export_csv,
    init_db,
    publish_extract,
    run_readonly_query,
    schema_catalog,
)
from .pii import redact_pii

__all__ = [
    "BoundaryError",
    "QueryResult",
    "__version__",
    "add_record",
    "export_csv",
    "head",
    "init_db",
    "publish_extract",
    "record",
    "redact_pii",
    "run_readonly_query",
    "schema_catalog",
    "verify_chain",
]
