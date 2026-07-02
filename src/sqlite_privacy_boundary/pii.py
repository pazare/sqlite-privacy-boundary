"""Pattern-based redaction for free-text fields."""

from __future__ import annotations

import re
import unicodedata

_PII_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[email]"),
    (re.compile(r"\bhttps?://\S+\b"), "[link]"),
    (re.compile(r"(?<!\w)\(?\+?\d(?:[\s().\-]*\d){6,}(?!\w)"), "[phone]"),
    (re.compile(r"(?<!\w)@[A-Za-z0-9_]{2,}\b"), "[handle]"),
    (
        re.compile(
            r"\b\d{1,5}\s+([A-Za-z0-9.]+\s){0,4}"
            r"(st|street|ave|avenue|rd|road|blvd|boulevard|ln|lane|dr|drive|"
            r"ct|court|way|pl|place)\b",
            re.IGNORECASE,
        ),
        "[address]",
    ),
    (re.compile(r"(?<!\w)\d{5}(?:-\d{4})?(?!\w)"), "[zip]"),
    (re.compile(r"(?<!\w)\d{6,}(?!\w)"), "[number]"),
)


def redact_pii(text: str) -> tuple[str, int]:
    """Return ``(clean_text, redaction_count)``.

    The function normalizes unicode look-alikes and removes default-ignorable
    format characters before matching.
    """
    if not text:
        return text, 0
    cleaned = unicodedata.normalize("NFKC", text)
    cleaned = "".join(ch for ch in cleaned if unicodedata.category(ch) != "Cf")
    count = 0
    for pattern, replacement in _PII_PATTERNS:
        cleaned, n = pattern.subn(replacement, cleaned)
        count += n
    cleaned = re.sub(r"[ \t]+", " ", cleaned).strip()
    return cleaned, count
