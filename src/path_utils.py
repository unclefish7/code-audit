"""Path normalization helpers for stable audit file identity."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def normalize_audit_file_path(raw_path: Any) -> str:
    """Normalize file path text for stable dedup and display.

    Rules:
    - Normalize slashes and trim whitespace.
    - If path contains '/juliet-test-suite-c/', strip prefix before it.
    - Convert absolute paths to basename (stable across staging dirs).
    """
    value = str(raw_path or "").strip().replace("\\", "/")
    if not value:
        return ""

    marker = "/juliet-test-suite-c/"
    idx = value.find(marker)
    if idx >= 0:
        value = value[idx + len(marker) :]

    p = Path(value)
    if p.is_absolute():
        return p.name

    value = value.strip("/")
    parts = [seg for seg in value.split("/") if seg]
    if not parts:
        return ""

    return "/".join(parts)
