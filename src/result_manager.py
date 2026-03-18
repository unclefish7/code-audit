"""Manage deduplicated audit result persistence."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


class ResultManager:
    """Load, deduplicate, and write final audit results."""

    def __init__(self, output_path: Path, dedup_enabled: bool = True):
        self.output_path = output_path
        self.dedup_enabled = dedup_enabled
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def _dedup_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
        raw_lines = item.get("lines", [])
        if not isinstance(raw_lines, list):
            raw_lines = []
        norm_lines = tuple(sorted(set(int(x) for x in raw_lines if isinstance(x, int))))

        return (
            item.get("cwe", ""),
            item.get("file_path", ""),
            item.get("final_decision", "unknown"),
            norm_lines,
        )

    def _load_payload(self) -> Dict[str, Any]:
        if not self.output_path.exists():
            return {"task_info": {}, "results": []}

        try:
            with self.output_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:  # noqa: BLE001
            self.logger.warning("Failed to load existing results, fallback empty: %s", exc)
            return {"task_info": {}, "results": []}

        if not isinstance(data, dict):
            return {"task_info": {}, "results": []}

        if not isinstance(data.get("results"), list):
            data["results"] = []

        if not isinstance(data.get("task_info"), dict):
            data["task_info"] = {}

        return data

    def append_results(self, model_name: str, new_results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Append deduplicated results and persist output JSON."""
        payload = self._load_payload()
        existing = payload.get("results", [])

        seen = set()
        for item in existing:
            seen.add(self._dedup_key(item))

        kept = 0
        skipped = 0
        for item in new_results:
            key = self._dedup_key(item)
            if self.dedup_enabled and key in seen:
                skipped += 1
                self.logger.info("Skip duplicated result for unit_id=%s", item.get("unit_id", ""))
                continue

            existing.append(item)
            seen.add(key)
            kept += 1

        payload["task_info"] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model": model_name,
        }
        payload["results"] = existing

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        self.logger.info(
            "Results written. output=%s total=%d kept=%d skipped=%d",
            self.output_path,
            len(existing),
            kept,
            skipped,
        )
        return {"kept": kept, "skipped": skipped, "total": len(existing)}
