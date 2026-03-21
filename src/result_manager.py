"""Manage deduplicated audit result persistence."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .path_utils import normalize_audit_file_path


class ResultManager:
    """Load, deduplicate, and write final audit results."""

    def __init__(self, output_path: Path, dedup_enabled: bool = True):
        self.output_path = output_path
        self.dedup_enabled = dedup_enabled
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def _dedup_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
        if "file_path" not in item:
            return ("invalid", id(item))

        raw_lines = item.get("bug_lines", item.get("lines", []))
        if not isinstance(raw_lines, list):
            raw_lines = []
        norm_lines = tuple(sorted(set(int(x) for x in raw_lines if isinstance(x, int))))

        return (
            item.get("file_path", ""),
            int(item.get("function_start_line", -1) or -1),
            int(item.get("function_end_line", -1) or -1),
            norm_lines,
        )

    @staticmethod
    def _normalize_file_path(raw_path: Any) -> str:
        return normalize_audit_file_path(raw_path)

    @staticmethod
    def _format_result_for_output(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Already normalized finding item (new schema)
        if "final_decision" not in item and "file_path" in item and "reason" in item:
            raw_bug_lines = item.get("bug_lines", item.get("lines", []))
            if not isinstance(raw_bug_lines, list):
                raw_bug_lines = []
            usage = item.get("token_usage", {}) if isinstance(item.get("token_usage", {}), dict) else {}
            return {
                "file_path": ResultManager._normalize_file_path(item.get("file_path", "")),
                "function_start_line": int(item.get("function_start_line", -1) or -1),
                "function_end_line": int(item.get("function_end_line", -1) or -1),
                "bug_lines": [int(x) for x in raw_bug_lines if isinstance(x, int)],
                "reason": item.get("reason", ""),
                "token_usage": {
                    "prompt_tokens": int(usage.get("prompt_tokens", 0) or 0),
                    "completion_tokens": int(usage.get("completion_tokens", 0) or 0),
                    "total_tokens": int(usage.get("total_tokens", 0) or 0),
                },
            }

        decision = str(item.get("final_decision", "")).strip().lower()
        usage = item.get("token_usage", {}) if isinstance(item.get("token_usage", {}), dict) else {}

        normalized_usage = {
            "prompt_tokens": int(usage.get("prompt_tokens", 0) or 0),
            "completion_tokens": int(usage.get("completion_tokens", 0) or 0),
            "total_tokens": int(usage.get("total_tokens", 0) or 0),
        }

        if decision != "yes":
            return None

        lines = item.get("lines", [])
        if not isinstance(lines, list):
            lines = []

        return {
            "file_path": ResultManager._normalize_file_path(item.get("file_path", "")),
            "function_start_line": int(item.get("function_start_line", -1) or -1),
            "function_end_line": int(item.get("function_end_line", -1) or -1),
            "bug_lines": [int(x) for x in lines if isinstance(x, int)],
            "reason": item.get("reason", ""),
            "token_usage": normalized_usage,
        }

    @staticmethod
    def _aggregate_token_usage(results: List[Dict[str, Any]]) -> Dict[str, int]:
        total_prompt = 0
        total_completion = 0
        total_tokens = 0

        for item in results:
            usage = item.get("token_usage", {}) if isinstance(item.get("token_usage", {}), dict) else {}
            prompt = int(usage.get("prompt_tokens", 0) or 0)
            completion = int(usage.get("completion_tokens", 0) or 0)
            total = int(usage.get("total_tokens", 0) or 0)
            if total <= 0:
                total = prompt + completion

            total_prompt += prompt
            total_completion += completion
            total_tokens += total

        return {
            "prompt_tokens": total_prompt,
            "completion_tokens": total_completion,
            "total_tokens": total_tokens,
        }

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
        existing_raw = payload.get("results", [])
        existing: List[Dict[str, Any]] = []
        for item in existing_raw:
            if not isinstance(item, dict):
                continue
            formatted = self._format_result_for_output(item)
            if formatted is not None:
                existing.append(formatted)

        seen = set()
        for item in existing:
            seen.add(self._dedup_key(item))

        kept = 0
        skipped = 0
        for item in new_results:
            output_item = self._format_result_for_output(item)
            if output_item is None:
                continue
            key = self._dedup_key(output_item)
            if self.dedup_enabled and key in seen:
                skipped += 1
                self.logger.info("Skip duplicated result for unit_id=%s", item.get("unit_id", ""))
                continue

            existing.append(output_item)
            seen.add(key)
            kept += 1

        payload["task_info"] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model": model_name,
            "overall_token_usage": self._aggregate_token_usage(existing),
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
