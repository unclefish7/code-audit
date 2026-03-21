#!/usr/bin/env python3
"""Deduplicate audit_results.json by file path + function range + bug lines."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_PATH = PROJECT_ROOT / "outputs" / "results" / "audit_results.json"


def _as_int(value: Any, default: int = -1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_bug_lines(item: Dict[str, Any]) -> List[int]:
    raw_lines = item.get("bug_lines", item.get("lines", []))
    if isinstance(raw_lines, int):
        raw_lines = [raw_lines]
    if not isinstance(raw_lines, list):
        raw_lines = []
    return sorted(set(_as_int(x, default=-1) for x in raw_lines if _as_int(x, default=-1) >= 0))


def _normalize_file_path(raw_path: Any) -> str:
    value = str(raw_path or "").strip().replace("\\", "/").strip("/")
    if not value:
        return ""

    marker = "/juliet-test-suite-c/"
    idx = value.find(marker)
    if idx >= 0:
        value = value[idx + len(marker) :].strip("/")

    p = Path(value)
    if p.is_absolute():
        return p.name

    parts = [seg for seg in value.split("/") if seg]
    if not parts:
        return ""

    # Treat "CWE259_Hard_Coded_Password/xxx__..." and "xxx__..." as the same file.
    basename = parts[-1]
    if len(parts) >= 2:
        parent = parts[-2]
        if basename.startswith(parent + "__"):
            return basename

    return "/".join(parts)


def _dedup_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
    file_path = _normalize_file_path(item.get("file_path", ""))
    function_start_line = _as_int(item.get("function_start_line", -1), default=-1)
    function_end_line = _as_int(item.get("function_end_line", -1), default=-1)
    bug_lines = tuple(_normalize_bug_lines(item))
    return (file_path, function_start_line, function_end_line, bug_lines)


def _aggregate_token_usage(results: List[Dict[str, Any]]) -> Dict[str, int]:
    prompt_tokens = 0
    completion_tokens = 0
    total_tokens = 0

    for item in results:
        usage = item.get("token_usage", {})
        if not isinstance(usage, dict):
            continue
        prompt = _as_int(usage.get("prompt_tokens", 0), default=0)
        completion = _as_int(usage.get("completion_tokens", 0), default=0)
        total = _as_int(usage.get("total_tokens", 0), default=0)
        if total <= 0:
            total = prompt + completion
        prompt_tokens += max(prompt, 0)
        completion_tokens += max(completion, 0)
        total_tokens += max(total, 0)

    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }


def dedup_payload(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    results = payload.get("results", [])
    if not isinstance(results, list):
        results = []

    deduped: List[Dict[str, Any]] = []
    seen = set()
    dropped = 0

    for item in results:
        if not isinstance(item, dict):
            dropped += 1
            continue
        key = _dedup_key(item)
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        deduped.append(item)

    payload["results"] = deduped

    task_info = payload.get("task_info", {})
    if not isinstance(task_info, dict):
        task_info = {}
    task_info["overall_token_usage"] = _aggregate_token_usage(deduped)
    payload["task_info"] = task_info

    stats = {
        "before": len(results),
        "after": len(deduped),
        "dropped": dropped,
    }
    return payload, stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deduplicate audit results by file_path + function range + bug_lines",
    )
    parser.add_argument(
        "--input",
        default=str(DEFAULT_RESULTS_PATH),
        help="Path to input audit_results.json",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Path to output JSON. Defaults to overwrite input.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only print stats, do not write files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve() if args.output else input_path

    if not input_path.exists():
        print(f"[ERROR] Input not found: {input_path}")
        return 1

    with input_path.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    if not isinstance(payload, dict):
        print("[ERROR] Input JSON root must be an object.")
        return 1

    payload, stats = dedup_payload(payload)
    print(
        f"Dedup done. before={stats['before']} after={stats['after']} dropped={stats['dropped']}"
    )

    if args.dry_run:
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"Wrote deduplicated results to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
