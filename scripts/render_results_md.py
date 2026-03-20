#!/usr/bin/env python3
"""Render audit_results.json to a human-readable Markdown report.

Features:
- Keep original result content (file, function range, reason, token usage).
- Add source snippets around each bug line.
- Prefer local source files from audit.target; optional Joern fallback.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config_loader import ConfigError, load_config
from src.joern_client import JoernClient, JoernClientError

SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
}


@dataclass
class SourceResolver:
    roots: List[Path]
    files: List[Path]

    @classmethod
    def from_targets(cls, targets: Sequence[str]) -> "SourceResolver":
        roots: List[Path] = []
        files: List[Path] = []
        seen = set()

        for raw in targets:
            p = Path(str(raw)).resolve()
            if not p.exists():
                continue

            if p.is_file() and p.suffix.lower() in SOURCE_EXTENSIONS:
                rp = p.resolve()
                if rp not in seen:
                    seen.add(rp)
                    files.append(rp)
                roots.append(rp.parent)
                continue

            if p.is_dir():
                roots.append(p)
                for child in p.rglob("*"):
                    if not child.is_file() or child.suffix.lower() not in SOURCE_EXTENSIONS:
                        continue
                    rc = child.resolve()
                    if rc in seen:
                        continue
                    seen.add(rc)
                    files.append(rc)

        return cls(roots=roots, files=files)

    def resolve(self, raw_file_path: str) -> Optional[Path]:
        if not raw_file_path:
            return None

        candidate = Path(raw_file_path)
        if candidate.is_absolute() and candidate.exists():
            return candidate.resolve()

        normalized = raw_file_path.replace("\\", "/").strip("/")
        if not normalized:
            return None

        # 1) Try relative to each root directly.
        for root in self.roots:
            joined = (root / normalized).resolve()
            if joined.exists() and joined.is_file():
                return joined

        # 2) Basename unique match.
        name = Path(normalized).name
        if name:
            name_matches = [p for p in self.files if p.name == name]
            if len(name_matches) == 1:
                return name_matches[0]

        # 3) Suffix path match against known files.
        suffix = "/" + normalized
        suffix_matches = [
            p for p in self.files if p.as_posix().endswith(suffix) or p.as_posix().endswith(normalized)
        ]
        if len(suffix_matches) == 1:
            return suffix_matches[0]

        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render audit_results.json to Markdown")
    parser.add_argument(
        "--config",
        default=str(PROJECT_ROOT / "configs" / "config.yaml"),
        help="Path to config.yaml",
    )
    parser.add_argument(
        "--input",
        default=str(PROJECT_ROOT / "outputs" / "results" / "audit_results.json"),
        help="Path to audit_results.json",
    )
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "outputs" / "results" / "audit_results.md"),
        help="Path to output markdown file",
    )
    parser.add_argument(
        "--context-lines",
        type=int,
        default=3,
        help="How many lines before/after bug line to show",
    )
    parser.add_argument(
        "--joern-fallback",
        action="store_true",
        help="Use Joern query fallback when local source file is not found",
    )
    return parser.parse_args()


def _safe_int_list(value: Any) -> List[int]:
    if not isinstance(value, list):
        return []
    out: List[int] = []
    for x in value:
        if isinstance(x, int):
            out.append(x)
    return out


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Result JSON root must be object")
    return data


def _read_snippet(file_path: Path, line_no: int, radius: int) -> str:
    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if not lines:
        return "(empty file)"

    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)

    rendered: List[str] = []
    for idx in range(start, end + 1):
        marker = ">" if idx == line_no else " "
        rendered.append(f"{marker} {idx:5d} | {lines[idx - 1]}")
    return "\n".join(rendered)


def _language_from_suffix(path: Path) -> str:
    suf = path.suffix.lower()
    if suf in {".c", ".h"}:
        return "c"
    if suf in {".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}:
        return "cpp"
    return "text"


def _display_path(raw: Any) -> str:
    value = str(raw or "").strip().replace("\\", "/")
    if not value:
        return ""

    marker = "/juliet-test-suite-c/"
    idx = value.find(marker)
    if idx >= 0:
        return value[idx + len(marker) :].strip("/")

    p = Path(value)
    if p.is_absolute():
        return p.name
    return value.strip("/")


def _make_joern_fallback_snippet(
    client: JoernClient,
    raw_file_path: str,
    bug_line: int,
) -> Optional[str]:
    escaped = JoernClient._escape_for_joern_string(Path(raw_file_path).name)
    query = (
        'cpg.method.filename(".*' + escaped + '")'
        '.filter(m => m.lineNumber.getOrElse(-1) <= ' + str(bug_line) + ' && '
        'm.lineNumberEnd.getOrElse(-1) >= ' + str(bug_line) + ')'
        '.map(m => (m.name, m.filename, m.lineNumber.getOrElse(-1), m.lineNumberEnd.getOrElse(-1), m.code)).l'
    )

    try:
        data = client.query_sync(query)
    except JoernClientError:
        return None

    if not isinstance(data, dict):
        return None
    stdout = str(data.get("stdout", "")).strip()
    if not stdout:
        return None
    return stdout


def render_markdown(
    payload: Dict[str, Any],
    resolver: SourceResolver,
    context_lines: int,
    joern_client: Optional[JoernClient] = None,
) -> str:
    task_info = payload.get("task_info", {}) if isinstance(payload.get("task_info"), dict) else {}
    results = payload.get("results", []) if isinstance(payload.get("results"), list) else []

    lines: List[str] = []
    lines.append("# Audit Results Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- generated_at: {task_info.get('generated_at', '')}")
    lines.append(f"- model: {task_info.get('model', '')}")

    overall = task_info.get("overall_token_usage", {}) if isinstance(task_info.get("overall_token_usage"), dict) else {}
    lines.append(f"- overall_prompt_tokens: {int(overall.get('prompt_tokens', 0) or 0)}")
    lines.append(f"- overall_completion_tokens: {int(overall.get('completion_tokens', 0) or 0)}")
    lines.append(f"- overall_total_tokens: {int(overall.get('total_tokens', 0) or 0)}")
    lines.append(f"- findings_count: {len([x for x in results if isinstance(x, dict)])}")

    for idx, item in enumerate(results, start=1):
        if not isinstance(item, dict):
            continue

        file_path = _display_path(item.get("file_path", ""))
        bug_lines = _safe_int_list(item.get("bug_lines", []))
        reason = str(item.get("reason", "")).strip()
        function_start = int(item.get("function_start_line", -1) or -1)
        function_end = int(item.get("function_end_line", -1) or -1)
        usage = item.get("token_usage", {}) if isinstance(item.get("token_usage"), dict) else {}

        lines.append("")
        lines.append(f"## Finding {idx}")
        lines.append("")
        lines.append(f"- file_path: {file_path}")
        lines.append(f"- function_start_line: {function_start}")
        lines.append(f"- function_end_line: {function_end}")
        lines.append(f"- bug_lines: {bug_lines}")
        lines.append(f"- reason: {reason}")
        lines.append(
            "- token_usage: "
            f"prompt={int(usage.get('prompt_tokens', 0) or 0)}, "
            f"completion={int(usage.get('completion_tokens', 0) or 0)}, "
            f"total={int(usage.get('total_tokens', 0) or 0)}"
        )

        resolved_file = resolver.resolve(file_path)
        if not bug_lines:
            lines.append("")
            lines.append("### Source Context")
            lines.append("")
            lines.append("No bug lines provided.")
            continue

        lines.append("")
        lines.append("### Source Context")
        lines.append("")

        for bug_line in bug_lines:
            lines.append(f"#### Around bug line {bug_line}")
            lines.append("")
            if resolved_file is not None and resolved_file.exists():
                snippet = _read_snippet(resolved_file, bug_line, context_lines)
                lang = _language_from_suffix(resolved_file)
                lines.append(f"(source: {_display_path(resolved_file)})")
                lines.append("")
                lines.append(f"```{lang}")
                lines.append(snippet)
                lines.append("```")
                lines.append("")
                continue

            lines.append("Local source file not found from audit.target.")
            if joern_client is not None:
                fb = _make_joern_fallback_snippet(joern_client, file_path, bug_line)
                if fb:
                    lines.append("")
                    lines.append("Joern fallback (raw function match output):")
                    lines.append("")
                    lines.append("```text")
                    lines.append(fb)
                    lines.append("```")
                else:
                    lines.append("Joern fallback: no matching function context returned.")
            lines.append("")

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()

    if args.context_lines < 0:
        print("[ERROR] --context-lines must be >= 0")
        return 1

    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}")
        return 1

    try:
        config = load_config(Path(args.config).resolve())
    except ConfigError as exc:
        print(f"[ERROR] Config error: {exc}")
        return 1

    resolver = SourceResolver.from_targets(config.get("audit", {}).get("target", []))

    joern_client: Optional[JoernClient] = None
    if args.joern_fallback:
        joern_cfg = config.get("joern", {}) if isinstance(config.get("joern", {}), dict) else {}
        joern_client = JoernClient(
            server_url=str(joern_cfg.get("server_url", "http://127.0.0.1:8080/query-sync")),
            timeout_seconds=int(joern_cfg.get("timeout_seconds", 120) or 120),
        )

    try:
        payload = _load_json(input_path)
        md = render_markdown(
            payload=payload,
            resolver=resolver,
            context_lines=int(args.context_lines),
            joern_client=joern_client,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Failed to render markdown: {exc}")
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md, encoding="utf-8")

    logging.getLogger(__name__).info("Markdown report written to: %s", output_path)
    print(f"[OK] Markdown report written to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
