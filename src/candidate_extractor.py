"""Execute candidate queries and normalize results."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List

from .joern_client import JoernClient, JoernClientError, extract_records


class CandidateExtractorError(Exception):
    """Raised when candidate query execution fails."""


class CandidateExtractor:
    """Run Joern queries and shape candidates into standard dict list."""

    def __init__(self, client: JoernClient):
        self.client = client
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def _strip_ansi(text: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    @staticmethod
    def _contains_joern_error_text(text: str) -> bool:
        if not text:
            return False
        markers = ["[E008]", "Error:", "Not Found Error", "Exception"]
        return any(marker in text for marker in markers)

    def _ensure_query_not_failed(self, cwe: str, rule_type: str, response_data: Any, query: str) -> None:
        if not isinstance(response_data, dict):
            return

        stdout = self._strip_ansi(str(response_data.get("stdout", "")))
        stderr = self._strip_ansi(str(response_data.get("stderr", "")))

        if self._contains_joern_error_text(stdout) or self._contains_joern_error_text(stderr):
            query_hint = " ".join(query.split())[:300]
            msg = (
                f"Joern query syntax/runtime failed. cwe={cwe} rule_type={rule_type} "
                f"query={query_hint}"
            )
            if stderr.strip():
                msg += f" stderr={stderr[:300]}"
            if stdout.strip():
                msg += f" stdout={stdout[:300]}"
            raise CandidateExtractorError(msg)

    @staticmethod
    def _unescape_scala_string(token: str) -> str:
        """Decode a Scala string token to Python string."""
        if token.startswith('"""') and token.endswith('"""') and len(token) >= 6:
            return token[3:-3]

        try:
            return json.loads(token)
        except json.JSONDecodeError:
            return token

    @staticmethod
    def _extract_list_region(text: str) -> str:
        marker = "List("
        pos = text.find(marker)
        if pos < 0:
            return ""
        return text[pos + len(marker) :]

    def _split_top_level_tuples(self, list_region: str) -> List[str]:
        tuples: List[str] = []
        depth = 0
        start = -1
        i = 0
        in_quote = False
        in_triple = False

        while i < len(list_region):
            ch = list_region[i]
            nxt3 = list_region[i : i + 3]

            if in_triple:
                if nxt3 == '"""':
                    in_triple = False
                    i += 3
                    continue
                i += 1
                continue

            if in_quote:
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    in_quote = False
                i += 1
                continue

            if nxt3 == '"""':
                in_triple = True
                i += 3
                continue

            if ch == '"':
                in_quote = True
                i += 1
                continue

            if ch == '(':
                if depth == 0:
                    start = i
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0 and start >= 0:
                    tuples.append(list_region[start : i + 1])
                    start = -1
            i += 1

        return tuples

    def _split_tuple_fields(self, tuple_text: str) -> List[str]:
        inner = tuple_text.strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1]

        fields: List[str] = []
        start = 0
        i = 0
        in_quote = False
        in_triple = False

        while i < len(inner):
            ch = inner[i]
            nxt3 = inner[i : i + 3]

            if in_triple:
                if nxt3 == '"""':
                    in_triple = False
                    i += 3
                    continue
                i += 1
                continue

            if in_quote:
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    in_quote = False
                i += 1
                continue

            if nxt3 == '"""':
                in_triple = True
                i += 3
                continue

            if ch == '"':
                in_quote = True
                i += 1
                continue

            if ch == ',':
                fields.append(inner[start:i].strip())
                start = i + 1

            i += 1

        tail = inner[start:].strip()
        if tail:
            fields.append(tail)

        return fields

    def _parse_tuple_rows_from_stdout(self, response_data: Any) -> List[List[str]]:
        """Parse Scala List((...)) rows from Joern stdout."""
        if not isinstance(response_data, dict):
            return []

        stdout_raw = str(response_data.get("stdout", ""))
        stdout = self._strip_ansi(stdout_raw)

        list_region = self._extract_list_region(stdout)
        if not list_region:
            return []

        tuple_texts = self._split_top_level_tuples(list_region)
        rows: List[List[str]] = []
        for tuple_text in tuple_texts:
            fields = self._split_tuple_fields(tuple_text)
            if fields:
                rows.append(fields)
        return rows

    @staticmethod
    def _to_int(value: str, default: int = -1) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _slug(text: str) -> str:
        """Create a readable ID-safe token."""
        cleaned = re.sub(r"[^A-Za-z0-9]+", "_", text or "")
        cleaned = cleaned.strip("_")
        return cleaned or "unknown"

    def _build_unit_id(
        self,
        cwe: str,
        function_name: str,
        match_line: int,
        call_name: str,
        rule_type: str,
    ) -> str:
        """Build stable readable unit ID."""
        cwe_part = self._slug(cwe.replace("-", ""))
        func_part = self._slug(function_name)
        line_part = str(match_line if match_line >= 0 else "unknown")
        tail_part = self._slug(call_name or rule_type)
        return f"{cwe_part}_{func_part}_{line_part}_{tail_part}"

    def _build_audit_unit_from_row(self, cwe: str, rule_type: str, row: List[str]) -> Dict[str, Any]:
        """Convert parsed tuple row to an audit_unit."""
        if len(row) >= 8:
            call_name = self._unescape_scala_string(row[0])
            match_code = self._unescape_scala_string(row[1])
            match_line = self._to_int(row[2])
            function_name = self._unescape_scala_string(row[3])
            file_path = self._unescape_scala_string(row[4])
            function_start = self._to_int(row[5])
            function_end = self._to_int(row[6])
            function_source = self._unescape_scala_string(row[7])

            unit_id = self._build_unit_id(
                cwe=cwe,
                function_name=function_name,
                match_line=match_line,
                call_name=call_name,
                rule_type=rule_type,
            )

            candidate: Dict[str, Any] = {
                "cwe": cwe,
                "rule_type": rule_type,
                "function_name": function_name,
                "file_path": file_path,
                "match_line": match_line,
                "match_code": match_code,
            }

            contexts: List[Dict[str, Any]] = [
                {
                    "context_type": "function_source",
                    "function_name": function_name,
                    "file_path": file_path,
                    "function_start_line": function_start,
                    "function_end_line": function_end,
                    "function_source": function_source,
                }
            ]

            return {
                "unit_id": unit_id,
                "candidate": candidate,
                "contexts": contexts,
            }

        # 5-tuple fallback:
        if len(row) >= 5:
            call_name = self._unescape_scala_string(row[0])
            match_code = self._unescape_scala_string(row[1])
            match_line = self._to_int(row[2])
            function_name = self._unescape_scala_string(row[3])
            file_path = self._unescape_scala_string(row[4])

            unit_id = self._build_unit_id(
                cwe=cwe,
                function_name=function_name,
                match_line=match_line,
                call_name=call_name,
                rule_type=rule_type,
            )

            return {
                "unit_id": unit_id,
                "candidate": {
                    "cwe": cwe,
                    "rule_type": rule_type,
                    "function_name": function_name,
                    "file_path": file_path,
                    "match_line": match_line,
                    "match_code": match_code,
                },
                "contexts": [
                    {
                        "context_type": "function_source",
                        "function_name": function_name,
                        "file_path": file_path,
                        "function_start_line": -1,
                        "function_end_line": -1,
                        "function_source": "",
                    }
                ],
            }

        return {
            "unit_id": self._build_unit_id(cwe=cwe, function_name="", match_line=-1, call_name="", rule_type=rule_type),
            "candidate": {
                "cwe": cwe,
                "rule_type": rule_type,
                "function_name": "",
                "file_path": "",
                "match_line": -1,
                "match_code": "",
            },
            "contexts": [
                {
                    "context_type": "function_source",
                    "function_name": "",
                    "file_path": "",
                    "function_start_line": -1,
                    "function_end_line": -1,
                    "function_source": "",
                }
            ],
        }

    @staticmethod
    def _normalize_record(default_cwe: str, record: Dict[str, Any]) -> Dict[str, Any]:
        line_value = record.get("line_number", record.get("lineNumber", -1))
        try:
            line_number = int(line_value) if line_value is not None else -1
        except (TypeError, ValueError):
            line_number = -1

        candidate = {
            "cwe": record.get("cwe", default_cwe),
            "rule_type": record.get("rule_type", "unknown"),
            "function_name": record.get("function_name", ""),
            "file_path": record.get("file_path", ""),
            "line_number": line_number,
            "code": record.get("code", ""),
        }

        # Keep extra fields for future extension.
        for key, value in record.items():
            if key not in candidate:
                candidate[key] = value

        return candidate

    def extract(self, query_specs: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Execute query specs and return audit units."""
        audit_units: List[Dict[str, Any]] = []

        for spec in query_specs:
            cwe = spec["cwe"]
            rule_type = spec["rule_type"]
            query = spec["query"]

            self.logger.info("Running candidate query for %s (%s)", cwe, rule_type)
            try:
                response_data = self.client.query_sync(query)
            except JoernClientError as exc:
                raise CandidateExtractorError(f"Query failed for {cwe} ({rule_type}): {exc}") from exc

            self._ensure_query_not_failed(cwe=cwe, rule_type=rule_type, response_data=response_data, query=query)

            tuple_rows = self._parse_tuple_rows_from_stdout(response_data)
            if tuple_rows:
                self.logger.info("Received %d tuple records for %s (%s)", len(tuple_rows), cwe, rule_type)
                for row in tuple_rows:
                    audit_units.append(self._build_audit_unit_from_row(cwe=cwe, rule_type=rule_type, row=row))
                continue

            records = extract_records(response_data)
            self.logger.info("Received %d raw records for %s (%s)", len(records), cwe, rule_type)

            for record in records:
                item = self._normalize_record(default_cwe=cwe, record=record)
                if item.get("rule_type") == "unknown":
                    item["rule_type"] = rule_type
                unit_id = self._build_unit_id(
                    cwe=item.get("cwe", cwe),
                    function_name=item.get("function_name", ""),
                    match_line=item.get("line_number", -1),
                    call_name=item.get("call_name", ""),
                    rule_type=item.get("rule_type", rule_type),
                )
                audit_units.append(
                    {
                        "unit_id": unit_id,
                        "candidate": {
                            "cwe": item.get("cwe", cwe),
                            "rule_type": item.get("rule_type", rule_type),
                            "function_name": item.get("function_name", ""),
                            "file_path": item.get("file_path", ""),
                            "match_line": item.get("line_number", -1),
                            "match_code": item.get("code", ""),
                        },
                        "contexts": [
                            {
                                "context_type": "function_source",
                                "function_name": item.get("function_name", ""),
                                "file_path": item.get("file_path", ""),
                                "function_start_line": -1,
                                "function_end_line": -1,
                                "function_source": "",
                            }
                        ],
                    }
                )

        # Basic deduplication for stable output.
        unique = []
        seen = set()
        for item in audit_units:
            cand = item.get("candidate", {})
            contexts = item.get("contexts", [])
            primary_ctx = contexts[0] if isinstance(contexts, list) and contexts else {}
            key = (
                cand.get("cwe"),
                cand.get("file_path"),
                cand.get("function_name"),
                primary_ctx.get("function_start_line"),
                primary_ctx.get("function_end_line"),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)

        return unique
