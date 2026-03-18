"""Fetch additional code context from Joern for unknown audit decisions."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .joern_client import JoernClient, JoernClientError


class ContextFetcher:
    """Resolve function/variable/macro context requests via Joern queries."""

    def __init__(self, client: JoernClient, source_paths: List[str] | None = None):
        self.client = client
        self.logger = logging.getLogger(__name__)
        self.source_paths = [str(Path(p).resolve()) for p in (source_paths or [])]

    @staticmethod
    def _escape_for_query(raw: str) -> str:
        return raw.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _strip_ansi(text: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    @staticmethod
    def _extract_json_from_text(raw: str) -> Dict[str, Any]:
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {}
        return {}

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

    def _parse_tuple_rows(self, response_data: Any) -> List[List[str]]:
        if not isinstance(response_data, dict):
            return []

        stdout = self._strip_ansi(str(response_data.get("stdout", "")))
        list_region = self._extract_list_region(stdout)
        if not list_region:
            return []

        rows: List[List[str]] = []
        for tuple_text in self._split_top_level_tuples(list_region):
            fields = self._split_tuple_fields(tuple_text)
            if fields:
                rows.append(fields)
        return rows

    @staticmethod
    def _decode_token(token: str) -> str:
        if token.startswith('"""') and token.endswith('"""') and len(token) >= 6:
            return token[3:-3]
        try:
            return json.loads(token)
        except json.JSONDecodeError:
            return token

    @staticmethod
    def _to_int(raw: str, default: int = -1) -> int:
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    def _query(self, query: str) -> List[List[str]]:
        data = self.client.query_sync(query)
        return self._parse_tuple_rows(data)

    def _query_safe(self, query: str, error_hint: str, errors: List[str]) -> List[List[str]]:
        try:
            return self._query(query)
        except JoernClientError as exc:
            errors.append(f"{error_hint}: {exc}")
            return []

    @staticmethod
    def _dedup_contexts(contexts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate noisy contexts while preserving original order."""
        deduped: List[Dict[str, Any]] = []
        seen: set[Tuple[Any, ...]] = set()

        for ctx in contexts:
            ctype = str(ctx.get("context_type", ""))
            if ctype == "macro_definition":
                # For macros, definition text is usually what LLM needs most.
                key = (
                    ctype,
                    str(ctx.get("name", "")),
                    str(ctx.get("definition", "")).strip(),
                )
            else:
                key = (ctype, json.dumps(ctx, ensure_ascii=False, sort_keys=True))

            if key in seen:
                continue
            seen.add(key)
            deduped.append(ctx)

        return deduped

    def _fetch_function_context(self, name: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        esc = self._escape_for_query(name)
        query_def = (
            'cpg.method.nameExact("' + esc + '")'
            '.map(m => (m.name, m.filename, m.lineNumber.getOrElse(-1), '
            'm.lineNumberEnd.getOrElse(-1), m.code)).l'
        )

        query_callee = (
            'cpg.method.nameExact("' + esc + '")'
            '.callee.map(m => (m.name, m.filename, m.lineNumber.getOrElse(-1), '
            'm.lineNumberEnd.getOrElse(-1))).l'
        )

        query_caller = (
            'cpg.method.nameExact("' + esc + '")'
            '.caller.map(m => (m.name, m.filename, m.lineNumber.getOrElse(-1), '
            'm.lineNumberEnd.getOrElse(-1))).l'
        )

        query_call_out = (
            'cpg.method.nameExact("' + esc + '")'
            '.callOut.map(c => (c.name, c.code, c.location.lineNumber.getOrElse(-1), '
            'c.location.filename)).l'
        )

        query_call_in = (
            'cpg.method.nameExact("' + esc + '")'
            '.callIn.map(c => (c.name, c.code, c.location.lineNumber.getOrElse(-1), '
            'c.location.filename, c.method.name)).l'
        )

        contexts: List[Dict[str, Any]] = []
        errors: List[str] = []
        rows = self._query_safe(query_def, f"function context query failed for {name}", errors)

        for row in rows[:5]:
            if len(row) < 5:
                continue
            contexts.append(
                {
                    "context_type": "function",
                    "name": self._decode_token(row[0]),
                    "file_path": self._decode_token(row[1]),
                    "function_start_line": self._to_int(row[2]),
                    "function_end_line": self._to_int(row[3]),
                    "source": self._decode_token(row[4]),
                }
            )

        callee_rows = self._query_safe(query_callee, f"function callee query failed for {name}", errors)
        for row in callee_rows[:10]:
            if len(row) < 4:
                continue
            contexts.append(
                {
                    "context_type": "function_callee",
                    "name": self._decode_token(row[0]),
                    "file_path": self._decode_token(row[1]),
                    "function_start_line": self._to_int(row[2]),
                    "function_end_line": self._to_int(row[3]),
                }
            )

        caller_rows = self._query_safe(query_caller, f"function caller query failed for {name}", errors)
        for row in caller_rows[:10]:
            if len(row) < 4:
                continue
            contexts.append(
                {
                    "context_type": "function_caller",
                    "name": self._decode_token(row[0]),
                    "file_path": self._decode_token(row[1]),
                    "function_start_line": self._to_int(row[2]),
                    "function_end_line": self._to_int(row[3]),
                }
            )

        call_out_rows = self._query_safe(query_call_out, f"function callOut query failed for {name}", errors)
        for row in call_out_rows[:20]:
            if len(row) < 4:
                continue
            contexts.append(
                {
                    "context_type": "function_call_out",
                    "callee_name": self._decode_token(row[0]),
                    "call_code": self._decode_token(row[1]),
                    "line": self._to_int(row[2]),
                    "file_path": self._decode_token(row[3]),
                }
            )

        call_in_rows = self._query_safe(query_call_in, f"function callIn query failed for {name}", errors)
        for row in call_in_rows[:20]:
            if len(row) < 5:
                continue
            contexts.append(
                {
                    "context_type": "function_call_in",
                    "call_name": self._decode_token(row[0]),
                    "call_code": self._decode_token(row[1]),
                    "line": self._to_int(row[2]),
                    "file_path": self._decode_token(row[3]),
                    "caller_function": self._decode_token(row[4]),
                }
            )

        if not contexts:
            errors.append(f"function context not found for name={name}")

        return contexts, errors

    def _fetch_variable_context(self, function_name: str, var_name: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        esc_var = self._escape_for_query(var_name)
        esc_func = self._escape_for_query(function_name)

        scoped_local_query = (
            'cpg.method.nameExact("' + esc_func + '").local.nameExact("' + esc_var + '")'
            '.map(l => (l.name, l.code, l.location.lineNumber.getOrElse(-1), '
            'l.method.name, l.location.filename)).l'
        )

        global_local_query = (
            'cpg.local.nameExact("' + esc_var + '")'
            '.map(l => (l.name, l.code, l.location.lineNumber.getOrElse(-1), '
            'l.method.name, l.location.filename)).l'
        )

        parameter_query = (
            'cpg.parameter.nameExact("' + esc_var + '")'
            '.map(p => (p.name, p.code, p.location.lineNumber.getOrElse(-1), '
            'p.method.name, p.location.filename)).l'
        )

        member_query = (
            'cpg.member.nameExact("' + esc_var + '")'
            '.map(m => (m.name, m.code, m.location.lineNumber.getOrElse(-1), '
            'm.typeDecl.name, m.location.filename)).l'
        )

        identifier_query = (
            'cpg.identifier.nameExact("' + esc_var + '")'
            '.map(i => (i.name, i.code, i.location.lineNumber.getOrElse(-1), '
            'i.method.name, i.location.filename)).l'
        )

        contexts: List[Dict[str, Any]] = []
        errors: List[str] = []

        rows = self._query_safe(scoped_local_query, f"scoped local query failed for {var_name}", errors)
        if not rows:
            rows = self._query_safe(global_local_query, f"global local query failed for {var_name}", errors)

        for row in rows[:8]:
            if len(row) < 5:
                continue
            contexts.append(
                {
                    "context_type": "variable_local",
                    "name": self._decode_token(row[0]),
                    "definition_code": self._decode_token(row[1]),
                    "line": self._to_int(row[2]),
                    "function_name": self._decode_token(row[3]),
                    "file_path": self._decode_token(row[4]),
                }
            )

        parameter_rows = self._query_safe(parameter_query, f"parameter query failed for {var_name}", errors)
        for row in parameter_rows[:8]:
            if len(row) < 5:
                continue
            contexts.append(
                {
                    "context_type": "variable_parameter",
                    "name": self._decode_token(row[0]),
                    "definition_code": self._decode_token(row[1]),
                    "line": self._to_int(row[2]),
                    "function_name": self._decode_token(row[3]),
                    "file_path": self._decode_token(row[4]),
                }
            )

        member_rows = self._query_safe(member_query, f"member query failed for {var_name}", errors)
        for row in member_rows[:8]:
            if len(row) < 5:
                continue
            contexts.append(
                {
                    "context_type": "variable_member",
                    "name": self._decode_token(row[0]),
                    "definition_code": self._decode_token(row[1]),
                    "line": self._to_int(row[2]),
                    "type_decl": self._decode_token(row[3]),
                    "file_path": self._decode_token(row[4]),
                }
            )

        identifier_rows = self._query_safe(identifier_query, f"identifier usage query failed for {var_name}", errors)
        for row in identifier_rows[:8]:
            if len(row) < 5:
                continue
            contexts.append(
                {
                    "context_type": "variable_identifier_usage",
                    "name": self._decode_token(row[0]),
                    "usage_code": self._decode_token(row[1]),
                    "line": self._to_int(row[2]),
                    "function_name": self._decode_token(row[3]),
                    "file_path": self._decode_token(row[4]),
                }
            )

        if not contexts:
            errors.append(f"variable context not found for name={var_name}")

        return contexts, errors

    def _fetch_macro_context_from_source(self, macro_name: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Fallback macro lookup by scanning source text for #define lines."""
        contexts: List[Dict[str, Any]] = []
        errors: List[str] = []

        pattern = re.compile(r"^\s*#\s*define\s+" + re.escape(macro_name) + r"\b(.*)$")
        for raw_path in self.source_paths:
            path = Path(raw_path)
            if not path.exists() or not path.is_file():
                continue

            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError as exc:
                errors.append(f"macro source read failed for {path}: {exc}")
                continue

            for idx, line in enumerate(lines, start=1):
                m = pattern.match(line)
                if not m:
                    continue
                contexts.append(
                    {
                        "context_type": "macro_definition",
                        "name": macro_name,
                        "file_path": str(path),
                        "line": idx,
                        "definition": line.strip(),
                    }
                )

        if not contexts:
            errors.append(f"macro definition not found in source scan for name={macro_name}")

        return contexts, errors

    def _fetch_macro_context(self, macro_name: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        esc = self._escape_for_query(macro_name)

        # Joern does not always expose C/C++ macros directly. We provide a best-effort
        # lookup using identifiers/calls named as macro symbol and keep clear errors.
        macro_like_query = (
            'cpg.identifier.nameExact("' + esc + '")'
            '.map(i => (i.name, i.code, i.location.lineNumber.getOrElse(-1), '
            'i.method.name, i.location.filename)).l'
        )

        contexts: List[Dict[str, Any]] = []
        errors: List[str] = []

        rows = self._query_safe(macro_like_query, f"macro context query failed for {macro_name}", errors)

        for row in rows[:8]:
            if len(row) < 5:
                continue
            contexts.append(
                {
                    "context_type": "macro_usage",
                    "name": self._decode_token(row[0]),
                    "usage_code": self._decode_token(row[1]),
                    "line": self._to_int(row[2]),
                    "function_name": self._decode_token(row[3]),
                    "file_path": self._decode_token(row[4]),
                }
            )

        # Always try source scan for #define so the model gets concrete macro definitions,
        # not only identifier usages.
        source_contexts, source_errors = self._fetch_macro_context_from_source(macro_name)
        contexts.extend(source_contexts)
        if source_errors and not source_contexts:
            errors.extend(source_errors)

        contexts = self._dedup_contexts(contexts)

        if not contexts:
            errors.append(f"macro context not found for name={macro_name}")

        return contexts, errors

    def fetch_contexts(
        self,
        unit: Dict[str, Any],
        need_context: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Fetch contexts requested by model and return (contexts, errors)."""
        candidate = unit.get("candidate", {})
        function_name = str(candidate.get("function_name", "")).strip()

        contexts: List[Dict[str, Any]] = []
        errors: List[str] = []

        seen_req: set[Tuple[str, str]] = set()

        for req in need_context:
            req_type = str(req.get("type", "")).strip().lower()
            name = str(req.get("name", "")).strip()

            if not req_type or not name:
                errors.append(f"invalid context request: {req}")
                continue

            req_key = (req_type, name)
            if req_key in seen_req:
                continue
            seen_req.add(req_key)

            if req_type == "function":
                sub_ctx, sub_err = self._fetch_function_context(name)
            elif req_type == "variable":
                sub_ctx, sub_err = self._fetch_variable_context(function_name=function_name, var_name=name)
            elif req_type == "macro":
                sub_ctx, sub_err = self._fetch_macro_context(name)
            else:
                sub_ctx, sub_err = [], [f"unsupported context request type={req_type} name={name}"]

            contexts.extend(sub_ctx)
            errors.extend(sub_err)

        return self._dedup_contexts(contexts), errors
