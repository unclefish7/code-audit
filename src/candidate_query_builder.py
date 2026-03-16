"""Build Joern query strings from enabled rules."""

from __future__ import annotations

from typing import Dict, List


class CandidateQueryBuilder:
    """Generate first-version Joern queries for candidate extraction."""

    def __init__(self, rules_config: Dict[str, bool]):
        self.rules_config = rules_config

    def build_queries(self) -> List[Dict[str, str]]:
        """Return query specs in tuple-based style for stable parsing."""
        queries: List[Dict[str, str]] = []

        if self.rules_config.get("enable_cwe78", False):
            queries.append(
                {
                    "cwe": "CWE-78",
                    "rule_type": "sink_call",
                    "query": self._build_cwe78_query(),
                }
            )

        if self.rules_config.get("enable_cwe259", False):
            queries.extend(self._build_cwe259_queries())

        return queries

    @staticmethod
    def _build_cwe78_query() -> str:
        # Candidate + function context in one query:
        # (call_name, match_code, match_line, function_name, file_path,
        #  function_start_line, function_end_line, function_source)
        return r'''
cpg.call
  .name("system|popen|execl|execv|execve")
  .map(c => (
    c.name,
    c.code,
    c.location.lineNumber.get,
    c.method.name,
    c.location.filename,
    c.method.lineNumber.get,
    c.method.lineNumberEnd.get,
    c.method.code
  ))
  .l
'''.strip()

    @staticmethod
    def _build_cwe259_queries() -> List[Dict[str, str]]:
        """Build simple, compilable CWE-259 candidate queries with function context."""
        return [
            {
                "cwe": "CWE-259",
                "rule_type": "sensitive_identifier",
                "query": r'''
cpg.identifier
  .name("(?i).*(password|passwd|pwd|pass|auth|login).*")
  .map(i => (
    i.name,
    i.code,
    i.location.lineNumber.get,
    i.method.name,
    i.location.filename,
    i.method.lineNumber.get,
    i.method.lineNumberEnd.get,
    i.method.code
  ))
  .l
'''.strip(),
            },
            {
                "cwe": "CWE-259",
                "rule_type": "suspicious_literal",
                "query": r'''
cpg.literal
  .code("(?i).*(password|passwd|pwd|admin|root|secret|token).*")
  .map(l => (
    l.code,
    l.code,
    l.location.lineNumber.get,
    l.method.name,
    l.location.filename,
    l.method.lineNumber.get,
    l.method.lineNumberEnd.get,
    l.method.code
  ))
  .l
'''.strip(),
            },
            {
                "cwe": "CWE-259",
                "rule_type": "sensitive_compare_call",
                "query": r'''
cpg.call
  .name("(?i).*(strcmp|strncmp|memcmp|login|auth|authenticate|check).*")
  .map(c => (
    c.name,
    c.code,
    c.location.lineNumber.get,
    c.method.name,
    c.location.filename,
    c.method.lineNumber.get,
    c.method.lineNumberEnd.get,
    c.method.code
  ))
  .l
'''.strip(),
            },
        ]
