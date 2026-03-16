"""HTTP client for local Joern server."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import requests


class JoernClientError(Exception):
    """Raised when Joern server request fails."""


class JoernClient:
    """Simple Joern HTTP client based on requests."""

    def __init__(self, server_url: str, timeout_seconds: int = 120):
        self.server_url = server_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def _escape_for_joern_string(raw: str) -> str:
        # Escape backslashes and double quotes for Joern REPL string literal.
        return raw.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _truncate(text: str, size: int = 300) -> str:
        if len(text) <= size:
            return text
        return text[:size] + "..."

    @staticmethod
    def _contains_error_text(text: str) -> bool:
        if not text:
            return False
        markers = ["[E008]", "Error:", "Not Found Error", "Exception"]
        return any(marker in text for marker in markers)

    def _raise_query_error(self, query: str, response_data: Any) -> None:
        query_hint = self._truncate(" ".join(query.split()))
        stderr = ""
        stdout = ""
        if isinstance(response_data, dict):
            stderr = str(response_data.get("stderr", "")).strip()
            stdout = str(response_data.get("stdout", "")).strip()

        detail_parts = [f"Joern query failed. url={self.server_url}", f"query={query_hint}"]
        if stderr:
            detail_parts.append(f"stderr={self._truncate(stderr)}")
        if stdout:
            detail_parts.append(f"stdout={self._truncate(stdout)}")
        raise JoernClientError(" | ".join(detail_parts))

    def query(self, query_str: str) -> Any:
        """Execute Joern query via query-sync endpoint and return parsed response."""
        payload = {"query": query_str}
        self.logger.info("Joern query-sync request. url=%s", self.server_url)

        try:
            resp = requests.post(self.server_url, json=payload, timeout=self.timeout_seconds)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise JoernClientError(
                f"Failed to call Joern query endpoint: {self.server_url}. "
                "Please verify server URL and network connectivity."
            ) from exc

        try:
            data: Any = resp.json()
        except ValueError:
            text = (resp.text or "").strip()
            if not text:
                data = {}
            else:
                data = {"stdout": text}

        if isinstance(data, dict):
            stdout = str(data.get("stdout", "")).strip()
            stderr = str(data.get("stderr", "")).strip()
            if stdout:
                self.logger.info("Joern stdout: %s", self._truncate(stdout))
            if stderr:
                self.logger.warning("Joern stderr: %s", self._truncate(stderr))

            # query-sync commonly reports errors here even on HTTP 200.
            if data.get("success") is False:
                self._raise_query_error(query_str, data)
            if self._contains_error_text(stderr) or self._contains_error_text(stdout):
                self._raise_query_error(query_str, data)

        return data

    def query_sync(self, query: str) -> Any:
        """Backward-compatible alias for synchronous query execution."""
        return self.query(query)

    def import_code(self, input_path: str) -> Any:
        """Import code into Joern workspace by executing importCode via query-sync."""
        abs_path = str(Path(input_path).resolve())
        escaped = self._escape_for_joern_string(abs_path)
        query = f'importCode("{escaped}")'
        self.logger.info("Importing into Joern via query-sync. path=%s", abs_path)
        try:
            return self.query(query)
        except JoernClientError as exc:
            raise JoernClientError(
                f"Failed to import path via query-sync. path={abs_path}. {exc}"
            ) from exc


def extract_records(response_data: Any) -> List[Dict[str, Any]]:
    """Extract list[dict] records from common Joern query response shapes."""
    if isinstance(response_data, list):
        return [x for x in response_data if isinstance(x, dict)]

    if isinstance(response_data, dict):
        for key in ("result", "results", "data", "value"):
            value = response_data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]

        # query-sync often puts output in stdout as JSON string or lines.
        stdout = response_data.get("stdout")
        if isinstance(stdout, str):
            text = stdout.strip()
            if not text:
                return []

            # Try parse the whole stdout as JSON first.
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    return [x for x in parsed if isinstance(x, dict)]
                if isinstance(parsed, dict):
                    return [parsed]
            except json.JSONDecodeError:
                pass

            # Fallback: parse per line.
            records: List[Dict[str, Any]] = []
            for line in text.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        records.append(obj)
                except json.JSONDecodeError:
                    continue
            return records

    return []
