"""Run iterative LLM audit on audit units."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

if __package__ in (None, ""):
    # Support running this file directly: python src/audit_runner.py
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from src.context_fetcher import ContextFetcher
    from src.llm_client import LLMClient, LLMClientError
else:
    from .context_fetcher import ContextFetcher
    from .llm_client import LLMClient, LLMClientError


SYSTEM_PROMPT = (
    "You are a strict security audit assistant. "
    "Always reply with a single JSON object only, no markdown, no extra text."
)

MAIN_AUDIT_PROMPT = """
You are auditing one code audit unit for vulnerability judgment.

Rules:
1. Judge only based on provided evidence/context.
2. Output JSON only.
3. decision must be one of: yes, no, unknown.
4. If decision is yes or no, output fields: decision, lines, reason.
5. If decision is unknown, output fields: decision, reason, need_context.
6. need_context must be a non-empty array when decision=unknown.
7. need_context[].type must be one of: function, variable, macro.
8. need_context[] items must include name.
9. Focus on the current candidate function and its direct dataflow/callees only.
10. Do not request unrelated good/bad branch symbols from other paths.

Schema for yes/no:
{
  "decision": "yes",
  "lines": [76],
  "reason": "short reason"
}

Schema for unknown:
{
  "decision": "unknown",
  "reason": "short reason",
  "need_context": [
    {"type": "function", "name": "badSource"}
  ]
}

Audit unit JSON:
{unit_json}
""".strip()

CONTINUE_PROMPT = """
Additional context is appended below. Continue the same audit and output JSON only.

Additional contexts JSON:
{contexts_json}
""".strip()

VALIDATE_PROMPT = """
Validate your prior conclusion using all conversation evidence.

Rules:
1. Output JSON only.
2. If evidence is sufficient, return validated=true and keep final_decision as yes/no.
3. If evidence is insufficient/contradictory, return validated=false and final_decision=unknown.

Schema:
{
  "validated": true,
  "final_decision": "yes",
  "lines": [76],
  "reason": "short reason"
}
""".strip()


class AuditRunner:
    """Coordinate per-unit single-session iterative audit workflow."""

    def __init__(self, config: Dict[str, Any], llm_client: LLMClient, context_fetcher: ContextFetcher):
        self.config = config
        self.llm = llm_client
        self.fetcher = context_fetcher
        self.logger = logging.getLogger(__name__)

        audit_cfg = config.get("audit", {})
        self.max_iterations = int(audit_cfg.get("max_iterations", 3))
        self.enable_validate = bool(audit_cfg.get("enable_validate", True))
        self.record_usage = bool(config.get("token", {}).get("record_usage", True))

    @staticmethod
    def _init_usage() -> Dict[str, int]:
        return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    @staticmethod
    def _accumulate_usage(total: Dict[str, int], usage: Optional[Dict[str, int]]) -> None:
        if not usage:
            return
        total["prompt_tokens"] += int(usage.get("prompt_tokens", 0) or 0)
        total["completion_tokens"] += int(usage.get("completion_tokens", 0) or 0)
        total["total_tokens"] += int(usage.get("total_tokens", 0) or 0)

    @staticmethod
    def _extract_json_block(text: str) -> str:
        text = (text or "").strip()
        if not text:
            return ""

        if text.startswith("{") and text.endswith("}"):
            return text

        start = text.find("{")
        if start < 0:
            return ""

        depth = 0
        in_quote = False
        escaped = False

        for i in range(start, len(text)):
            ch = text[i]
            if in_quote:
                if escaped:
                    escaped = False
                    continue
                if ch == "\\":
                    escaped = True
                    continue
                if ch == '"':
                    in_quote = False
                continue

            if ch == '"':
                in_quote = True
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]

        return ""

    def _parse_json(self, raw_text: str) -> Optional[Dict[str, Any]]:
        text = (raw_text or "").strip()
        if not text:
            return None

        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        block = self._extract_json_block(text)
        if not block:
            return None

        try:
            parsed = json.loads(block)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None

        return None

    @staticmethod
    def _normalize_lines(raw_lines: Any) -> List[int]:
        if not isinstance(raw_lines, list):
            return []
        result: List[int] = []
        for item in raw_lines:
            try:
                result.append(int(item))
            except (TypeError, ValueError):
                continue
        return sorted(set(result))

    @staticmethod
    def _build_result_base(unit: Dict[str, Any]) -> Dict[str, Any]:
        candidate = unit.get("candidate", {})
        return {
            "cwe": candidate.get("cwe", ""),
            "file_path": candidate.get("file_path", ""),
        }

    def _chat_once(self, messages: List[Dict[str, str]], usage_total: Dict[str, int]) -> Optional[Dict[str, Any]]:
        self.logger.info("调用LLM中...")
        try:
            response = self.llm.chat(messages)
        except LLMClientError as exc:
            self.logger.error("LLM call failed: %s", exc)
            return None

        text = str(response.get("text", "")).strip()
        usage = response.get("usage")
        if self.record_usage:
            if usage:
                self._accumulate_usage(usage_total, usage)
            else:
                self.logger.warning("LLM response usage missing; continue with partial accumulation")

        messages.append({"role": "assistant", "content": text})
        parsed = self._parse_json(text)
        return parsed

    def _run_single_unit(self, unit: Dict[str, Any]) -> Dict[str, Any]:
        unit_base = self._build_result_base(unit)
        usage_total = self._init_usage()

        messages: List[Dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]

        messages.append(
            {
                "role": "user",
                "content": MAIN_AUDIT_PROMPT.replace(
                    "{unit_json}",
                    json.dumps(unit, ensure_ascii=False, indent=2),
                ),
            }
        )

        decision = "unknown"
        lines: List[int] = []
        reason = "max iterations reached"
        iterations = 0
        validated = False

        for idx in range(1, self.max_iterations + 1):
            iterations = idx
            self.logger.info("第%d轮推理", idx)
            parsed = self._chat_once(messages=messages, usage_total=usage_total)
            if parsed is None:
                self.logger.error("LLM输出不是合法JSON: %s", unit_base.get("file_path", "unknown"))
                decision = "unknown"
                lines = []
                reason = "invalid llm json output"
                break

            round_reason = str(parsed.get("reason", "")).strip()
            if round_reason:
                self.logger.info("LLM理由: %s", round_reason)

            resp_decision = str(parsed.get("decision", "")).strip().lower()
            if resp_decision in ("yes", "no"):
                decision = resp_decision
                lines = self._normalize_lines(parsed.get("lines", []))
                reason = str(parsed.get("reason", "")).strip()
                break

            if resp_decision != "unknown":
                self.logger.error("非法decision值: %s (%s)", resp_decision, unit_base.get("file_path", "unknown"))
                decision = "unknown"
                lines = []
                reason = "unexpected decision format"
                break

            need_context = parsed.get("need_context")
            if not isinstance(need_context, list) or not need_context:
                self.logger.error("decision=unknown但缺少need_context: %s", unit_base.get("file_path", "unknown"))
                decision = "unknown"
                lines = []
                reason = str(parsed.get("reason", "unknown without need_context"))
                break

            allowed = {"function", "variable", "macro"}
            filtered_need_context = []
            for req in need_context:
                if not isinstance(req, dict):
                    continue
                req_type = str(req.get("type", "")).strip().lower()
                req_name = str(req.get("name", "")).strip()
                if req_type not in allowed or not req_name:
                    self.logger.warning("Skip invalid context request: %s", req)
                    continue
                filtered_need_context.append({"type": req_type, "name": req_name})

            if not filtered_need_context:
                self.logger.error("need_context都无效: %s", unit_base.get("file_path", "unknown"))
                decision = "unknown"
                lines = []
                reason = "invalid need_context entries"
                break

            extra_contexts, errors = self.fetcher.fetch_contexts(unit=unit, need_context=filtered_need_context)
            # Log what LLM requested and what was returned
            req_summary = ", ".join([f"{r['type']}:{r['name']}" for r in filtered_need_context])
            self.logger.info(
                "LLM请求上下文 (%s): %s",
                unit_base.get("file_path", unit.get("unit_id", "")),
                req_summary
            )
            
            # Log returned contexts (truncated summary)
            context_summary_parts = []
            for ctx in extra_contexts[:5]:  # Show first 5 contexts
                ctx_type = ctx.get("context_type", "unknown")
                ctx_name = ctx.get("name", "")
                context_summary_parts.append(f"{ctx_type}:{ctx_name[:20]}")
            
            context_str = ", ".join(context_summary_parts)
            if len(extra_contexts) > 5:
                context_str += f", +{len(extra_contexts) - 5} more"
            
            self.logger.info(
                "已返回%d条上下文: %s",
                len(extra_contexts),
                context_str if context_str else "(empty)"
            )
            
            for err in errors:
                self.logger.warning("Context fetch issue for %s: %s", unit_base.get("file_path", "unknown"), err)

            if not extra_contexts:
                decision = "unknown"
                lines = []
                reason = "unable to fetch requested contexts"
                break

            unit_contexts = unit.setdefault("contexts", [])
            if isinstance(unit_contexts, list):
                unit_contexts.extend(extra_contexts)
            else:
                unit["contexts"] = extra_contexts

            messages.append(
                {
                    "role": "user",
                    "content": CONTINUE_PROMPT.format(
                        contexts_json=json.dumps(extra_contexts, ensure_ascii=False, indent=2)
                    ),
                }
            )

            # Context is appended as a user message; continue to next iteration for re-judgement.
            reason = str(parsed.get("reason", "insufficient context")).strip()
            continue

        if decision in ("yes", "no") and self.enable_validate:
            messages.append({"role": "user", "content": VALIDATE_PROMPT})
            parsed_validate = self._chat_once(messages=messages, usage_total=usage_total)
            if parsed_validate is None:
                self.logger.error("Invalid validate JSON for %s", unit_base.get("file_path", "unknown"))
                validated = False
            else:
                validated = bool(parsed_validate.get("validated", False))
                final_decision = str(parsed_validate.get("final_decision", "")).strip().lower()
                if final_decision in ("yes", "no", "unknown"):
                    decision = final_decision
                lines = self._normalize_lines(parsed_validate.get("lines", lines))
                reason = str(parsed_validate.get("reason", reason)).strip()
                if reason:
                    self.logger.info("Validate理由: %s", reason)

        result = {
            **unit_base,
            "final_decision": decision,
            "lines": lines,
            "reason": reason,
            "iterations": iterations,
            "validated": validated,
            "token_usage": usage_total,
        }
        return result

    def run(self, audit_units: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run audit for all units, each in an isolated conversation session."""
        results: List[Dict[str, Any]] = []
        for unit in audit_units:
            candidate = unit.get("candidate", {})
            self.logger.info("开始审计: %s", candidate.get("file_path", unit.get("unit_id", "unknown")))
            result = self._run_single_unit(unit=unit)
            self.logger.info("审计完成: decision=%s lines=%s", result.get("final_decision", "unknown"), result.get("lines", []))
            results.append(result)
        return results
