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
    from src.path_utils import normalize_audit_file_path
else:
    from .context_fetcher import ContextFetcher
    from .llm_client import LLMClient, LLMClientError
    from .path_utils import normalize_audit_file_path


SYSTEM_PROMPT = (
        "你是一个严格的安全审计助手。"
        "始终只返回一个 JSON 对象，不要使用 markdown，不要输出任何额外文本。"
)

MAIN_AUDIT_PROMPT = """
你正在审计一个代码审计单元，并给出漏洞判断。

规则：
1. 只能基于已提供的证据/上下文进行判断。
2. 只输出 JSON。
3. decision 必须是 yes、no、unknown 之一。
4. 如果 decision 是 yes 或 no，输出字段：decision、lines、reason。
5. 如果 decision 是 unknown，输出字段：decision、reason、need_context。
6. 当 decision=unknown 时，need_context 必须是非空数组。
7. need_context[].type 必须是 function、variable、macro 之一。
8. need_context[] 每个元素都必须包含 name。
9. 只关注当前 candidate 函数及其直接数据流/直接被调函数。
10. 不要请求其他路径中无关的 good/bad 分支符号。
11. 对于 type=function 的请求，只能请求代码中真实存在且精确的符号名。
12. 不要构造 caller_of_X 或 callee_of_X 这类伪函数名。
13. 如果要查看调用者/被调用者，请请求真实目标函数名本身。
14. 每个函数相关上下文都包含：file_path、function_start_line、function_end_line、函数源码。
15. 如果 decision 为 yes，lines 必须是当前文件中漏洞行号组成的非空整数数组。
16. 不要把注释标签当作函数请求（例如 badSource/goodSource/connect_socket），除非它们在代码里是实际符号。

yes/no 的输出结构：
{
  "decision": "yes",
  "lines": [76],
  "reason": "short reason"
}

unknown 的输出结构：
{
  "decision": "unknown",
  "reason": "short reason",
  "need_context": [
        {"type": "function", "name": "actual_existing_function_name"}
  ]
}

审计单元 JSON：
{unit_json}
""".strip()

CONTINUE_PROMPT = """
下面追加了额外上下文。请继续同一审计，并且仅输出 JSON。

追加上下文 JSON：
{contexts_json}
""".strip()

YES_LINES_FIX_PROMPT = """
你上一次输出中 decision=yes，但没有给出有效且非空的 lines。
请基于已有证据重新判断，并且只输出 JSON。
当 decision=yes 时，lines 必须是非空整数数组。
""".strip()

CONTEXT_MISS_PROMPT = """
请求的上下文未找到。

上下文获取错误：
{errors_json}

请继续同一审计，并且只输出 JSON。
如果 decision 仍为 unknown，请使用真实存在且精确的符号名请求不同上下文。
""".strip()

VALIDATE_PROMPT = """
请基于当前会话中的全部证据校验你之前的结论。

规则：
1. 只输出 JSON。
2. 如果证据充分，返回 validated=true，并保持 final_decision 为 yes/no。
3. 如果证据不足或存在矛盾，返回 validated=false，并将 final_decision 设为 unknown。

输出结构：
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
        self.enable_validate = bool(
            audit_cfg.get("validate_stage_enabled", audit_cfg.get("enable_validate", True))
        )
        self.stateless_llm_calls = bool(audit_cfg.get("stateless_llm_calls", False))
        self.record_usage = bool(config.get("token", {}).get("record_usage", True))
        self.llm_context_max_lines = int(audit_cfg.get("llm_context_max_lines", 500))

    def _truncate_code_for_llm(self, code_text: str) -> str:
        """Limit code context length before sending to LLM."""
        text = str(code_text or "")
        lines = text.splitlines()
        if len(lines) <= self.llm_context_max_lines:
            return text

        kept = lines[: self.llm_context_max_lines]
        omitted = len(lines) - self.llm_context_max_lines
        kept.append(f"/* ... truncated {omitted} lines by llm_context_max_lines ... */")
        return "\n".join(kept)

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
    def _extract_function_range(unit: Dict[str, Any]) -> Dict[str, int]:
        contexts = unit.get("contexts", [])
        if not isinstance(contexts, list):
            return {"function_start_line": -1, "function_end_line": -1}

        for ctx in contexts:
            if not isinstance(ctx, dict):
                continue
            if str(ctx.get("context_type", "")).strip() != "function_source":
                continue
            try:
                start = int(ctx.get("function_start_line", -1))
            except (TypeError, ValueError):
                start = -1
            try:
                end = int(ctx.get("function_end_line", -1))
            except (TypeError, ValueError):
                end = -1
            return {"function_start_line": start, "function_end_line": end}

        return {"function_start_line": -1, "function_end_line": -1}

    @classmethod
    def _build_result_base(cls, unit: Dict[str, Any]) -> Dict[str, Any]:
        candidate = unit.get("candidate", {})
        func_range = cls._extract_function_range(unit)
        return {
            "cwe": candidate.get("cwe", ""),
            "file_path": normalize_audit_file_path(candidate.get("file_path", "")),
            "function_start_line": func_range["function_start_line"],
            "function_end_line": func_range["function_end_line"],
        }

    def _normalize_context_for_llm(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        ctype = str(ctx.get("context_type", "")).strip()
        def as_int(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return -1

        if ctype in {
            "function_source",
            "function",
            "function_caller_source",
            "function_callee_source",
            "function_fuzzy_match",
        }:
            src_raw = str(ctx.get("source", "") or ctx.get("function_source", ""))
            src = self._truncate_code_for_llm(src_raw)
            return {
                "context_type": ctype,
                "name": str(ctx.get("name", "") or ctx.get("function_name", "")),
                "file_path": normalize_audit_file_path(ctx.get("file_path", "")),
                "function_start_line": as_int(ctx.get("function_start_line", -1)),
                "function_end_line": as_int(ctx.get("function_end_line", -1)),
                "source": src,
            }
        return ctx

    def _build_unit_for_llm(self, unit: Dict[str, Any]) -> Dict[str, Any]:
        candidate = unit.get("candidate", {})
        contexts_raw = unit.get("contexts", [])
        contexts_norm: List[Dict[str, Any]] = []

        if isinstance(contexts_raw, list):
            for ctx in contexts_raw:
                if isinstance(ctx, dict):
                    contexts_norm.append(self._normalize_context_for_llm(ctx))

        return {
            "unit_id": unit.get("unit_id", ""),
            "candidate": candidate,
            "contexts": contexts_norm,
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

    def _chat_with_full_prompt(
        self,
        unit: Dict[str, Any],
        usage_total: Dict[str, int],
        extra_instruction: str = "",
    ) -> Optional[Dict[str, Any]]:
        unit_json = json.dumps(self._build_unit_for_llm(unit), ensure_ascii=False, indent=2)
        user_content = MAIN_AUDIT_PROMPT.replace("{unit_json}", unit_json)
        if extra_instruction.strip():
            user_content = f"{user_content}\n\n额外要求：\n{extra_instruction.strip()}"

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]
        return self._chat_once(messages=messages, usage_total=usage_total)

    def _run_single_unit(self, unit: Dict[str, Any]) -> Dict[str, Any]:
        unit_base = self._build_result_base(unit)
        usage_total = self._init_usage()

        messages: List[Dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]

        messages.append(
            {
                "role": "user",
                "content": MAIN_AUDIT_PROMPT.replace(
                    "{unit_json}",
                    json.dumps(self._build_unit_for_llm(unit), ensure_ascii=False, indent=2),
                ),
            }
        )

        stateless_extra_instruction = ""

        decision = "unknown"
        lines: List[int] = []
        reason = "max iterations reached"
        iterations = 0
        validated = False

        for idx in range(1, self.max_iterations + 1):
            iterations = idx
            self.logger.info("第%d轮推理", idx)
            if self.stateless_llm_calls:
                parsed = self._chat_with_full_prompt(
                    unit=unit,
                    usage_total=usage_total,
                    extra_instruction=stateless_extra_instruction,
                )
            else:
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
                if decision == "yes" and not lines:
                    self.logger.warning("decision=yes but lines empty for %s", unit_base.get("file_path", "unknown"))
                    if idx < self.max_iterations:
                        if self.stateless_llm_calls:
                            stateless_extra_instruction = YES_LINES_FIX_PROMPT
                        else:
                            messages.append({"role": "user", "content": YES_LINES_FIX_PROMPT})
                        decision = "unknown"
                        continue
                    decision = "unknown"
                    reason = "decision yes without valid lines"
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
                reason = "requested context not found"
                if idx < self.max_iterations:
                    miss_prompt = CONTEXT_MISS_PROMPT.format(
                        errors_json=json.dumps(errors, ensure_ascii=False, indent=2)
                    )
                    if self.stateless_llm_calls:
                        stateless_extra_instruction = miss_prompt
                    else:
                        messages.append(
                            {
                                "role": "user",
                                "content": miss_prompt,
                            }
                        )
                    continue
                decision = "unknown"
                lines = []
                reason = "unable to fetch requested contexts"
                break

            unit_contexts = unit.setdefault("contexts", [])
            if isinstance(unit_contexts, list):
                unit_contexts.extend(extra_contexts)
            else:
                unit["contexts"] = extra_contexts

            if self.stateless_llm_calls:
                # 下一轮会带完整上下文重建提示词，不依赖历史会话。
                stateless_extra_instruction = ""
            else:
                messages.append(
                    {
                        "role": "user",
                        "content": CONTINUE_PROMPT.format(
                            contexts_json=json.dumps(
                                [self._normalize_context_for_llm(c) for c in extra_contexts],
                                ensure_ascii=False,
                                indent=2,
                            )
                        ),
                    }
                )

            # Context is appended as a user message; continue to next iteration for re-judgement.
            reason = str(parsed.get("reason", "insufficient context")).strip()
            continue

        if decision in ("yes", "no") and self.enable_validate:
            if self.stateless_llm_calls:
                parsed_validate = self._chat_with_full_prompt(
                    unit=unit,
                    usage_total=usage_total,
                    extra_instruction=VALIDATE_PROMPT,
                )
            else:
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
                if decision == "yes" and not lines:
                    decision = "unknown"
                    reason = "validated yes without valid lines"
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
