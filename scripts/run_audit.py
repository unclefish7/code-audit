#!/usr/bin/env python3
"""Run LLM audit workflow on generated audit units."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.audit_runner import AuditRunner
from src.config_loader import ConfigError, load_config
from src.context_fetcher import ContextFetcher
from src.joern_client import JoernClient
from src.llm_client import LLMClient, LLMClientError
from src.result_manager import ResultManager


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        force=True,
    )
    # Hide verbose transport/query logs; keep concise workflow logs only.
    logging.getLogger("src.joern_client").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run LLM audit on audit units JSON")
    parser.add_argument(
        "--config",
        default=str(PROJECT_ROOT / "configs" / "config.yaml"),
        help="Path to config.yaml",
    )
    return parser.parse_args()


def _load_audit_units(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Audit units JSON not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Audit units JSON root must be object")

    units = data.get("audit_units", [])
    if not isinstance(units, list):
        raise ValueError("audit_units must be a list")

    normalized = [u for u in units if isinstance(u, dict)]
    return normalized


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"[ERROR] Config error: {exc}")
        return 1

    setup_logging(config.get("logging", {}).get("level", "INFO"))
    logger = logging.getLogger("run_audit")

    audit_cfg = config.get("audit", {})
    input_json = Path(str(audit_cfg.get("input_audit_units_json", ""))).resolve()
    output_json = Path(str(audit_cfg.get("output_results_json", ""))).resolve()

    try:
        audit_units = _load_audit_units(input_json)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load audit units: %s", exc)
        return 1

    logger.info("Loaded audit units: %d", len(audit_units))

    joern_cfg = config.get("joern", {})
    joern_client = JoernClient(
        server_url=str(joern_cfg.get("server_url", "http://localhost:8080/query-sync")),
        timeout_seconds=int(joern_cfg.get("timeout_seconds", 120)),
    )

    try:
        llm_client = LLMClient(config)
    except LLMClientError as exc:
        logger.error("LLM client init failed: %s", exc)
        return 1

    context_fetcher = ContextFetcher(
        client=joern_client,
        source_paths=audit_cfg.get("target", []),
    )
    runner = AuditRunner(config=config, llm_client=llm_client, context_fetcher=context_fetcher)

    results = runner.run(audit_units=audit_units)

    manager = ResultManager(
        output_path=output_json,
        dedup_enabled=bool(audit_cfg.get("dedup_enabled", True)),
    )
    stats = manager.append_results(model_name=str(config.get("llm", {}).get("model", "")), new_results=results)

    logger.info(
        "Audit done. results=%d kept=%d skipped=%d output=%s",
        len(results),
        stats.get("kept", 0),
        stats.get("skipped", 0),
        output_json,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
