#!/usr/bin/env python3
"""Build Joern project and export candidate points to JSON."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.candidate_extractor import CandidateExtractor, CandidateExtractorError
from src.candidate_query_builder import CandidateQueryBuilder
from src.config_loader import ConfigError, load_config
from src.joern_client import JoernClient
from src.project_builder import ProjectBuildError, ProjectBuilder


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Joern candidates JSON from config")
    parser.add_argument(
        "--config",
        default=str(PROJECT_ROOT / "configs" / "config.yaml"),
        help="Path to config.yaml",
    )
    return parser.parse_args()


def _derive_relative_base(input_targets: list[str]) -> Path | None:
    """Derive a common base path from mixed file/directory targets."""
    if not input_targets:
        return None

    target_paths = [Path(p).resolve() for p in input_targets]

    base_candidates = []
    for p in target_paths:
        if p.is_dir():
            base_candidates.append(str(p))
        else:
            base_candidates.append(str(p.parent))

    common = Path(os.path.commonpath(base_candidates))
    return common.resolve()


def _derive_testcases_root(input_targets: list[str]) -> Path | None:
    marker = "/juliet-test-suite-c/testcases/"
    for raw in input_targets:
        full = str(Path(raw).resolve()).replace("\\", "/")
        idx = full.find(marker)
        if idx >= 0:
            return Path(full[: idx + len(marker)].rstrip("/"))
    return None


def _expand_target_files(input_targets: list[str]) -> list[Path]:
    files: list[Path] = []
    seen: set[str] = set()
    for raw in input_targets:
        p = Path(raw).resolve()
        if p.is_file():
            key = str(p)
            if key not in seen:
                seen.add(key)
                files.append(p)
            continue
        if p.is_dir():
            for child in p.rglob("*"):
                if not child.is_file():
                    continue
                rp = child.resolve()
                key = str(rp)
                if key in seen:
                    continue
                seen.add(key)
                files.append(rp)
    return files


def _build_basename_lookup(known_files: list[Path], preferred_root: Path | None) -> dict[str, str]:
    if preferred_root is None:
        return {}
    bucket: dict[str, list[str]] = {}
    for file_path in known_files:
        try:
            rel = file_path.resolve().relative_to(preferred_root.resolve()).as_posix()
        except ValueError:
            continue
        bucket.setdefault(file_path.name, []).append(rel)

    lookup: dict[str, str] = {}
    for basename, rels in bucket.items():
        uniq = sorted(set(rels))
        if len(uniq) == 1:
            lookup[basename] = uniq[0]
    return lookup


def _relativize_path(
    raw_path: str,
    base_path: Path | None,
    preferred_root: Path | None,
    basename_lookup: dict[str, str],
) -> str:
    path_obj = Path(raw_path)
    if path_obj.is_absolute():
        if preferred_root is not None:
            try:
                return path_obj.resolve().relative_to(preferred_root.resolve()).as_posix()
            except ValueError:
                pass
        if base_path is not None:
            try:
                return path_obj.resolve().relative_to(base_path.resolve()).as_posix()
            except ValueError:
                pass
        return path_obj.name

    normalized = raw_path.replace("\\", "/").strip("/")
    marker = "juliet-test-suite-c/testcases/"
    if normalized.startswith(marker):
        normalized = normalized[len(marker) :]
    if "/" in normalized:
        return normalized

    mapped = basename_lookup.get(normalized)
    if mapped:
        return mapped

    return normalized


def _relativize_audit_unit_paths(
    audit_units: list[dict[str, Any]],
    base_path: Path | None,
    preferred_root: Path | None,
    basename_lookup: dict[str, str],
) -> None:
    """Convert audit unit candidate/context file paths to base-relative form where possible."""
    for unit in audit_units:
        candidate = unit.get("candidate", {})
        contexts = unit.get("contexts", [])

        cand_path = str(candidate.get("file_path", "")).strip()
        if cand_path:
            candidate["file_path"] = _relativize_path(
                cand_path,
                base_path=base_path,
                preferred_root=preferred_root,
                basename_lookup=basename_lookup,
            )

        if isinstance(contexts, list):
            for ctx in contexts:
                if not isinstance(ctx, dict):
                    continue
                ctx_path = str(ctx.get("file_path", "")).strip()
                if ctx_path:
                    ctx["file_path"] = _relativize_path(
                        ctx_path,
                        base_path=base_path,
                        preferred_root=preferred_root,
                        basename_lookup=basename_lookup,
                    )


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"[ERROR] Config error: {exc}")
        return 1

    setup_logging(config["logging"]["level"])
    logger = logging.getLogger("build_candidates")

    joern_cfg = config["joern"]
    client = JoernClient(
        server_url=joern_cfg["server_url"],
        timeout_seconds=int(joern_cfg.get("timeout_seconds", 120)),
    )
    logger.info("Using Joern query endpoint: %s", joern_cfg["server_url"])

    try:
        builder = ProjectBuilder(config=config, client=client, project_root=PROJECT_ROOT)
        build_info = builder.build()
    except ProjectBuildError as exc:
        logger.error("Project build failed: %s", exc)
        return 1
    except Exception as exc:  # noqa: BLE001 - keep first version simple
        logger.error("Unexpected project build error: %s", exc)
        return 1

    query_builder = CandidateQueryBuilder(config["rules"])
    queries = query_builder.build_queries()

    if not queries:
        logger.warning("No candidate rule enabled, output will contain empty candidates list")

    extractor = CandidateExtractor(client)
    try:
        audit_units = extractor.extract(queries)
    except CandidateExtractorError as exc:
        logger.error("Candidate query failed: %s", exc)
        return 1

    base_path = _derive_relative_base(input_targets=build_info["input_targets"])
    preferred_root = _derive_testcases_root(input_targets=build_info["input_targets"])
    known_files = _expand_target_files(input_targets=build_info["input_targets"])
    basename_lookup = _build_basename_lookup(known_files=known_files, preferred_root=preferred_root)
    _relativize_audit_unit_paths(
        audit_units,
        base_path=base_path,
        preferred_root=preferred_root,
        basename_lookup=basename_lookup,
    )

    output_path = Path(config["output"]["candidate_json"]).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "task_info": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_mode": config["audit"].get("input_mode", "target_list"),
            "project_name": build_info["project_name"],
        },
        "relative_path_root": (
            str(preferred_root.resolve())
            if preferred_root is not None
            else (str(base_path.resolve()) if base_path is not None else "")
        ),
        "input_targets": build_info["input_targets"],
        "rules": {
            "enable_cwe78": bool(config["rules"].get("enable_cwe78", False)),
            "enable_cwe259": bool(config["rules"].get("enable_cwe259", False)),
        },
        "audit_units": audit_units,
    }

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    logger.info("Candidate JSON written to: %s", output_path)
    logger.info("Total audit_units: %d", len(audit_units))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
