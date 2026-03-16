"""Load and validate YAML config for candidate building."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


def _require_keys(data: Dict[str, Any], keys: List[str], parent: str = "") -> None:
    for key in keys:
        if key not in data:
            prefix = f"{parent}." if parent else ""
            raise ConfigError(f"Missing required config key: {prefix}{key}")


def _resolve_path(root: Path, raw_path: str) -> str:
    if not raw_path:
        return ""
    path = Path(raw_path)
    if path.is_absolute():
        return str(path)
    return str((root / path).resolve())


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load YAML config file and return validated dict.

    Args:
        config_path: Path to YAML config.

    Returns:
        A validated config dictionary with normalized paths.

    Raises:
        ConfigError: If config is missing or invalid.
    """
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    if not isinstance(raw, dict):
        raise ConfigError("Config root must be a mapping/object")

    _require_keys(raw, ["joern", "audit", "rules", "output", "logging"])

    joern = raw["joern"]
    audit = raw["audit"]
    target = audit.get("target", {})
    output = raw["output"]

    if not isinstance(joern, dict):
        raise ConfigError("joern must be an object")
    if not isinstance(audit, dict):
        raise ConfigError("audit must be an object")
    if not isinstance(target, (list, dict)):
        raise ConfigError("audit.target must be a list or object")
    if not isinstance(output, dict):
        raise ConfigError("output must be an object")

    _require_keys(joern, ["server_url"])
    _require_keys(audit, ["target"])
    _require_keys(output, ["candidate_json"])

    root_dir = config_path.parent.parent

    # Normalize output path
    output["candidate_json"] = _resolve_path(root_dir, str(output.get("candidate_json", "")))

    # Normalize and validate audit targets.
    # New schema: audit.target is a list of files/directories.
    # Backward compatibility: also accept old dict schema.
    normalized_targets: List[str] = []

    if isinstance(target, list):
        normalized_targets = [_resolve_path(root_dir, str(item)) for item in target if str(item).strip()]
    elif isinstance(target, dict):
        # Legacy fields compatibility: single_file | multi_file | directory
        single_file = str(target.get("single_file", "")).strip()
        directory = str(target.get("directory", "")).strip()
        multi_file = target.get("multi_file", [])

        if single_file:
            normalized_targets.append(_resolve_path(root_dir, single_file))
        if isinstance(multi_file, list):
            normalized_targets.extend(
                _resolve_path(root_dir, str(item)) for item in multi_file if str(item).strip()
            )
        if directory:
            normalized_targets.append(_resolve_path(root_dir, directory))
    else:
        raise ConfigError("audit.target must be a list or object")

    # Deduplicate while preserving order.
    deduped_targets: List[str] = []
    seen = set()
    for item in normalized_targets:
        if item in seen:
            continue
        seen.add(item)
        deduped_targets.append(item)

    if not deduped_targets:
        raise ConfigError("audit.target cannot be empty")

    missing = [p for p in deduped_targets if not Path(p).exists()]
    if missing:
        raise ConfigError(f"Some audit targets do not exist: {missing}")

    target = deduped_targets
    audit["target"] = target

    # Set defaults for optional joern config
    joern.setdefault("timeout_seconds", 120)

    # Set default project name and logging level
    audit.setdefault("project_name", "code_audit_candidates")
    audit.setdefault("input_mode", "target_list")
    raw["logging"].setdefault("level", "INFO")

    return raw
