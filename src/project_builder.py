"""Build Joern project from configured audit targets."""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Set

from .joern_client import JoernClient, JoernClientError


class ProjectBuildError(Exception):
    """Raised when project input preparation or import fails."""


class ProjectBuilder:
    """Prepare input path for Joern import and trigger import."""

    def __init__(self, config: Dict[str, Any], client: JoernClient, project_root: Path):
        self.config = config
        self.client = client
        self.project_root = project_root
        self.logger = logging.getLogger(__name__)

    def _prepare_input_targets(self) -> List[str]:
        targets = self.config["audit"].get("target", [])
        if not isinstance(targets, list) or not targets:
            raise ProjectBuildError("audit.target must be a non-empty list")
        return [str(Path(item).resolve()) for item in targets]

    def _collect_source_files(self, input_targets: List[str]) -> List[Path]:
        """Collect all files from mixed targets, recursively for directories."""
        files: List[Path] = []
        seen: Set[str] = set()

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
                    key = str(child.resolve())
                    if key in seen:
                        continue
                    seen.add(key)
                    files.append(child.resolve())
                continue

        if not files:
            raise ProjectBuildError("No source files found from audit.target")

        return files

    def _build_staging_dir(self, files: List[Path]) -> Path:
        """Copy all collected files into a temporary staging directory."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        staging_dir = self.project_root / "workspace" / f"target_stage_{timestamp}"
        staging_dir.mkdir(parents=True, exist_ok=True)

        common_parent = Path(os.path.commonpath([str(f.parent) for f in files]))
        used_paths: Set[str] = set()

        for src in files:
            try:
                rel = src.relative_to(common_parent)
            except ValueError:
                rel = Path(src.name)

            dst = (staging_dir / rel).resolve()
            dst_key = str(dst)
            if dst_key in used_paths:
                stem, suffix = dst.stem, dst.suffix
                idx = 1
                while True:
                    alt = dst.with_name(f"{stem}_{idx}{suffix}")
                    if str(alt) not in used_paths:
                        dst = alt
                        dst_key = str(dst)
                        break
                    idx += 1

            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            used_paths.add(dst_key)

        self.logger.info("Prepared staging directory: %s (%d files)", staging_dir, len(files))
        return staging_dir

    def build(self) -> Dict[str, Any]:
        """Prepare target input and import into Joern.

        Returns:
            Metadata including effective input path and original input targets.
        """
        input_targets = self._prepare_input_targets()
        project_name = self.config["audit"].get("project_name", "code_audit_candidates")

        files = self._collect_source_files(input_targets)
        staging_dir = self._build_staging_dir(files)

        self.logger.info("Start Joern import. project=%s input_path=%s", project_name, staging_dir)
        try:
            import_result = self.client.import_code(str(staging_dir))
        except JoernClientError as exc:
            raise ProjectBuildError(f"Import failed for path: {staging_dir}. reason: {exc}") from exc

        self.logger.info("Joern project import done. project=%s", project_name)
        return {
            "project_name": project_name,
            "input_targets": input_targets,
            "import_result": {
                "input_path": str(staging_dir),
                "collected_file_count": len(files),
                "result": import_result,
            },
        }
