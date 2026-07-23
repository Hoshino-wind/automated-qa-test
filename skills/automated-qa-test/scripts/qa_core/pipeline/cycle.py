"""周期运行所需的路径、摘要和当前产物状态。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from qa_core.contracts import ArtifactPaths
from qa_core.contracts.artifacts import ARTIFACT_FILENAMES


@dataclass(slots=True)
class CycleContext:
    script_dir: Path
    artifacts: ArtifactPaths
    skip_report: bool = False
    current_artifacts: set[Path] = field(default_factory=set)
    summary: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        script_dir: Path,
        run_dir: Path,
        overrides: Mapping[str, str | None],
        skip_report: bool,
    ) -> "CycleContext":
        artifacts = ArtifactPaths.from_overrides(run_dir, overrides)
        summary = {
            "schema_version": 1,
            "status": "running",
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "run_dir": str(artifacts.run_dir),
            "paths": artifacts.summary_paths(skip_report=skip_report),
            "steps": [],
        }
        return cls(
            script_dir=script_dir.resolve(),
            artifacts=artifacts,
            skip_report=skip_report,
            summary=summary,
        )

    @classmethod
    def from_namespace(cls, *, script_dir: Path, args: Any) -> "CycleContext":
        overrides = {name: getattr(args, name, None) for name in ARTIFACT_FILENAMES}
        return cls.create(
            script_dir=script_dir,
            run_dir=Path(args.run_dir),
            overrides=overrides,
            skip_report=bool(args.skip_report),
        )

    def mark_current(self, path: Path) -> None:
        self.current_artifacts.add(path.resolve())
