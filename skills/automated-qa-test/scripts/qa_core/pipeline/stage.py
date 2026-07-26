"""Uniform execution and journaling boundary for cycle stages."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

CommandResult = dict[str, Any]
CommandExecutor = Callable[[list[str], Path | None], CommandResult]
StageCommandExecutor = Callable[
    [str, list[str], Path | None, int],
    CommandResult,
]


@dataclass(slots=True)
class StageRunner:
    summary: dict[str, Any]
    executor: CommandExecutor
    stage_executor: StageCommandExecutor | None = None

    def record(self, name: str, result: CommandResult) -> CommandResult:
        self.summary.setdefault("steps", []).append({"name": name, **result})
        return result

    def run(
        self,
        name: str,
        command: list[str],
        *,
        cwd: Path | None = None,
        probe_count: int = 0,
    ) -> CommandResult:
        if self.stage_executor is None:
            result = self.executor(command, cwd)
        else:
            result = self.stage_executor(
                name,
                command,
                cwd,
                probe_count,
            )
        result.setdefault("probe_count", probe_count)
        return self.record(name, result)

    def skip(self, name: str, reason: str) -> CommandResult:
        return self.record(name, {"skipped": True, "exit_code": 0, "reason": reason})
