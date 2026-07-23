"""Uniform execution and journaling boundary for cycle stages."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

CommandResult = dict[str, Any]
CommandExecutor = Callable[[list[str], Path | None], CommandResult]


@dataclass(slots=True)
class StageRunner:
    summary: dict[str, Any]
    executor: CommandExecutor

    def record(self, name: str, result: CommandResult) -> CommandResult:
        self.summary.setdefault("steps", []).append({"name": name, **result})
        return result

    def run(self, name: str, command: list[str], *, cwd: Path | None = None) -> CommandResult:
        return self.record(name, self.executor(command, cwd))

    def skip(self, name: str, reason: str) -> CommandResult:
        return self.record(name, {"skipped": True, "exit_code": 0, "reason": reason})
