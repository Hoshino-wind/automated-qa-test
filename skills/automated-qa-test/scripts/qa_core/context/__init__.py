"""版本化、只读且不得充当运行证据的 Agent 上下文编译器。"""

from .compiler import (
    ContextCompileError,
    ContextSnapshot,
    compile_context_snapshot,
)
from .verifier import ContextVerificationResult, verify_context_snapshot

__all__ = [
    "ContextCompileError",
    "ContextSnapshot",
    "ContextVerificationResult",
    "compile_context_snapshot",
    "verify_context_snapshot",
]
