"""QA 编排层共享的运行时控制原语。"""

from .action_protocol import (
    ACTION_AUTHORITY_KEY_ENV,
    ACTION_AUTHORIZATION_TICKET_ENV,
    NO_HUMAN_AUTHORIZATION_SHA256,
    RESOLUTION_POLICY,
    RESOLUTION_POLICY_SHA256,
    ActionJournalPreflight,
    ActionJournalVerification,
    ActionProtocolError,
    build_action_contracts,
    issue_action_authorization_ticket,
    load_action_contracts,
    preflight_action_journal,
    verify_action_journal,
)
from .attempts import AttemptStore
from .budget import (
    BudgetExceeded,
    BudgetReason,
    BudgetSnapshot,
    RunBudget,
    StageBudget,
)
from .cycle_attempt import (
    CYCLE_OUTPUT_NAMES,
    CycleAttemptError,
    CycleAttemptResult,
    commit_cycle_attempt,
)
from .process import ProcessExecutor
from .session import (
    AGENT_OWNER_PREFIX,
    CYCLE_OWNER_PREFIX,
    RunSession,
)
from .state_coordinator import RunStateCoordinator

__all__ = [
    "AGENT_OWNER_PREFIX",
    "ACTION_AUTHORITY_KEY_ENV",
    "ACTION_AUTHORIZATION_TICKET_ENV",
    "NO_HUMAN_AUTHORIZATION_SHA256",
    "ActionJournalPreflight",
    "ActionJournalVerification",
    "ActionProtocolError",
    "AttemptStore",
    "BudgetExceeded",
    "BudgetReason",
    "BudgetSnapshot",
    "CYCLE_OWNER_PREFIX",
    "CYCLE_OUTPUT_NAMES",
    "CycleAttemptError",
    "CycleAttemptResult",
    "ProcessExecutor",
    "RESOLUTION_POLICY",
    "RESOLUTION_POLICY_SHA256",
    "RunBudget",
    "RunSession",
    "RunStateCoordinator",
    "StageBudget",
    "build_action_contracts",
    "commit_cycle_attempt",
    "load_action_contracts",
    "issue_action_authorization_ticket",
    "preflight_action_journal",
    "verify_action_journal",
]
