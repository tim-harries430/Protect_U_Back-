from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adapter_wall import ActionDomain, ActionEnvelope, AdapterActionType
from claude_code_hooks import _bash_targets_and_effects
from harness_adapter import infer_action_domain, infer_action_type, infer_declared_scope
from llm_channel import ChannelType
from ot_gate import DeclaredScope, SideEffect
from parallel_audit import EvidenceDisposition
from phi_registry import ActorType, PhiRegistry
from protect_scan import confirm_protect_scan, default_protect_scan_profile
from xray_review import audit_with_xray_review


SOURCE_ADAPTER = "codex_shell_guard"
DEFAULT_ACTOR_ID = "codex_cli"
LOG_FILE_NAME = "pub_codex_guard.jsonl"
BLOCKING_DISPOSITIONS = frozenset(
    {
        EvidenceDisposition.HOLD,
        EvidenceDisposition.KILL,
        EvidenceDisposition.QUARANTINE,
        EvidenceDisposition.REJECT,
    }
)

# Codex's own shell-snapshot bootstrap (and many ordinary commands) use shell
# plumbing that the shared bash heuristic in claude_code_hooks mis-reads as
# filesystem targets:
#   * `2>/dev/null`   -> phantom WRITE to target "/dev/null"
#   * `<(compgen -e)` -> phantom READ of target "(compgen"
# Those phantom paths trip CAPABILITY_PATH_DENIED and KILL a benign command.
# We neutralise the plumbing here, inside the Codex adapter, so the shared
# parser stays untouched. We do NOT go blind: a process substitution's inner
# command is re-analysed on its own, so `<(curl http://evil)` keeps its NETWORK
# effect and genuine targets are preserved.
_BENIGN_REDIRECT_SINKS = (
    "null",
    "zero",
    "full",
    "random",
    "urandom",
    "stdout",
    "stderr",
    "tty",
)
_BENIGN_SINK_REDIRECT_RE = re.compile(
    r"(?:&|[0-9]+)?[<>]{1,2}&?\s*/dev/(?:" + "|".join(_BENIGN_REDIRECT_SINKS) + r")\b"
)
_PROCESS_SUBSTITUTION_RE = re.compile(r"[<>]\(([^()]*)\)")


def _is_phantom_target(target: str) -> bool:
    if target.startswith("("):
        return True
    if target.startswith("/dev/") and target.rsplit("/", 1)[-1] in _BENIGN_REDIRECT_SINKS:
        return True
    return False


def _codex_shell_targets_and_effects(
    command_text: str,
) -> tuple[tuple[str, ...], set[SideEffect]]:
    """Extract targets/effects for a Codex shell command.

    Wraps the shared ``_bash_targets_and_effects`` but neutralises shell
    plumbing first so benign redirects and process substitutions do not become
    phantom filesystem targets. The inner command of each process substitution
    is analysed separately so its real effects (e.g. network) are not lost.
    """
    inner_commands = _PROCESS_SUBSTITUTION_RE.findall(command_text)
    cleaned = _PROCESS_SUBSTITUTION_RE.sub(" ", command_text)
    cleaned = _BENIGN_SINK_REDIRECT_RE.sub(" ", cleaned)

    targets, effects = _bash_targets_and_effects(cleaned)
    targets = list(targets)
    effects = set(effects)

    for inner in inner_commands:
        inner = inner.strip()
        if not inner:
            continue
        inner_targets, inner_effects = _bash_targets_and_effects(inner)
        targets.extend(inner_targets)
        effects |= inner_effects

    deduped = tuple(
        dict.fromkeys(target for target in targets if not _is_phantom_target(target))
    )
    return deduped, effects


@dataclass(frozen=True)
class CodexGuardDecision:
    action: ActionEnvelope
    disposition: EvidenceDisposition
    reason_code: str
    executed: bool = False
    exit_code: int | None = None

    @property
    def blocked(self) -> bool:
        return self.disposition in BLOCKING_DISPOSITIONS

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_adapter": SOURCE_ADAPTER,
            "action_id": self.action.action_id,
            "actor_id": self.action.actor_id,
            "command_text": self.action.command_text,
            "cwd": self.action.cwd,
            "target_paths": tuple(self.action.target_paths),
            "expected_side_effects": tuple(
                sorted(effect.value for effect in self.action.expected_side_effects)
            ),
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "blocked": self.blocked,
            "executed": self.executed,
            "exit_code": self.exit_code,
            "can_execute": False,
            "can_grant_permission": False,
        }


def action_from_shell_argv(
    argv: Sequence[str],
    *,
    cwd: str,
    environ: Mapping[str, str] | None = None,
) -> ActionEnvelope:
    env = environ or os.environ
    command_text = _command_text_from_shell_argv(argv)
    target_paths, effects = _codex_shell_targets_and_effects(command_text)
    action_type = infer_action_type(
        "shell",
        tool_name="shell",
        effects=set(effects),
        command_text=command_text,
    )
    declared_scope = infer_declared_scope(
        None,
        effects=set(effects),
        action_type=action_type,
    )
    action_domain = infer_action_domain(
        None,
        declared_scope=declared_scope,
        effects=set(effects),
        command_text=command_text,
        target_paths=target_paths,
        action_type=action_type,
        default=ActionDomain.GENERAL,
    )
    cid = _correlation_id(env)
    raw_payload = {
        "codex_guard": {
            "schema_version": "pub_codex_shell_guard:v0",
            "shell_argv": tuple(str(item) for item in argv),
            "cwd": cwd,
            "sandbox": _sandbox_evidence_from_env(env),
            "approval": _approval_evidence_from_env(env),
            "policy": _policy_evidence_from_env(env),
        }
    }
    return ActionEnvelope(
        actor_id=env.get("PUB_CODEX_ACTOR_ID", DEFAULT_ACTOR_ID),
        action_type=action_type,
        action_domain=action_domain,
        channel_type=ChannelType.AGENT_PROPOSAL,
        command_text=command_text,
        cwd=cwd,
        target_paths=target_paths,
        expected_side_effects=set(effects),
        declared_scope=declared_scope,
        source_adapter=SOURCE_ADAPTER,
        tool_name="shell",
        raw_payload=raw_payload,
        branch_id=env.get("PUB_CODEX_SESSION_ID", "codex_cli_session"),
        action_id=f"codex_cli:{cid}",
        parent_event_id=env.get("PUB_CODEX_SESSION_ID", "codex_cli_parent"),
        user_request_id=env.get("PUB_CODEX_USER_REQUEST_ID", "codex_cli_user_request"),
    )


def audit_shell_argv(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> CodexGuardDecision:
    env = environ or os.environ
    actual_cwd = cwd or os.getcwd()
    action = action_from_shell_argv(argv, cwd=actual_cwd, environ=env)
    registry = PhiRegistry()
    registry.register_actor(action.actor_id, ActorType.AGENT)
    project_root = _project_root_for_action(action, env)
    profile = confirm_protect_scan(default_protect_scan_profile(project_root), confirmed=True)
    decision = audit_with_xray_review(
        action,
        registry=registry,
        project_root=project_root,
        protect_profile=profile,
    )
    return CodexGuardDecision(
        action=action,
        disposition=decision.disposition,
        reason_code=decision.reason_code,
    )


def run_guarded_shell(
    argv: Sequence[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> int:
    env = dict(environ or os.environ)
    decision = audit_shell_argv(argv, cwd=os.getcwd(), environ=env)
    _append_log(env, {"phase": "pre", **decision.to_dict()})
    if decision.blocked:
        print(
            f"PUB_CODEX_GUARD: blocked before Codex shell execution: "
            f"{decision.disposition.value} {decision.reason_code}",
            file=sys.stderr,
        )
        return 126

    invoked_shell = Path(env.get("PUB_CODEX_INVOKED_SHELL", "")).name.lower()
    real_shell = (
        env.get("PUB_CODEX_REAL_SH")
        if invoked_shell == "sh"
        else env.get("PUB_CODEX_REAL_SHELL") or env.get("PUB_CODEX_REAL_BASH")
    )
    if not real_shell:
        print("PUB_CODEX_GUARD: missing PUB_CODEX_REAL_SHELL", file=sys.stderr)
        return 127

    completed = subprocess.run([real_shell, *argv], env=env, check=False)
    _append_log(
        env,
        {
            "phase": "post",
            **CodexGuardDecision(
                action=decision.action,
                disposition=decision.disposition,
                reason_code=decision.reason_code,
                executed=True,
                exit_code=completed.returncode,
            ).to_dict(),
        },
    )
    return completed.returncode


def _command_text_from_shell_argv(argv: Sequence[str]) -> str:
    args = tuple(str(item) for item in argv)
    if len(args) >= 2 and args[0] in {"-c", "-lc", "-l", "-ic"}:
        return args[1] if args[0] in {"-c", "-lc", "-ic"} else " ".join(args)
    if len(args) >= 3 and args[0] == "-l" and args[1] == "-c":
        return args[2]
    return " ".join(args)


def _project_root_for_action(action: ActionEnvelope, env: Mapping[str, str]) -> str:
    return str(env.get("PUB_CODEX_PROJECT_ROOT") or action.cwd)


def _correlation_id(env: Mapping[str, str]) -> str:
    seed = env.get("PUB_CODEX_TOOL_USE_ID") or env.get("PUB_CODEX_SESSION_ID")
    if seed:
        return _safe_id(seed)
    return str(time.time_ns())


def _safe_id(value: str) -> str:
    return "".join(character if character.isalnum() or character in "-_." else "_" for character in value)[:96]


def _sandbox_evidence_from_env(env: Mapping[str, str]) -> dict[str, Any]:
    return {
        "available": _bool_env(env.get("PUB_CODEX_SANDBOX_AVAILABLE"), default=False),
        "mode": env.get("PUB_CODEX_SANDBOX_MODE", ""),
        "fallback": env.get("PUB_CODEX_SANDBOX_FALLBACK", "codex_shell_guard"),
    }


def _approval_evidence_from_env(env: Mapping[str, str]) -> dict[str, Any]:
    return {
        "policy": env.get("PUB_CODEX_APPROVAL_POLICY", ""),
        "source": "codex_exec_policy_observed",
    }


def _policy_evidence_from_env(env: Mapping[str, str]) -> dict[str, Any]:
    return {
        "exec_policy": env.get("PUB_CODEX_EXEC_POLICY", ""),
        "prefix_approval": env.get("PUB_CODEX_PREFIX_APPROVAL", ""),
    }


def _bool_env(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _append_log(env: Mapping[str, str], row: Mapping[str, Any]) -> None:
    root = Path(env.get("PUB_CODEX_LOG_DIR") or (Path.cwd() / ".pub_codex_guard"))
    root.mkdir(parents=True, exist_ok=True)
    payload = {"ts": time.time(), **dict(row)}
    with (root / LOG_FILE_NAME).open("a", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    return run_guarded_shell(tuple(argv or ()))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
