from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence


BACKUP_SUFFIX = ".protect_u_back.bak"
# Match ALL tools, not an allowlist. An 8-tool allowlist silently leaves every
# tool outside it -- WebFetch, WebSearch, Task subagents, NotebookEdit, and all
# mcp__* tools -- never routed through the hook: a default-allow front door on a
# default-deny gate. "*" fires the hook for every tool; the hook then decides
# per tool (recognized tools are classified, unknown ones are held for review).
TOOL_MATCHER = "*"
PRETOOL_SCRIPT = "pretool_admission.py"
POSTTOOL_SCRIPT = "posttool_autopsy.py"
MANAGED_SCRIPTS = (PRETOOL_SCRIPT, POSTTOOL_SCRIPT)


class ClaudeCodeConnectorError(RuntimeError):
    pass


def status_claude_code(
    claude_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
) -> dict[str, Any]:
    project_root = find_claude_project(claude_project)
    settings_path = _settings_path(project_root)
    settings = _read_settings(settings_path)
    commands = _managed_commands(protect_root=protect_root, python_bin=python_bin)
    pretool_hook = _has_hook_command(settings, "PreToolUse", commands["PreToolUse"])
    posttool_hook = _has_hook_command(settings, "PostToolUse", commands["PostToolUse"])
    return {
        "claude_project": str(project_root),
        "settings_path": str(settings_path),
        "settings_exists": settings_path.exists(),
        "connected": pretool_hook and posttool_hook,
        "pretool_hook": pretool_hook,
        "posttool_hook": posttool_hook,
        "managed_hook_count": _managed_hook_count(settings),
        "matcher": TOOL_MATCHER,
        "pretool_command": commands["PreToolUse"],
        "posttool_command": commands["PostToolUse"],
        "backup_path": str(_backup_path(settings_path)),
        "sha256": _sha256(settings_path) if settings_path.exists() else None,
    }


def connect_claude_code(
    claude_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
) -> dict[str, Any]:
    project_root = find_claude_project(claude_project)
    settings_path = _settings_path(project_root)
    settings = _read_settings(settings_path)
    original = _canonical(settings)

    commands = _managed_commands(protect_root=protect_root, python_bin=python_bin)
    _remove_managed_hooks(settings)
    _append_hook_command(settings, "PreToolUse", commands["PreToolUse"])
    _append_hook_command(settings, "PostToolUse", commands["PostToolUse"])

    changed = _canonical(settings) != original
    if changed:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        if settings_path.exists():
            _backup_once(settings_path)
        _write_settings(settings_path, settings)

    result = status_claude_code(
        project_root,
        protect_root=protect_root,
        python_bin=python_bin,
    )
    result["changed"] = changed
    result["protect_root"] = _protect_root_literal(protect_root)
    result["python_bin"] = python_bin
    return result


def disconnect_claude_code(claude_project: str | Path | None = None) -> dict[str, Any]:
    project_root = find_claude_project(claude_project)
    settings_path = _settings_path(project_root)
    settings = _read_settings(settings_path)
    original = _canonical(settings)
    removed = _remove_managed_hooks(settings)
    changed = _canonical(settings) != original
    if changed:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        if settings_path.exists():
            _backup_once(settings_path)
        _write_settings(settings_path, settings)

    result = status_claude_code(project_root)
    result["changed"] = changed
    result["removed_hook_count"] = removed
    return result


def verify_claude_code(
    claude_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
) -> dict[str, Any]:
    status = status_claude_code(
        claude_project,
        protect_root=protect_root,
        python_bin=python_bin,
    )
    project_root = Path(status["claude_project"])

    from claude_code_hooks import run_pretool_admission

    payload = {
        "session_id": "pub_claude_code_connector_verify",
        "transcript_path": str(project_root / ".claude" / "pub_verify_transcript.jsonl"),
        "cwd": str(project_root),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf .", "description": "synthetic destructive probe"},
        "tool_use_id": "pub_claude_code_connector_verify",
    }
    verify_dir = project_root / ".claude" / "pub_verify_state"
    result = run_pretool_admission(
        json.dumps(payload),
        environ={
            "CLAUDE_PROJECT_DIR": str(project_root),
            "PUB_CLAUDE_HOOK_STATE_DIR": str(verify_dir),
            "PUB_CLAUDE_HOOK_LOG_DIR": str(verify_dir),
        },
    )
    hook_output = result.output.get("hookSpecificOutput") if result.output else None
    return {
        **status,
        "preflight_blocked": bool(
            isinstance(hook_output, dict) and hook_output.get("permissionDecision") == "deny"
        ),
        "disposition": result.disposition.value,
        "reason_code": result.reason_code,
        "io_executed": False,
        "can_execute": False,
        "can_grant_permission": False,
    }


def find_claude_project(claude_project: str | Path | None = None) -> Path:
    candidate = Path(claude_project or Path.cwd()).expanduser().resolve(strict=False)
    if candidate.name == "settings.local.json" and candidate.parent.name == ".claude":
        return candidate.parent.parent
    if candidate.name == ".claude":
        return candidate.parent
    return candidate


def _settings_path(project_root: Path) -> Path:
    return project_root / ".claude" / "settings.local.json"


def _read_settings(settings_path: Path) -> dict[str, Any]:
    if not settings_path.exists():
        return {}
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise ClaudeCodeConnectorError(f"invalid Claude Code settings JSON: {settings_path}") from exc
    if not isinstance(data, dict):
        raise ClaudeCodeConnectorError("Claude Code settings root must be a JSON object.")
    return data


def _write_settings(settings_path: Path, settings: dict[str, Any]) -> None:
    settings_path.write_text(
        json.dumps(settings, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="",
    )


def _append_hook_command(settings: dict[str, Any], event_name: str, command: str) -> None:
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ClaudeCodeConnectorError("Claude Code settings hooks field must be a JSON object.")
    entries = hooks.setdefault(event_name, [])
    if not isinstance(entries, list):
        raise ClaudeCodeConnectorError(f"Claude Code hooks.{event_name} must be a JSON array.")
    entries.append(
        {
            "matcher": TOOL_MATCHER,
            "hooks": [{"type": "command", "command": command}],
        }
    )


def _remove_managed_hooks(settings: dict[str, Any]) -> int:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return 0

    removed = 0
    for event_name in ("PreToolUse", "PostToolUse"):
        entries = hooks.get(event_name)
        if not isinstance(entries, list):
            continue
        kept_entries = []
        for entry in entries:
            if not isinstance(entry, dict):
                kept_entries.append(entry)
                continue
            hook_items = entry.get("hooks")
            if not isinstance(hook_items, list):
                if _entry_mentions_managed_script(entry):
                    removed += 1
                else:
                    kept_entries.append(entry)
                continue
            kept_hooks = []
            for hook in hook_items:
                if _is_managed_hook(hook):
                    removed += 1
                else:
                    kept_hooks.append(hook)
            if kept_hooks:
                kept_entry = dict(entry)
                kept_entry["hooks"] = kept_hooks
                kept_entries.append(kept_entry)
        if kept_entries:
            hooks[event_name] = kept_entries
        else:
            hooks.pop(event_name, None)
    if not hooks:
        settings.pop("hooks", None)
    return removed


def _has_hook_command(settings: dict[str, Any], event_name: str, command: str) -> bool:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False
    entries = hooks.get(event_name)
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("matcher") != TOOL_MATCHER:
            continue
        hook_items = entry.get("hooks")
        if not isinstance(hook_items, list):
            continue
        for hook in hook_items:
            if isinstance(hook, dict) and hook.get("type") == "command" and hook.get("command") == command:
                return True
    return False


def _managed_hook_count(settings: dict[str, Any]) -> int:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return 0
    count = 0
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("hooks"), list):
                count += sum(1 for hook in entry["hooks"] if _is_managed_hook(hook))
    return count


def _is_managed_hook(hook: Any) -> bool:
    if not isinstance(hook, dict) or hook.get("type") != "command":
        return False
    command = hook.get("command")
    return isinstance(command, str) and any(script in command for script in MANAGED_SCRIPTS)


def _entry_mentions_managed_script(entry: dict[str, Any]) -> bool:
    return any(script in json.dumps(entry, sort_keys=True) for script in MANAGED_SCRIPTS)


def _managed_commands(*, protect_root: str | Path | None, python_bin: str) -> dict[str, str]:
    return {
        "PreToolUse": _hook_command(
            python_bin=python_bin,
            protect_root=protect_root,
            script_name=PRETOOL_SCRIPT,
        ),
        "PostToolUse": _hook_command(
            python_bin=python_bin,
            protect_root=protect_root,
            script_name=POSTTOOL_SCRIPT,
        ),
    }


def _hook_command(*, python_bin: str, protect_root: str | Path | None, script_name: str) -> str:
    return f"{python_bin} {_quote_if_needed(_script_path(_protect_root_literal(protect_root), script_name))}"


def _protect_root_literal(protect_root: str | Path | None) -> str:
    if protect_root is None:
        return str(Path(__file__).resolve(strict=False).parent)
    return str(protect_root).strip().strip('"').strip("'")


def _script_path(root: str, script_name: str) -> str:
    root = root.rstrip("/\\")
    separator = "\\" if "\\" in root and "/" not in root else "/"
    return f"{root}{separator}{script_name}"


def _quote_if_needed(value: str) -> str:
    if not any(character.isspace() for character in value):
        return value
    return '"' + value.replace('"', '\\"') + '"'


def _canonical(settings: dict[str, Any]) -> str:
    return json.dumps(settings, sort_keys=True, separators=(",", ":"))


def _backup_path(path: Path) -> Path:
    return path.with_name(path.name + BACKUP_SUFFIX)


def _backup_once(path: Path) -> None:
    backup = _backup_path(path)
    if not backup.exists():
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8", newline="")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Connect Protect U Back to Claude Code hooks.")
    parser.add_argument("command", choices=("status", "connect", "disconnect", "verify"))
    parser.add_argument("--claude-project", default=".")
    parser.add_argument("--protect-root")
    parser.add_argument("--python-bin", default="python3")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    operations = {
        "status": lambda: status_claude_code(
            args.claude_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
        ),
        "connect": lambda: connect_claude_code(
            args.claude_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
        ),
        "disconnect": lambda: disconnect_claude_code(args.claude_project),
        "verify": lambda: verify_claude_code(
            args.claude_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
        ),
    }
    try:
        result = operations[args.command]()
    except Exception as exc:
        print(f"Claude Code connector error: {exc}")
        return 1
    _print_result(result, as_json=args.json)
    return 0


def _print_result(result: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    for key, value in result.items():
        if isinstance(value, dict):
            print(f"{key}:")
            for child_key, child_value in value.items():
                print(f"  {child_key}: {child_value}")
        else:
            print(f"{key}: {value}")


if __name__ == "__main__":
    raise SystemExit(main())
