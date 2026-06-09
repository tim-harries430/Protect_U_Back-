# Kimi CLI Shell Entrypoint Summary

Source snapshot:

- Repository snapshot: `C:\dev\sp\vendor\kimi-cli-main`
- Version: `kimi-cli 1.45.0`
- Shell tool file: `C:\dev\sp\vendor\kimi-cli-main\src\kimi_cli\tools\shell\__init__.py`
- Shell tool SHA256: `95E6BC59F344C1DEE4E8D19D19DE7D373A330F01E20D214D845CF30B7C8B88F7`

Observed shell execution paths:

- Foreground shell: `Shell.__call__` preprocesses the command, asks approval, then calls `_run_shell_command`.
- Foreground process boundary: `_run_shell_command` calls `kaos.exec(*self._shell_args(command), env=env)`.
- Final foreground argv shape: `_shell_args(command)` returns `(shell_path, "-c", command)`.
- Background shell: `_run_in_background` preprocesses and approves the command, then calls `runtime.background_tasks.create_bash_task(...)`.
- Background task spec: `background.manager.create_bash_task(...)` stores `(shell_path, command, cwd, timeout_s)` and launches a worker.
- Background process boundary: `background.worker` calls `asyncio.create_subprocess_exec(spec.shell_path, "-c", spec.command, ...)`.

Recommended Protect_U_Back attachment points:

- Foreground: add a preflight gate immediately before `kaos.exec(...)`.
- Background: add a preflight gate immediately before `create_bash_task(...)`, before task spec persistence and worker launch.
- Do not protect network/browser/other tools from this connector.
- Do not treat this as an OS sandbox; this is a pre-I/O shell execution gate.

Policy mapping:

- PASS: allow the original Kimi execution path to continue.
- HOLD/KILL: return a tool error before process creation.
- Evidence claim `io_executed=false` means the target shell command did not reach `kaos.exec`, `create_bash_task`, or the background worker subprocess boundary.
