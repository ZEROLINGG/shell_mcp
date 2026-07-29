Shell MCP Core Principles: Use `exec` for one-off, non-blocking commands.
For operations that require maintaining state or multi-turn interactions
(python/node REPL, gdb, ssh, mysql, sudo confirmation, reverse shells, etc.),
use the closed loop: `shell_spawn -> shell_send_line -> shell_output -> shell_close`.
After sending each step, you must use `shell_output` to confirm the state before deciding on the next step. Do not send commands in batches.

If the target program relies on a real terminal (sudo password prompts, colored output/progress bars,
some remote tools that require a tty), or you need to observe a full-screen redraw-based program,
consider spawning with `shell_spawn(pty=true)` (default size 100x40) and prefer `shell_snapshot`
over `shell_output` to observe the current screen (snapshot now also reports the cursor position).
In pty mode you can also actually DRIVE full-screen TUI programs (vim/nano/htop/less/whiptail/
menuconfig, etc.) using `shell_snapshot` + `shell_send_keys` + `shell_cursor_position` /
`shell_move_cursor` + `shell_resize` — see guide://shell/pty and guide://shell/tui for details.

For commands with uncertain completion time (gdb continue/run, ssh login prompts, long-running tasks),
prefer `shell_wait_for(pattern=..., timeout_ms=...)` over repeatedly guessing `idle_ms` with `shell_output`.

⚠️ Security Guidelines (MUST read guide://shell/security first): All operations of this tool will be audited and recorded; any operation that may adversely affect the user's local machine (destructive commands, privilege escalation, persistent changes, etc.) must be explained to the user to gain explicit consent before execution.

For detailed scenarios, please read_resource: guide://shell/basics, guide://shell/pty, guide://shell/tui,
guide://shell/gdb, guide://shell/ssh, guide://shell/sudo, guide://shell/reverse_shell,
guide://shell/security