# shell_mcp

MCP (Model Context Protocol) server that provides shell command execution capabilities to AI agents and LLMs.

## Features

- **Single-shot execution** — `exec` tool runs a command with configurable shell interpreter and timeout
- **Interactive sessions** — Full lifecycle management (`shell_spawn`, `shell_send`, `shell_send_line`, `shell_output`, `shell_reset`, `shell_close`, `shell_close_all`)
- **Prompt templates** — Guided workflows for GDB debugging, SSH connections, and reverse shell listeners
- **Resource documentation** — Security guidelines, usage basics, and scenario-specific recipes via `guide://shell/*`
- **Audit logging** — Every command is recorded as structured JSON (trace ID, timing, shell, input) to daily rolling log files
- **Shell blacklist** — Blocks direct invocation of interactive programs (gdb, ssh, mysql, etc.) as interpreters; guides users toward the correct spawn-bash-then-send pattern

## Architecture

```
MCP Client (AI Agent / LLM)
        │
        │ JSON-RPC over stdin/stdout
        ▼
┌─────────────────────────────────┐
│  rmcp Server (ShellMcpService)  │
│  ┌───────────────────────────┐  │
│  │ @tool  » exec              │  │
│  │ @tool  » shell_spawn       │  │
│  │ @tool  » shell_send        │  │
│  │ @tool  » shell_send_line   │  │
│  │ @tool  » shell_output      │  │
│  │ @tool  » shell_reset       │  │
│  │ @tool  » shell_close       │  │
│  │ @tool  » shell_close_all   │  │
│  ├───────────────────────────┤  │
│  │ @prompt » gdb/ssh/reverse  │  │
│  ├───────────────────────────┤  │
│  │ Resources » guide://shell/*│  │
│  └───────────────────────────┘  │
│  ┌───────────────────────────┐  │
│  │ Session Store              │  │
│  │ DashMap<tag, Shell>        │  │
│  └───────────────────────────┘  │
│  ┌───────────────────────────┐  │
│  │ audit::with_audit()        │  │
│  │  → JSON logs per command   │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
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
    "shell_mcp": {
      "command": "/path/to/shell_mcp/target/release/shell_mcp"
    }
  }
}
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `warn,audit=info` | Log level filter |

## Tools

| Tool | Description |
|---|---|
| `exec` | Run a one-off command with optional timeout. Params: `input`, `shell` (default: bash), `timeout_ms` |
| `shell_spawn` | Create an interactive shell session. Params: `shell`, `tag` |
| `shell_send` | Send raw bytes (no trailing newline, e.g. Ctrl+C). Params: `input`, `tag` |
| `shell_send_line` | Send a command with trailing newline. Params: `input`, `tag` |
| `shell_output` | Read buffered stdout/stderr. Params: `idle_ms`, `tag` |
| `shell_list` | List all active session tags |
| `shell_exists` | Check if a session tag exists |
| `shell_reset` | Kill and restart a session. Params: `tag` |
| `shell_close` | Close and remove a single session. Params: `tag` |
| `shell_close_all` | Close all sessions |

## Prompts

| Prompt | Parameters | Description |
|---|---|---|
| `shell_usage_guide` | — | General usage overview |
| `gdb_debug_session` | `binary_path`, `tag?` | Step-by-step GDB/pwndbg workflow |
| `ssh_connect_session` | `host`, `user`, `tag?` | SSH connection workflow |
| `reverse_shell_session` | `attacker_ip`, `port?`, `tag?` | CTF reverse shell listener setup |

## Resources

| URI | Content |
|---|---|
| `guide://shell/security` | Security guidelines (highest priority) |
| `guide://shell/basics` | Session lifecycle and best practices |
| `guide://shell/gdb` | GDB/pwndbg debugging workflow |
| `guide://shell/ssh` | SSH remote connection workflow |
| `guide://shell/sudo` | sudo password confirmation handling |
| `guide://shell/reverse_shell` | Reverse shell listener workflow |

## Audit Logs

All tool calls are logged as structured JSON to `logs/shell_audit.log` (daily rolling) with:

- `trace_id` — UUID v4 per invocation
- `action` — tool name
- `shell`, `tag`, `input` — command context
- `begin` / `end` events with duration and success/failure status

## License

[MIT](LICENSE)