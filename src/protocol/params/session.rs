// src/protocol/params/session.rs
use rmcp::schemars;
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SpawnParams {
    /// Interpreter: can be a common shell/interpreter name (bash/sh/zsh/cmd/powershell/python/node),
    /// or an absolute/relative path to an executable to specify a particular version
    /// (e.g., "/usr/local/bin/python3.11", "C:\\nvm\\v20\\node.exe").
    ///
    /// ⚠️ Interactive programs like debuggers (gdb/lldb/windbg), database clients (mysql/psql/redis-cli),
    /// ssh/telnet/nc, etc., are NOT "interpreters" and should NOT be passed here —
    /// you should first start a session using shell_spawn(shell="bash"),
    /// and then use shell_send_line to send them as normal commands.
    /// See resources: guide://shell/gdb, guide://shell/ssh
    pub shell: String,
    /// Unique session identifier
    pub tag: String,
    /// Whether to spawn in PTY (pseudo-terminal) mode, default false (pipe mode).
    /// Enable this for programs that rely on real terminal semantics (some sudo prompts,
    /// colored output/progress bars, tools requiring an allocated tty), when you need
    /// to observe full-screen redraw-based output via shell_snapshot, or when you intend to
    /// actually drive a full-screen TUI program (see guide://shell/tui).
    /// See guide://shell/pty for guidance on when to use this.
    pub pty: Option<bool>,
    /// PTY window column count, only effective when pty=true, default 100
    pub cols: Option<u16>,
    /// PTY window row count, only effective when pty=true, default 40
    pub rows: Option<u16>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TagParams {
    /// Target session identifier
    pub tag: String,
}