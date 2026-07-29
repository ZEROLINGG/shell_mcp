// src/protocol/params/exec.rs
use rmcp::schemars;
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecParams {
    /// Command content to execute
    pub input: String,
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
    /// Timeout in milliseconds, default 3000
    pub timeout_ms: Option<u64>,
}