// src/service/io.rs
use super::TerminalMcpService;
use crate::protocol::params::{OutputParams, SendParams, WaitForParams};
use crate::{audit_extra, config};
use rmcp::{handler::server::wrapper::Parameters, tool, tool_router};
use shell_engine::util::strip_ansi_codes;
use std::time::Duration;
use crate::security::audit;

#[tool_router(router = io_tool_router, vis = "pub(crate)")]
impl TerminalMcpService {
    #[tool(description = "Send content to the specified interactive shell (without appending a newline)")]
    async fn shell_send(&self, Parameters(SendParams { input, tag }): Parameters<SendParams>) -> String {
        let audit_tag = tag.clone();
        let audit_input = input.clone();

        audit::with_audit(
            "shell_send",
            audit_extra!(audit_tag, audit_input),
            || async move {
                let shell = self.registry.get(&tag)?;
                shell.lock().await.send(&input).await.map_err(|e| e.to_string())?;
                Ok(serde_json::json!("sent"))
            },
        )
            .await
    }

    #[tool(description = "Send content to the specified interactive shell and append a newline (equivalent to pressing Enter)")]
    async fn shell_send_line(&self, Parameters(SendParams { input, tag }): Parameters<SendParams>) -> String {
        let audit_tag = tag.clone();
        let audit_input = input.clone();

        audit::with_audit(
            "shell_send_line",
            audit_extra!(audit_tag, audit_input),
            || async move {
                let shell = self.registry.get(&tag)?;
                shell.lock().await.send_line(&input).await.map_err(|e| e.to_string())?;
                Ok(serde_json::json!("sent"))
            },
        )
            .await
    }

    #[tool(description = "Get the output of the specified interactive shell (including stdout and \
stderr). MUST be called after every shell_send_line to confirm the state before deciding the next \
step. Set strip_ansi=true to strip ANSI escape/control sequences (colors, cursor movement, \
screen-clearing, etc.) from the returned stdout/stderr before returning — this is mainly intended \
for pty-mode sessions, where the raw byte stream is frequently interleaved with such sequences and \
hard to read as plain text. Note this does not reconstruct the actual rendered screen layout; when \
you need the real on-screen state (e.g. inside a full-screen TUI program), use shell_snapshot \
instead (see guide://shell/pty).")]
    async fn shell_output(
        &self,
        Parameters(OutputParams { tag, idle_ms, strip_ansi }): Parameters<OutputParams>,
    ) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_output", audit_extra!(audit_tag), || async move {
            let shell = self.registry.get(&tag)?;
            let idle = Some(Duration::from_millis(idle_ms.unwrap_or(config::OUTPUT_IDLE_MS)));

            let mut guard = shell.lock().await;
            let result = guard.output(idle, None).await;
            drop(guard);

            let (stdout, stderr) = if strip_ansi.unwrap_or(false) {
                (strip_ansi_codes(&result.stdout), strip_ansi_codes(&result.stderr))
            } else {
                (result.stdout, result.stderr)
            };

            Ok(serde_json::json!({ "stdout": stdout, "stderr": stderr }))
        })
            .await
    }

    #[tool(description = "Block and wait until `pattern` appears in stdout/stderr of the specified session, \
or until `timeout_ms` elapses (default 5000), then return everything collected so far. \
Suitable for commands with uncertain completion time (gdb continue/run hitting a breakpoint, \
yes/password prompts during ssh login, long-running task completion markers, etc.). Compared to \
repeatedly calling shell_output(idle_ms=...) and manually guessing the wait time, this significantly \
reduces the number of interaction turns. Set strip_ansi=true to strip ANSI escape/control sequences \
from stdout/stderr BEFORE both the pattern match and the returned text are computed — mainly \
intended for pty-mode sessions, where raw output is often interleaved with such sequences, which \
can otherwise cause a plain-text `pattern` to fail to match even though it is visually present. \
The `matched` field in the response indicates whether the pattern was actually seen (false means \
it timed out without matching).")]
    async fn shell_wait_for(
        &self,
        Parameters(WaitForParams { tag, pattern, timeout_ms, strip_ansi }): Parameters<WaitForParams>,
    ) -> String {
        let audit_tag = tag.clone();
        let audit_pattern = pattern.clone();

        audit::with_audit(
            "shell_wait_for",
            audit_extra!(audit_tag, audit_pattern),
            || async move {
                let shell = self.registry.get(&tag)?;
                let timeout = Duration::from_millis(timeout_ms.unwrap_or(config::WAIT_FOR_TIMEOUT_MS));

                let mut guard = shell.lock().await;
                let result = guard.output_until(pattern.clone(), Some(timeout)).await;
                drop(guard);

                let (stdout, stderr) = if strip_ansi.unwrap_or(false) {
                    (strip_ansi_codes(&result.stdout), strip_ansi_codes(&result.stderr))
                } else {
                    (result.stdout, result.stderr)
                };

                let matched = stdout.contains(&pattern) || stderr.contains(&pattern);

                Ok(serde_json::json!({
                    "stdout": stdout,
                    "stderr": stderr,
                    "matched": matched,
                }))
            },
        )
            .await
    }
}