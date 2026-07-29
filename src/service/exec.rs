// src/service/exec.rs
use super::TerminalMcpService;
use crate::protocol::params::ExecParams;
use crate::{audit, audit_extra, config};
use rmcp::{handler::server::wrapper::Parameters, tool, tool_router};
use shell_engine::exec::exec;
use std::time::Duration;

#[tool_router(router = exec_tool_router, vis = "pub(crate)")]
impl TerminalMcpService {
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
        let timeout = Duration::from_millis(timeout_ms.unwrap_or(config::EXEC_TIMEOUT_MS));
        let audit_input = input.clone();
        let audit_shell = shell.clone();

        audit::with_audit(
            "exec",
            audit_extra!(audit_shell, audit_input),
            || async move {
                exec(input, shell, Some(timeout))
                    .await
                    .map(|res| serde_json::to_value(res).unwrap_or(serde_json::Value::Null))
                    .map_err(|e| e.to_string())
            },
        )
        .await
    }
}
