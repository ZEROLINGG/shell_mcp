// src/service/session.rs
use super::TerminalMcpService;
use crate::protocol::params::{SpawnParams, TagParams};
use crate::{audit, audit_extra, config};
use rmcp::{handler::server::wrapper::Parameters, tool, tool_router};
use shell_engine::shell::Shell;

#[tool_router(router = session_tool_router, vis = "pub(crate)")]
impl TerminalMcpService {
    #[tool(description = "List tags and shell paths of all interactive shell sessions")]
    async fn shell_list(&self) -> String {
        audit::with_audit("shell_list", serde_json::json!({}), || async {
            Ok(serde_json::json!(self.registry.describe_all()))
        })
            .await
    }

    #[tool(description = "Check if an interactive shell session with the specified tag exists")]
    async fn shell_exists(&self, Parameters(TagParams { tag }): Parameters<TagParams>) -> String {
        let audit_tag = tag.clone();
        audit::with_audit("shell_exists", audit_extra!(audit_tag), || async move {
            Ok(serde_json::json!(self.registry.contains(&tag)))
        })
            .await
    }

    #[tool(description = "Create an interactive shell session with the tag as a unique identifier. \
Set pty=true to spawn in PTY (pseudo-terminal) mode, default window size 100x40; see \
guide://shell/pty for when this is needed, and guide://shell/tui if you intend to drive a \
full-screen TUI program inside it. For complex debugging/remote connection scenarios, \
it is recommended to first read_resource(guide://shell/gdb or guide://shell/ssh)")]
    async fn shell_spawn(
        &self,
        Parameters(SpawnParams { shell, tag, pty, cols, rows }): Parameters<SpawnParams>,
    ) -> String {

        let use_pty = pty.unwrap_or(false);
        let audit_tag = tag.clone();
        let audit_shell = if use_pty {
            format!("{shell}(pty)")
        } else {
            shell.clone()
        };

        audit::with_audit(
            "shell_spawn",
            audit_extra!(audit_tag, audit_shell),
            || async move {
                // 先做一次快速检查，避免 tag 已存在时还去 spawn 一次进程；
                // 真正防止并发重复注册的保证在 ShellRegistry::insert_new 内部
                // 的原子 entry 操作上（不持锁跨 await）。
                if self.registry.contains(&tag) {
                    return Err(format!("Session '{tag}' already exists"));
                }

                let mut builder = Shell::new(&shell).enable_buffer();

                #[cfg(feature = "pty")]
                if use_pty {
                    builder = builder.enable_pty();
                }
                #[cfg(not(feature = "pty"))]
                if use_pty {
                    return Err(
                        "This build of shell_mcp was not compiled with pty support".to_string(),
                    );
                }

                let mut s = builder.spawn().await.map_err(|e| e.to_string())?;

                #[cfg(feature = "pty")]
                if use_pty {
                    let cols = cols.unwrap_or(config::PTY_DEFAULT_COLS);
                    let rows = rows.unwrap_or(config::PTY_DEFAULT_ROWS);
                    s.resize(cols, rows).await.map_err(|e| e.to_string())?;
                }
                #[cfg(not(feature = "pty"))]
                {
                    let _ = (cols, rows);
                }

                self.registry.insert_new(tag, s)?;
                Ok(serde_json::json!({ "result": "created", "pty": use_pty }))
            },
        )
            .await
    }

    #[tool(description = "Reset the specified interactive shell session (exit and restart)")]
    async fn shell_reset(&self, Parameters(TagParams { tag }): Parameters<TagParams>) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_reset", audit_extra!(audit_tag), || async move {
            let shell = self.registry.get(&tag)?;
            shell.lock().await.reset().await.map_err(|e| e.to_string())?;
            Ok(serde_json::json!("reset"))
        })
            .await
    }

    #[tool(description = "Close and remove the specified interactive shell session")]
    async fn shell_close(&self, Parameters(TagParams { tag }): Parameters<TagParams>) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_close", audit_extra!(audit_tag), || async move {
            match self.registry.remove(&tag) {
                Some(shell) => {
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
        audit::with_audit("shell_close_all", serde_json::json!({}), || async {
            let (closed, errors) = self.registry.close_all().await;
            Ok(serde_json::json!({ "closed": closed, "errors": errors }))
        })
            .await
    }
}