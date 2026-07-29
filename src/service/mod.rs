
// src/service/mod.rs
//! MCP 服务本体：把会话表（ShellRegistry）与各个能力域的 `#[tool]`/`#[prompt]`
//! 实现（分别位于本目录的兄弟模块中）组装到一起。
//!
//! `exec` / `session` / `io` / `pty` 四个子模块各自维护一组内聚的 `#[tool]`
//! 方法，并通过 `#[tool_router(router = ...)]` 各自产出一个具名 `ToolRouter`，
//! 最后在这里用 `+` 合并成 MCP 框架实际派发所用的单一 router。

mod exec;
mod io;
mod prompts;
mod pty;
mod session;

use crate::shell_registry::ShellRegistry;
use rmcp::handler::server::router::{prompt::PromptRouter, tool::ToolRouter};

#[derive(Clone)]
pub struct TerminalMcpService {
    pub(crate) registry: ShellRegistry,
    pub(crate) tool_router: ToolRouter<Self>,
    pub(crate) prompt_router: PromptRouter<Self>,
}

impl TerminalMcpService {
    pub fn new() -> Self {
        Self {
            registry: ShellRegistry::new(),
            tool_router: Self::exec_tool_router()
                + Self::session_tool_router()
                + Self::io_tool_router()
                + Self::pty_tool_router(),
            prompt_router: Self::prompt_router(),
        }
    }
}

impl Default for TerminalMcpService {
    fn default() -> Self {
        Self::new()
    }
}