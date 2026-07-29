// src/main.rs
mod audit;
mod config;
mod docs;
mod protocol;
mod resources;
mod server_handler;
mod service;
mod shell_registry;

use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use service::TerminalMcpService;


pub(crate) use protocol::{err, ok};

#[tokio::main]
async fn main() -> Result<()> {
    let _audit_guard = audit::init();

    tracing::info!(target: "audit", event = "server_start", "shell mcp service starting");

    let server = TerminalMcpService::new().serve(stdio()).await?;

    server.waiting().await?;

    tracing::info!(target: "audit", event = "server_stop", "shell mcp service stopped");

    Ok(())
}