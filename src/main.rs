mod config;
mod docs;
mod protocol;
mod resources;
mod server_handler;
mod service;
mod shell_registry;
mod security;
mod utils;

use anyhow::Result;
use rmcp::{transport::stdio, ServiceExt};
use service::TerminalMcpService;


pub(crate) use protocol::{err, ok};
use security::audit;

#[tokio::main]
async fn main() -> Result<()> {
    let _audit_guard = audit::init();

    tracing::info!(target: "audit", event = "server_start", "shell mcp service starting");

    let server = TerminalMcpService::new().serve(stdio()).await?;

    server.waiting().await?;

    tracing::info!(target: "audit", event = "server_stop", "shell mcp service stopped");

    Ok(())
}