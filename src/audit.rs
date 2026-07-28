use crate::ToolResponse;
use tokio::time::Instant;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, fmt};

pub fn init() -> WorkerGuard {
    let log_dir = "./logs";
    let _ = std::fs::create_dir_all(log_dir);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(log_dir) {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            let _ = std::fs::set_permissions(log_dir, perms);
        }
    }

    let file_appender = tracing_appender::rolling::daily(log_dir, "shell_audit.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn,audit=info"));

    fmt()
        .json()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_env_filter(filter)
        .with_target(true)
        .with_current_span(false)
        .with_span_list(false)
        .init();

    guard
}

pub async fn with_audit<F, Fut>(
    action: &str,
    tag: Option<String>,
    shell: Option<String>,
    input: Option<String>,
    f: F,
) -> String
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    let trace_id = uuid::Uuid::new_v4().to_string();
    let tag_str = tag.unwrap_or_default();
    let shell_str = shell.unwrap_or_default();
    let input_str = input.as_deref().unwrap_or_default();

    tracing::info!(
            target: "audit",
            event = "begin",
            trace_id = %trace_id,
            action = action,
            tag = %tag_str,
            shell = %shell_str,
            input = %input_str,
            "tool call started"
        );

    let start = Instant::now();
    let result = f().await;
    let duration_ms = start.elapsed().as_millis() as u64;

    match &result {
        Ok(_) => {
            tracing::info!(
                    target: "audit",
                    event = "end",
                    trace_id = %trace_id,
                    action = action,
                    tag = %tag_str,
                    shell = %shell_str,
                    input = %input_str,
                    success = true,
                    duration_ms = duration_ms,
                    "tool call finished"
                );
        }
        Err(e) => {
            tracing::warn!(
                    target: "audit",
                    event = "end",
                    trace_id = %trace_id,
                    action = action,
                    tag = %tag_str,
                    shell = %shell_str,
                    input = %input_str,
                    success = false,
                    duration_ms = duration_ms,
                    error = %e,
                    "tool call failed"
                );
        }
    }

    match result {
        Ok(data) => crate::ok!(data),
        Err(msg) => crate::err!(msg),
    }
}