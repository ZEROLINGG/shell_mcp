// src/audit.rs

use serde::Serialize;
use std::future::Future;
use tokio::time::Instant;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, fmt};

/// 初始化审计日志：按天滚动、JSON 格式、写入 ./logs 目录。
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

    let file_appender = tracing_appender::rolling::daily(log_dir, "terminal_audit.log");
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

/// 通用审计包装器。
///
/// `extra` 可以是任意实现了 `Serialize` 的类型（结构体 / `serde_json::json!` 构造的 `Value` 等），
/// 支持任意数量、任意类型的附加字段，无需修改本函数签名即可扩展。
///
/// 字段排序：只要 `serde_json` 没有开启 `preserve_order` feature，
/// `Value::Object` 底层是 `BTreeMap`，序列化时会自动按 key 字母序排列，
/// 因此不同调用点写的字段顺序不影响最终日志中的顺序，天然保证一致性。
pub async fn with_audit<F, Fut, E>(action: &str, extra: E, f: F) -> String
where
    E: Serialize,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    let trace_id = uuid::Uuid::new_v4().to_string();

    // 序列化失败时（极少见，比如自定义 Serialize 实现有 bug）退化为 null，
    // 不影响主流程，只是这次日志的 extra 字段缺失。
    let extra_json = serde_json::to_value(&extra).unwrap_or(serde_json::Value::Null);

    tracing::info!(
        target: "audit",
        event = "begin",
        trace_id = %trace_id,
        action = action,
        extra = %extra_json,
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
                extra = %extra_json,
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
                extra = %extra_json,
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

/// 语法糖宏：把若干个已存在的同名变量打包成 `serde_json::Value`，
/// 等价于 `serde_json::json!({ "name1": name1, "name2": name2, ... })`。
/// ```ignore
/// let tag = "t1".to_string();
/// let shell = "bash".to_string();
/// let input = "ls -la".to_string();
///
/// with_audit(
///     "run_shell",
///     audit_extra!(tag, shell, input),
///     || async move { ... },
/// )
/// .await;
/// ```
#[macro_export]
macro_rules! audit_extra {
    ($($key:ident),* $(,)?) => {
        serde_json::json!({ $( stringify!($key): $key ),* })
    };
}

pub fn truncate_for_log(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}
