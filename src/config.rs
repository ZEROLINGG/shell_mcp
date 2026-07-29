// src/config.rs
//! 集中管理各工具的默认参数常量。

/// `exec` 单次执行的默认超时（毫秒）
pub const EXEC_TIMEOUT_MS: u64 = 3000;

/// `shell_output` / `shell_snapshot` 判定“已安静”的默认 idle 时间（毫秒）
pub const OUTPUT_IDLE_MS: u64 = 200;

/// `shell_wait_for` 的默认超时（毫秒）
pub const WAIT_FOR_TIMEOUT_MS: u64 = 5000;

/// `shell_spawn(pty=true)` 默认窗口列数
pub const PTY_DEFAULT_COLS: u16 = 100;

/// `shell_spawn(pty=true)` 默认窗口行数
pub const PTY_DEFAULT_ROWS: u16 = 40;