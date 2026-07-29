// src/protocol/params/io.rs
use rmcp::schemars;
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendParams {
    /// Content to send
    pub input: String,
    /// Target session identifier
    pub tag: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OutputParams {
    /// Target session identifier
    pub tag: String,
    /// Idle timeout in milliseconds, default 200
    pub idle_ms: Option<u64>,
    /// Whether to strip ANSI escape/control sequences (colors, cursor movement, screen-clearing,
    /// etc.) from the returned stdout/stderr before returning it, default false. This is mainly
    /// intended for pty-mode sessions, where the raw byte stream is frequently interleaved with
    /// such sequences, making it hard to read as plain text. Note this only removes escape codes
    /// from the raw incremental text — it does NOT reconstruct the actual rendered screen layout
    /// (line wrapping, overwritten redraws, cursor-positioned content); when you need the real
    /// on-screen state, use shell_snapshot instead. This field has no effect when used against
    /// shell_snapshot (its `screen` output is already fully rendered plain text).
    pub strip_ansi: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WaitForParams {
    /// Target session identifier
    pub tag: String,
    /// Substring expected to appear in stdout or stderr; returns immediately once matched
    pub pattern: String,
    /// Maximum time to wait in milliseconds; returns whatever has been collected so far
    /// even if the pattern was not matched, default 5000
    pub timeout_ms: Option<u64>,
    /// Whether to strip ANSI escape/control sequences from stdout/stderr before both returning
    /// them and evaluating the `pattern` match, default false. This is mainly intended for
    /// pty-mode sessions: raw pty output is often interleaved with cursor-movement/color escape
    /// sequences, which can otherwise cause a plain-text `pattern` to fail to match even though
    /// the text is visually present, or make the returned text hard to read. Has no effect on
    /// the actual screen layout reconstruction — for that, use shell_snapshot instead.
    pub strip_ansi: Option<bool>,
}