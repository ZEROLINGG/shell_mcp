// src/protocol/params/pty.rs
use rmcp::schemars;
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ControlParams {
    /// Target session identifier
    pub tag: String,
    /// Control character letter, e.g. "C" = Ctrl+C (interrupt/SIGINT), "D" = Ctrl+D (EOF),
    /// "Z" = Ctrl+Z (suspend, meaningful in pty mode only), "?" = DEL.
    /// Provide only the letter itself, without a "^" prefix.
    pub key: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendKeysParams {
    /// Target session identifier
    pub tag: String,
    /// Ordered list of items sent as a single burst. Each item is either:
    /// - literal text, sent as-is (e.g. "ls -la", "ihello world" for entering vim insert mode + typing)
    /// - a bracket-tagged special key (case-insensitive): [Up] [Down] [Left] [Right] [Home] [End]
    ///   [PageUp] [PageDown] [Insert] [Delete] [Tab] [BackTab] [Enter] [Escape] [Backspace]
    ///   [F1]..[F12]
    /// An unrecognized bracket tag (e.g. a typo like "[Upp]") causes an explicit error instead of
    /// being silently sent as literal text.
    pub keys: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoveCursorParams {
    /// Target session identifier
    pub tag: String,
    /// Target row, 1-based (ANSI CUP convention)
    pub row: u16,
    /// Target column, 1-based (ANSI CUP convention)
    pub col: u16,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ResizeParams {
    /// Target session identifier
    pub tag: String,
    /// New column count (must be >= 1)
    pub cols: u16,
    /// New row count (must be >= 1)
    pub rows: u16,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SnapshotParams {
    /// Target session identifier
    pub tag: String,
    /// Milliseconds to wait before snapshot
    pub wait_ms: Option<u64>,
}
