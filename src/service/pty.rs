// src/service/pty.rs
use super::TerminalMcpService;
use crate::protocol::params::{ControlParams, MoveCursorParams, ResizeParams, SendKeysParams, SnapshotParams, TagParams};
use crate::{audit_extra, config};
use rmcp::{handler::server::wrapper::Parameters, tool, tool_router};
use shell_engine::shell::Key;
use std::time::Duration;
use crate::security::audit;

#[tool_router(router = pty_tool_router, vis = "pub(crate)")]
impl TerminalMcpService {
    #[tool(description = "Send a standard terminal control character to the specified interactive shell \
(e.g. key=\"C\" for Ctrl+C/interrupt, \"D\" for Ctrl+D/EOF, \"Z\" for Ctrl+Z/suspend, \"?\" for DEL). \
Clearer and safer than embedding raw control bytes or \"^C\"-style strings inside shell_send/shell_send_line. \
In pty mode this is translated to the corresponding standard control byte; in pipe (non-pty) mode only \
two special semantics are preserved: R = reset the session (equivalent to shell_reset), D = send EOF \
(close stdin).")]
    async fn shell_send_control(
        &self,
        Parameters(ControlParams { tag, key }): Parameters<ControlParams>,
    ) -> String {
        let audit_tag = tag.clone();
        let audit_key = key.clone();

        audit::with_audit(
            "shell_send_control",
            audit_extra!(audit_tag, audit_key),
            || async move {
                let ch = key
                    .trim()
                    .chars()
                    .next()
                    .ok_or_else(|| "key must not be empty".to_string())?;

                let shell = self.registry.get(&tag)?;
                shell.lock().await.send_control_char(ch).await.map_err(|e| e.to_string())?;
                Ok(serde_json::json!("sent"))
            },
        )
            .await
    }

    #[tool(description = "Send an ordered sequence of literal text and/or special keys \
(arrow keys, Home/End, PageUp/PageDown, Insert/Delete, Tab/BackTab, Enter/Escape/Backspace, \
F1-F12) to the specified session as a single burst. Use this instead of embedding raw ANSI \
escape bytes in shell_send when you need to: recall shell history (Up/Down), move within / edit \
the current input line (Left/Right/Home/End/Delete/Backspace), trigger tab-completion (Tab), \
answer arrow-key-driven menus/wizards (whiptail/dialog-style), or drive a full-screen TUI \
program (vim/htop/less/menuconfig, etc.) together with shell_snapshot — see guide://shell/tui \
for the required workflow. Unknown bracket-tagged keys (e.g. a typo like \"[Upp]\") return an \
explicit error instead of being silently sent as literal text. After sending, ALWAYS use \
shell_snapshot (pty mode) or shell_output (pipe mode) to confirm the result before deciding the \
next step — never chain many key-sends assuming you already know what the screen will look like \
several steps ahead.")]
    async fn shell_send_keys(
        &self,
        Parameters(SendKeysParams { tag, keys }): Parameters<SendKeysParams>,
    ) -> String {
        let audit_tag = tag.clone();
        let audit_input = keys.join(" ");

        audit::with_audit(
            "shell_send_keys",
            audit_extra!(audit_tag, audit_input),
            || async move {
                let shell = self.registry.get(&tag)?;
                let seq = keys.into_iter().map(Key::StringChar).collect();
                shell.lock().await.send_keys(seq).await.map_err(|e| e.to_string())?;
                Ok(serde_json::json!("sent"))
            },
        )
            .await
    }

    #[tool(description = "Get a rendered virtual terminal screen snapshot plus the current cursor \
position of the specified session (only valid for sessions created with pty=true). Returns \
`{ \"screen\": \"...\", \"cursor\": {\"row\":.., \"col\":..} }` (cursor is 0-based, null if \
unavailable) after interpreting cursor movement/screen-clearing/color control sequences, instead \
of a raw byte stream. In pty mode, ALWAYS prefer this over shell_output to judge the program's \
current state (progress bars, screens after a clear, cursor-positioned redraw-based output, or \
full-screen TUI programs), because shell_output returns raw incremental bytes that may contain \
heavy control sequences or already-overwritten intermediate frames and are hard to interpret \
directly (shell_output's strip_ansi option only removes escape codes from the raw text, it does \
not reconstruct the actual screen layout the way this tool does). Full-screen TUI programs \
(vim/nano/htop/less/whiptail/menuconfig, etc.) are supported via this tool combined with \
shell_send_keys / shell_cursor_position / shell_move_cursor / shell_resize — see guide://shell/tui \
for the required send -> snapshot -> decide workflow.")]
    async fn shell_snapshot(
        &self,
        Parameters(SnapshotParams { tag, wait_ms }): Parameters<SnapshotParams>,
    ) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_snapshot", audit_extra!(audit_tag), || async move {
            #[cfg(feature = "pty")]
            {
                let shell = self.registry.get(&tag)?;
                let wait = Some(Duration::from_millis(wait_ms.unwrap_or(config::SNAPSHOT_WAIT_MS)));

                let mut guard = shell.lock().await;
                let screen = guard.output_snapshot(None, wait).await.map_err(|e| e.to_string())?;
                let cursor = guard
                    .cursor_position()
                    .ok()
                    .map(|(row, col)| serde_json::json!({ "row": row, "col": col }));
                drop(guard);

                Ok(serde_json::json!({ "screen": screen, "cursor": cursor }))
            }
            #[cfg(not(feature = "pty"))]
            {
                let _ = (tag, idle_ms);
                Err("This build of shell_mcp was not compiled with pty support".to_string())
            }
        })
            .await
    }

    #[tool(description = "Get the current cursor position (row, col; 0-based, vt100 convention) on \
the rendered virtual terminal screen of the specified session (only valid for pty=true sessions). \
Cheaper than shell_snapshot when you only need to know where the input caret / menu selection \
indicator currently sits, without pulling the full screen text.")]
    async fn shell_cursor_position(
        &self,
        Parameters(TagParams { tag }): Parameters<TagParams>,
    ) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_cursor_position", audit_extra!(audit_tag), || async move {
            #[cfg(feature = "pty")]
            {
                let shell = self.registry.get(&tag)?;
                let guard = shell.lock().await;
                let (row, col) = guard.cursor_position().map_err(|e| e.to_string())?;
                Ok(serde_json::json!({ "row": row, "col": col }))
            }
            #[cfg(not(feature = "pty"))]
            {
                let _ = tag;
                Err("This build of shell_mcp was not compiled with pty support".to_string())
            }
        })
            .await
    }

    #[tool(description = "Move the terminal cursor of the specified session to an absolute (row, col) \
position via a standard ANSI CUP escape sequence (only valid for pty=true sessions). Coordinates \
are 1-based (note: this differs from shell_cursor_position/shell_snapshot's 0-based cursor output \
— add 1 to reuse those values here). Only affects where subsequently sent characters land; it does \
not by itself trigger program behavior unless the running program itself reads cursor-addressed \
input (some full-screen TUI programs do). See guide://shell/tui.")]
    async fn shell_move_cursor(
        &self,
        Parameters(MoveCursorParams { tag, row, col }): Parameters<MoveCursorParams>,
    ) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_move_cursor", audit_extra!(audit_tag, row, col), || async move {
            #[cfg(feature = "pty")]
            {
                let shell = self.registry.get(&tag)?;
                let mut guard = shell.lock().await;
                guard.move_cursor_to(row, col).await.map_err(|e| e.to_string())?;
                Ok(serde_json::json!("moved"))
            }
            #[cfg(not(feature = "pty"))]
            {
                let _ = (tag, row, col);
                Err("This build of shell_mcp was not compiled with pty support".to_string())
            }
        })
            .await
    }

    #[tool(description = "Dynamically resize the PTY window of an already-running session (only valid \
for pty=true sessions) without losing session state (no need to re-spawn). Use this when a \
column/row-sensitive program (pagers, progress bars, table renderers, full-screen TUI programs) \
needs a different terminal size mid-session. cols/rows must be >= 1.")]
    async fn shell_resize(
        &self,
        Parameters(ResizeParams { tag, cols, rows }): Parameters<ResizeParams>,
    ) -> String {
        let audit_tag = tag.clone();

        audit::with_audit("shell_resize", audit_extra!(audit_tag, cols, rows), || async move {
            if cols == 0 || rows == 0 {
                return Err("cols and rows must be >= 1".to_string());
            }
            #[cfg(feature = "pty")]
            {
                let shell = self.registry.get(&tag)?;
                let mut guard = shell.lock().await;
                guard.resize(cols, rows).await.map_err(|e| e.to_string())?;
                Ok(serde_json::json!({ "cols": cols, "rows": rows }))
            }
            #[cfg(not(feature = "pty"))]
            {
                let _ = (tag, cols, rows);
                Err("This build of shell_mcp was not compiled with pty support".to_string())
            }
        })
            .await
    }
}