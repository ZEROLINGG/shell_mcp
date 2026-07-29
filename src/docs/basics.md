# shell_* Basic Usage and Lifecycle

1. shell_spawn(shell, tag, pty=false, cols, rows): Create a session, customize the tag (e.g., "py1").
   Set pty=true to spawn in PTY (pseudo-terminal) mode, default window size 100x40. See guide://shell/pty
   for when this is needed, and guide://shell/tui if your goal is to drive a full-screen program
   (vim/nano/htop/less/whiptail/menuconfig, etc.) inside it.
2. shell_send_line(input, tag): Send a command and automatically append a newline (Enter); most commonly used. Only returns "sent", without results.
3. shell_send(input, tag): Send content without appending a newline, used for raw text.
4. shell_send_control(tag, key): Send a standard terminal control character (C=interrupt, D=EOF, Z=suspend,
   ?=DEL, etc.), clearer and safer than embedding "\x03"/"^C" inside shell_send/shell_send_line.
5. shell_send_keys(tag, keys): Send an ordered mix of literal text and bracket-tagged special keys
   (e.g. "[Up]", "[Down]", "[Left]", "[Right]", "[Home]", "[End]", "[PageUp]", "[PageDown]",
   "[Insert]", "[Delete]", "[Tab]", "[BackTab]", "[Enter]", "[Escape]", "[Backspace]", "[F1]".."[F12]").
   Use this for shell-history recall, in-line editing, tab-completion, menu navigation, and driving
   full-screen TUI programs together with shell_snapshot. Unknown bracket tags return an explicit
   error instead of being silently sent as text. See guide://shell/tui.
6. shell_output(tag, idle_ms, strip_ansi): Get the output, MUST be called after every send_line; it
   waits until the output is silent for idle_ms (default 200ms) before returning the incremental
   stdout/stderr. Set strip_ansi=true to strip ANSI escape/control sequences (colors, cursor
   movement, etc.) from the returned text before returning it — this is mainly useful in pty mode,
   where the raw byte stream is often interleaved with such sequences and hard to read as plain
   text; when you need the actual rendered screen layout rather than just plain text, prefer
   shell_snapshot instead (see guide://shell/pty).
7. shell_wait_for(tag, pattern, timeout_ms, strip_ansi): Block until `pattern` appears in
   stdout/stderr, or until timeout (default 5000ms), then return everything collected so far.
   Set strip_ansi=true to strip ANSI sequences before both the pattern match and the returned text
   are computed — mainly useful in pty mode, where a plain-text `pattern` might otherwise fail to
   match because it is interrupted by embedded escape codes. Prefer this over repeatedly guessing
   idle_ms with shell_output when a command's completion time is uncertain (e.g. waiting for
   a breakpoint hit, a login prompt, or a specific log line). The response's `matched` field tells you
   whether the pattern was actually seen (false = timed out without seeing it).
8. shell_snapshot(tag, idle_ms): Get a rendered terminal screen snapshot plus the current cursor
   position (pty sessions only), shaped as `{ "screen": "...", "cursor": {"row":.., "col":..} }`
   (cursor 0-based, null if unavailable). In pty mode, ALWAYS prefer this over shell_output to
   understand the program's current on-screen state — including inside full-screen TUI programs —
   since shell_output in pty mode returns raw bytes intermixed with ANSI escape sequences that are
   hard to interpret directly (even with strip_ansi=true, stripping only removes the escape codes,
   it does not reconstruct the actual screen layout the way shell_snapshot does).
   See guide://shell/pty and guide://shell/tui.
9. shell_cursor_position(tag): Get just the current cursor (row, col; 0-based) without a full screen
   payload — cheaper than shell_snapshot when you only need to know where the caret/selection
   currently is (pty sessions only).
10. shell_move_cursor(tag, row, col): Move the cursor to an absolute 1-based (row, col) position via a
    standard ANSI CUP sequence (pty sessions only). Only affects where subsequently sent characters
    land; it does not by itself trigger program behavior.
11. shell_resize(tag, cols, rows): Dynamically resize an already-running pty session's terminal window
    without losing session state — use when a column/row-sensitive program needs a different size
    mid-session (pty sessions only).
12. shell_reset(tag): Force restart the session when stuck/in an infinite loop.
13. shell_close(tag): MUST be called when finished to avoid zombie processes.

Limitations: In pipe mode (pty=false), full-screen TUI/GUI programs (vim/nano/htop/less, etc.) are
still prohibited — use cat/head/grep to view files, since there is no way to observe the actual
screen layout without a real terminal. In pty mode (pty=true), full-screen TUI interaction IS
supported via the toolkit above (shell_snapshot + shell_send_keys + shell_cursor_position +
shell_move_cursor + shell_resize) — see guide://shell/tui for the required "send -> snapshot ->
decide" workflow and its caveats. It remains a strict turn-based loop, not true real-time human
interaction: never send a long chain of keys assuming you already know what several steps ahead
will look like on screen.
For long-running commands (gdb continue, ssh connection, large file downloads): prefer shell_wait_for
with an appropriate pattern; if no specific keyword is known in advance, call shell_output with a larger
idle_ms (2000~5000ms) and poll again rather than waiting indefinitely in a single call.