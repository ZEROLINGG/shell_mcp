# PTY (Pseudo-Terminal) Mode Guide

## When to use pty=true

The default pipe mode (pty=false) is sufficient for the vast majority of scenarios (exec, most
interactive REPLs, ssh, gdb, etc.). Consider explicitly setting pty=true in shell_spawn when:

1. The target program uses isatty()/tcgetattr() to detect whether it's attached to a real terminal
   and changes behavior accordingly, e.g.:
    - `sudo` may refuse to read a password, or behave differently, when not attached to a tty
    - Some CLI tools auto-disable colors/progress bars/interactive confirmations when not on a tty
      (silently falling back to a non-interactive mode)
    - Some remote/management tools require an allocated tty to complete their handshake
2. In pipe mode, shell_output repeatedly returns nothing even though the program should be producing
   output on a real terminal — this is often exactly a missing-tty issue; try re-spawning the same
   command with pty=true.
3. You need to observe full-screen, redraw-based output (progress bars, cursor-positioned status
   panels/tables), or you need to actually DRIVE a full-screen TUI program (vim/nano/htop/less/
   whiptail/menuconfig, etc.) — see guide://shell/tui for the dedicated workflow.

Default window size is 100 columns x 40 rows, which is enough for most cases; if the target program is
sensitive to window size (pagination, table width, line-wrapping based on column count), you can
customize it via the `cols`/`rows` parameters of shell_spawn, or adjust it later at runtime with
shell_resize without losing session state.

## In pty mode, prefer shell_snapshot for reading output

In pty mode, stdout/stderr are merged into a single stream, and the raw byte stream contains many ANSI
escape sequences (cursor movement, screen clearing, colors, etc.). Continuing to use shell_output in
this mode gives you the "raw incremental text", which is hard to interpret in full-screen/redraw
scenarios. You should instead call shell_snapshot to get the rendered screen (plus the current cursor
position) and judge the program's current state from that before deciding on the next action.

You can still use shell_wait_for / shell_output to detect "whether new output was produced" (e.g.
waiting for a keyword to appear in the raw stream). Both accept a `strip_ansi=true` option — mainly
intended for pty mode — which strips ANSI escape/control sequences from the text before it is
returned (and, for shell_wait_for, before the pattern match is evaluated). This is useful when you
only care about plain-text content (e.g. "did the string 'Segmentation fault' appear anywhere"),
and can prevent a plain-text pattern from failing to match just because it happens to be split up
by embedded escape codes. It does NOT reconstruct the actual on-screen layout (line wrapping,
overwritten redraws, cursor-positioned content) — once you need to understand the actual screen
layout/content, switch to shell_snapshot instead.

## Typical steps

1. shell_spawn(shell="bash", tag="t1", pty=true)   # default 100x40
2. shell_send_line(input="some_tty_sensitive_command", tag="t1")
3. shell_snapshot(tag="t1", idle_ms=500)           # observe the current screen + cursor, instead of shell_output
4. To wait for a specific keyword: shell_wait_for(tag="t1", pattern="...", timeout_ms=3000,
   strip_ansi=true)
5. If driving a full-screen program: shell_send_keys(tag="t1", keys=["[Down]", "[Enter]"]) then
   shell_snapshot again — see guide://shell/tui for the full loop.
6. shell_close(tag="t1")