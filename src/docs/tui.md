# Driving Full-Screen TUI Programs in PTY mode (vim/nano/htop/less/whiptail/menuconfig, etc.)

With pty=true plus the full pty toolkit (shell_snapshot, shell_cursor_position, shell_send_keys,
shell_move_cursor, shell_resize), full-screen redraw-based interactive programs are supported.
This lifts the previous blanket prohibition on vim/nano/htop/less etc. that applies in pipe mode.
The interaction model is still turn-based (send -> snapshot -> decide), not true real-time
keystroke-by-keystroke human interaction — you must request a fresh screen snapshot after every
input before deciding the next key, rather than assuming you already know how the screen looks.

## Core workflow

1. shell_spawn(shell="bash", tag="t1", pty=true[, cols, rows])
2. shell_send_line(input="vim file.txt", tag="t1")   # or htop / less / whiptail / menuconfig ...
3. shell_snapshot(tag="t1", idle_ms=300)
    - ALWAYS use shell_snapshot, never shell_output, once inside a full-screen program.
    - The response contains both `screen` (rendered plain text, ANSI sequences already interpreted)
      and `cursor` (0-based row/col), telling you exactly what is on screen and where the caret /
      selection indicator currently sits.
4. Decide the next input strictly based on the actual screen content + cursor position, then send:
    - shell_send_keys(tag="t1", keys=["[Down]", "[Down]", "[Enter]"]) for navigation/menu selection
    - shell_send(tag="t1", input="ihello world") to e.g. enter vim insert mode and type text
    - shell_send_keys(tag="t1", keys=["[Escape]"]) to leave insert mode back to vim normal mode
    - shell_send_line(tag="t1", input=":wq") to run a vim command-line command
    - shell_send_control(tag="t1", key="C") for interrupt, when a control character is more
      appropriate than a special key
5. Re-snapshot after every single action, exactly like the "send one step -> observe -> decide"
   discipline used everywhere else in this tool. Do NOT send a long chain of keys assuming you
   know the exact resulting screen several steps ahead — full-screen programs can behave
   differently depending on terminal size, current mode, or timing, and a wrong assumption
   compounds quickly across multiple steps.
6. If cols/rows mismatch causes broken rendering, or the screen becomes hard to interpret, call
   shell_resize(tag="t1", cols=.., rows=..) and re-snapshot.
7. When truly stuck (garbled screen, program not responding as expected to the keys you sent),
   use shell_send_control (e.g. key="C" for interrupt) or shell_reset as escape hatches — do not
   loop indefinitely guessing keys hoping the screen will recover on its own.
8. Prefer exiting the program through its own proper quit sequence when possible (e.g. `:wq`/`:q!`
   in vim, `q` in htop/less, Cancel/Exit in whiptail dialogs) before shell_close, to leave the
   remote/target state clean — though shell_close will still forcibly terminate the session if
   the program does not respond.

## Still true / not changed by this capability

- This is not a substitute for a human watching continuous real-time redraws; you only see the
  screen state at the moments you explicitly call shell_snapshot / shell_cursor_position.
- Overusing full-screen TUI interaction for tasks that don't need it is wasteful and error-prone —
  prefer cat/head/grep for simple read-only file inspection, and reserve TUI driving for cases
  that genuinely require it (editing via vim because no other editor is available, inspecting
  live status in htop, answering a whiptail/dialog wizard prompt, using menuconfig-style
  configuration tools, etc.).
- guide://shell/security still applies in full: if a TUI interaction ends up performing an action
  that falls under Rule 2 there (e.g. saving a config change that alters the system, applying a
  persistent/destructive change through a menuconfig-like tool), it still requires the same
  explicit user consent as if that action were run as an ordinary shell command. Driving a TUI is
  just a different input method — it does not change what kind of action is being performed.