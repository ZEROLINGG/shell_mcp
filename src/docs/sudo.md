# sudo Password / y-n Confirmation Scenario

1. shell_spawn(shell="bash", tag="b1")
2. shell_send_line(input="sudo -s apt update", tag="b1")
3. shell_output(tag="b1") observe if "[sudo] password for..." appears
4. shell_send_line(input="password", tag="b1")
5. shell_output(tag="b1", idle_ms=1000) (increase idle_ms if the command is slow)
6. shell_close(tag="b1")

If shell_output repeatedly shows nothing even after sending the sudo command (no password prompt at
all), sudo may be refusing to run without a real terminal. Try re-spawning with
shell_spawn(shell="bash", tag="b1", pty=true) and repeat the steps above; in pty mode prefer
shell_snapshot over shell_output to check the prompt. See guide://shell/pty.