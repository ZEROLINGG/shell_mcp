# SSH Remote Connection Scenario

Intermediate prompts (host fingerprint confirmation, password authentication) may or may not appear. You must observe step-by-step and respond accordingly. Do not assume a fixed number of steps.

1. shell_spawn(shell="bash", tag="ssh1")
2. shell_send_line(input="ssh user@host", tag="ssh1")
3. shell_output(tag="ssh1", idle_ms=1500), or shell_wait_for(tag="ssh1", pattern="password:",
   timeout_ms=3000) if you want to wait specifically for a known prompt; determine the next step based
   on actual content:
    - If "continue connecting (yes/no" appears -> send_line("yes")
    - If "password:" appears -> send_line(password)
    - If the remote prompt appears directly -> key authentication passed
4. Execute remote commands only after confirming successful login (remote prompt/"Last login"); if "Permission denied"/"Connection refused" occurs, terminate the process and report the error.
5. Before finishing, send_line("exit") to return to the local shell, then shell_close(tag="ssh1")

Note: After logging in, all send_line commands are executed on the remote host until an explicit exit.
ssh is also NOT a valid shell parameter value.