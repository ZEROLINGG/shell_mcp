# GDB / pwndbg Debugging Scenario

For every step, you must first read the output to confirm the program state (registers/breakpoints hit) before deciding on the next instruction. You must NEVER send multiple commands in batches in advance.

1. shell_spawn(shell="bash", tag="gdb1")
2. shell_send_line(input="gdb ./target_binary", tag="gdb1")
3. shell_output(tag="gdb1", idle_ms=1000) confirm the (gdb)/pwndbg> prompt appears
   (It is normal for pwndbg to have no output for a long time when loading debug info; just poll multiple times)
4. shell_send_line(input="start", tag="gdb1") followed by shell_output to confirm stopping at the entry breakpoint
5. Commands like continue/run have uncertain execution times: prefer
   shell_wait_for(tag="gdb1", pattern="Breakpoint", timeout_ms=5000) (adjust pattern as needed, e.g.
   "hit"/"exited"); if it times out without matching, call shell_wait_for again instead of waiting
   forever in one call.
6. Upon completion, shell_close(tag="gdb1")

Note: gdb is NOT a valid shell parameter value. You must spawn bash first and then send gdb as a command.