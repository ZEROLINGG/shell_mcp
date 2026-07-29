// src/docs/mod.rs
//! 所有通过 MCP resource（`guide://shell/...`）和 `ServerInfo::instructions`
//! 提供的说明文档。实际文本放在同目录下的 `.md` 文件里，方便用 Markdown
//! 工具编辑/校对，而不是塞在 Rust 字符串字面量里。

pub const QUICK_START: &str = include_str!("quick_start.md");
pub const SECURITY: &str = include_str!("security.md");
pub const BASICS: &str = include_str!("basics.md");
pub const PTY: &str = include_str!("pty.md");
pub const TUI: &str = include_str!("tui.md");
pub const GDB: &str = include_str!("gdb.md");
pub const SSH: &str = include_str!("ssh.md");
pub const SUDO: &str = include_str!("sudo.md");
pub const REVERSE_SHELL: &str = include_str!("reverse_shell.md");

/// 一篇通过 MCP resource 暴露的指南。
pub struct Guide {
    pub uri: &'static str,
    pub name: &'static str,
    pub content: &'static str,
}

/// 唯一真源：`list_resources` 与 `read_resource` 都从这张表派生，
/// 新增一篇文档只需要在这里加一条，不会再出现“改了 list 忘了改 read”的问题。
pub const ALL: &[Guide] = &[
    Guide {
        uri: "guide://shell/security",
        name: "⚠️ Security Guidelines (Must read first)",
        content: SECURITY,
    },
    Guide {
        uri: "guide://shell/basics",
        name: "shell_* Basic Usage and Lifecycle",
        content: BASICS,
    },
    Guide {
        uri: "guide://shell/pty",
        name: "PTY Mode Guide: when to enable pty, and preferring shell_snapshot",
        content: PTY,
    },
    Guide {
        uri: "guide://shell/tui",
        name: "Driving Full-Screen TUI Programs (vim/htop/less/whiptail) in pty mode",
        content: TUI,
    },
    Guide {
        uri: "guide://shell/gdb",
        name: "GDB / pwndbg Debugging Scenario Guide",
        content: GDB,
    },
    Guide {
        uri: "guide://shell/ssh",
        name: "SSH Remote Connection Scenario Guide",
        content: SSH,
    },
    Guide {
        uri: "guide://shell/sudo",
        name: "sudo Password / Confirmation Scenario Guide",
        content: SUDO,
    },
    Guide {
        uri: "guide://shell/reverse_shell",
        name: "CTF Reverse Shell Scenario Guide",
        content: REVERSE_SHELL,
    },
];

/// 根据 `guide://...` URI 查找文档内容。
pub fn find(uri: &str) -> Option<&'static str> {
    ALL.iter().find(|g| g.uri == uri).map(|g| g.content)
}