// src/shell_registry.rs
//! 交互式会话表的领域逻辑，完全不依赖 `rmcp`，只依赖 `shell_engine::Shell`
//! 与普通 Rust/JSON 类型，方便脱离 MCP 框架单独单元测试。

use dashmap::DashMap;
use shell_engine::shell::Shell;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct ShellRegistry {
    inner: Arc<DashMap<String, Arc<Mutex<Shell>>>>,
}

impl ShellRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 根据 tag 获取会话句柄的克隆；不存在时返回可读错误信息。
    pub fn get(&self, tag: &str) -> Result<Arc<Mutex<Shell>>, String> {
        self.inner
            .get(tag)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| format!("Session '{tag}' does not exist"))
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.inner.contains_key(tag)
    }

    /// 注册一个刚 spawn 好的 `Shell`。若 tag 已存在则原子性失败（不会覆盖）。
    ///
    /// 注意：调用方应当在真正执行耗时的 `spawn().await` 之前先用 `contains`
    /// 做一次快速检查（避免无意义的进程创建开销），但最终的“防重复注册”
    /// 保证以本方法内部的 `DashMap::entry` 原子操作为准 —— 这样可以避免像
    /// “在持有 DashMap 分片锁的同时跨 await 点”这种有风险的写法。
    pub fn insert_new(&self, tag: String, shell: Shell) -> Result<(), String> {
        match self.inner.entry(tag.clone()) {
            dashmap::Entry::Occupied(_) => Err(format!("Session '{tag}' already exists")),
            dashmap::Entry::Vacant(slot) => {
                slot.insert(Arc::new(Mutex::new(shell)));
                Ok(())
            }
        }
    }

    /// 移除并返回指定 tag 的会话句柄（如果存在）。
    pub fn remove(&self, tag: &str) -> Option<Arc<Mutex<Shell>>> {
        self.inner.remove(tag).map(|(_, v)| v)
    }

    /// 当前所有已注册的 tag（调用时刻的快照）。
    pub fn tags(&self) -> Vec<String> {
        self.inner.iter().map(|entry| entry.key().clone()).collect()
    }

    /// 构建 `shell_list` 所需的 JSON 摘要。
    pub fn describe_all(&self) -> Vec<serde_json::Value> {
        self.inner
            .iter()
            .map(|entry| {
                let tag = entry.key().clone();
                match entry.value().try_lock() {
                    Ok(guard) => {
                        #[cfg(feature = "pty")]
                        let (is_pty, pty_size) = (guard.is_pty(), guard.pty_window_size());
                        #[cfg(not(feature = "pty"))]
                        let (is_pty, pty_size): (bool, Option<(u16, u16)>) = (false, None);

                        serde_json::json!({
                            "tag": tag,
                            "shell_path": guard.shell_path,
                            "is_pty": is_pty,
                            "pty_size": pty_size,
                            "stdout_truncated_bytes": guard.output_truncated_bytes(),
                            "stderr_truncated_bytes": guard.error_truncated_bytes(),
                        })
                    }
                    Err(_) => serde_json::json!({ "tag": tag, "busy": true }),
                }
            })
            .collect()
    }

    /// 移除并关闭所有会话；返回成功关闭的 tag 列表和逐条错误信息。
    pub async fn close_all(&self) -> (Vec<String>, Vec<String>) {
        let mut closed = Vec::new();
        let mut errors = Vec::new();

        for tag in self.tags() {
            if let Some(shell) = self.remove(&tag) {
                match shell.lock().await.close() {
                    Ok(_) => closed.push(tag),
                    Err(e) => errors.push(format!("{tag}: {e}")),
                }
            }
        }

        (closed, errors)
    }
}