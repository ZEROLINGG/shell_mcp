// src/security/detect/mod.rs
#![allow(unused)]

pub mod bash;
pub mod cmd;
pub mod node;
pub mod powershell;
pub mod python;

use crate::security::audit::truncate_for_log;
use anyhow::Result;
use async_trait::async_trait;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::env;
use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};

static SHELL_DETECTION_LEVEL: LazyLock<Option<Severity>> = LazyLock::new(|| {
    match env::var("SHELL_DETECTION_LEVEL")
        .unwrap_or_else(|_| "low".to_string())
        .to_lowercase()
        .as_str()
    {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "none" => None,
        _ => Some(Severity::Low),
    }
});

static ON_DETECT_TIMEOUT: LazyLock<Duration> = LazyLock::new(|| {
    env::var("ON_DETECT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(3000))
});

static RULE_TIMEOUT: LazyLock<Duration> = LazyLock::new(|| {
    env::var("RULE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(3000))
});


#[derive(Default)]
pub struct Extensions {
    map: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Extensions {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
    /// 插入任意类型的数据
    pub fn insert<T: Send + Sync + 'static>(&mut self, val: T) {
        self.map.insert(TypeId::of::<T>(), Box::new(val));
    }
    /// 获取任意类型的数据的引用
    pub fn get<T: 'static>(&self) -> Option<&T> {
        self.map
            .get(&TypeId::of::<T>())
            .and_then(|boxed| boxed.as_ref().downcast_ref::<T>())
    }

    /// 获取任意类型数据的可变引用
    pub fn get_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.map
            .get_mut(&TypeId::of::<T>())
            .and_then(|boxed| boxed.as_mut().downcast_mut::<T>())
    }
}

impl std::fmt::Debug for Extensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extensions")
            .field("count", &self.map.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuleMetadata {
    pub name: String,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub enum DetectResult {
    Safe,
    ThreatDetected(Vec<(RuleMetadata, Option<String>)>),
    Unknown,
}

impl DetectResult {
    /// 聚合出本次命中中的最高危级别，方便调用方直接决策
    pub fn max_severity(&self) -> Option<Severity> {
        match self {
            DetectResult::ThreatDetected(hits) => hits.iter().map(|(m, _)| m.severity).max(),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ShellContext {
    pub shell_path: String,
    pub env: Vec<(String, String)>,    // 启动时快照，不可变，无锁访问
    history: RwLock<VecDeque<String>>, // 运行期追加，内部互斥
    max_history_size: usize,
    pub extensions: Extensions,
}

impl ShellContext {
    pub fn new(
        shell_path: impl Into<String>,
        env: Vec<(String, String)>,
        max_history_size: usize,
    ) -> Self {
        Self {
            shell_path: shell_path.into(),
            env,
            history: RwLock::new(VecDeque::with_capacity(max_history_size)),
            max_history_size,
            extensions: Extensions::new(),
        }
    }

    pub async fn push_history(&self, cmd: impl Into<String>) {
        if self.max_history_size == 0 {
            return;
        }
        let mut h = self.history.write().await;
        if h.len() >= self.max_history_size {
            h.pop_front();
        }
        h.push_back(cmd.into());
    }

    /// 克隆一份历史快照，适合规则需要长期持有/跨 await 使用的场景。
    pub async fn history_snapshot(&self) -> Vec<String> {
        self.history.read().await.iter().cloned().collect()
    }

    /// 零拷贝方式访问历史，闭包内直接借用 VecDeque。
    /// 适合规则只需做一次性扫描（如 contains/positional 检查）的场景，
    /// 避免为大容量历史付出整体 clone 的代价。
    pub async fn with_history<R>(&self, f: impl FnOnce(&VecDeque<String>) -> R) -> R {
        let guard = self.history.read().await;
        f(&guard)
    }

    /// 便捷方法：取最近 n 条历史（不含当前正在评估的这条）
    pub async fn recent_history(&self, n: usize) -> Vec<String> {
        self.with_history(|h| h.iter().rev().take(n).rev().cloned().collect())
            .await
    }
}

pub enum EvaluateResult {
    Hit(Option<String>),
    Miss,
}

#[async_trait]
pub trait Rule: Send + Sync {
    fn meta(&self) -> &RuleMetadata;
    async fn evaluate(&self, data: &str, ctx: &ShellContext) -> Result<EvaluateResult>;
}

#[async_trait]
pub trait Detector: Send + Sync {
    fn context(&self) -> &Arc<ShellContext>;
    fn rules(&self) -> &[Arc<dyn Rule>];

    async fn on_detect(&self, data: &str) -> Result<()>;

    async fn detect(&self, mut data: String, stop_on_first_hit: bool, append_enter: bool) -> DetectResult {
        if SHELL_DETECTION_LEVEL.is_none() {
            return DetectResult::Unknown;
        }
        let threshold_severity = SHELL_DETECTION_LEVEL.unwrap();

        let ctx = self.context();
        let mut hits = Vec::new();
        let mut evaluated = 0usize;

        let on_detect_timeout = *ON_DETECT_TIMEOUT;
        let rule_timeout = *RULE_TIMEOUT;

        if append_enter {
            data.push('\n');
        }
        let data_str = data.as_str();

        match timeout(on_detect_timeout, self.on_detect(data_str)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::error!(
                    target: "security::on_detect",
                    shell = %ctx.shell_path,
                    input_len = data_str.len(),
                    input_preview = %truncate_for_log(data_str, 200),
                    error = %e,
                    "on_detect failed, skipped rule evaluation"
                );
                return DetectResult::Unknown;
            }
            Err(_) => {
                tracing::error!(
                    target: "security::on_detect",
                    shell = %ctx.shell_path,
                    input_len = data_str.len(),
                    input_preview = %truncate_for_log(data_str, 200),
                    "on_detect timed out after {:?}", on_detect_timeout
                );
                return DetectResult::Unknown;
            }
        }

        let mut set = JoinSet::new();
        let mut rules_iter = self.rules().iter().cloned();

        let data_arc: Arc<str> = Arc::from(data_str);

        let spawn_rule = |set: &mut JoinSet<_>, rule: Arc<dyn Rule>, data_arc: Arc<str>, ctx: Arc<ShellContext>| {
            set.spawn(async move {
                let res = timeout(rule_timeout, rule.evaluate(&data_arc, &ctx)).await;
                (rule, res)
            });
        };

        // 初始填充滑动窗口
        for _ in 0..30 {
            if let Some(rule) = rules_iter.next() {
                spawn_rule(&mut set, rule, Arc::clone(&data_arc), Arc::clone(ctx));
            }
        }


        while let Some(res) = set.join_next().await {
            match res {
                Ok((rule, timeout_res)) => {
                    match timeout_res {
                        Ok(Ok(EvaluateResult::Hit(evidence))) => {
                            let meta = rule.meta().clone();
                            let is_over_threshold = meta.severity >= threshold_severity;

                            hits.push((meta, evidence));
                            evaluated += 1;

                            if stop_on_first_hit && is_over_threshold {
                                set.abort_all();
                                break;
                            }
                        }
                        Ok(Ok(EvaluateResult::Miss)) => {
                            evaluated += 1;
                        }
                        Ok(Err(err)) => {
                            tracing::error!(
                                target: "security::detect",
                                rule_name = %rule.meta().name,
                                rule_severity = ?rule.meta().severity,
                                shell = %ctx.shell_path,
                                input_len = data_str.len(),
                                input_preview = %truncate_for_log(data_str, 200),
                                error = %err,
                                error_debug = ?err,
                                "rule evaluate failed"
                            );
                        }
                        Err(_) => { // Timeout Error
                            tracing::warn!(
                                target: "security::detect",
                                rule_name = %rule.meta().name,
                                rule_severity = ?rule.meta().severity,
                                shell = %ctx.shell_path,
                                input_len = data_str.len(),
                                input_preview = %truncate_for_log(data_str, 200),
                                "rule evaluate timed out after {:?}", rule_timeout
                            );
                        }
                    }
                }
                Err(join_err) => {
                    if join_err.is_panic() {
                        tracing::error!("Rule evaluation task panicked: {}", join_err);
                    }
                }
            }

            if let Some(rule) = rules_iter.next() {
                spawn_rule(&mut set, rule, Arc::clone(&data_arc), Arc::clone(ctx));
            }
        }

        ctx.push_history(data).await;

        if !hits.is_empty() {
            DetectResult::ThreatDetected(hits)
        } else if evaluated == 0 {
            DetectResult::Unknown
        } else {
            DetectResult::Safe
        }
    }
}