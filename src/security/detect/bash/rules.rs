// bash/rules.rs

use crate::security::detect::{Rule, Severity, EvaluateResult};
use std::sync::Arc;
use crate::sec_bash_detector_rule_impl_base;
use crate::security::detect::bash::ast::detect_remote_execution;
use crate::security::utils::{url_analyze, UrlAnalysisResult};

sec_bash_detector_rule_impl_base!(
    RuleBashTcpUdpReverseShell1,
    name: "bash_tcp_udp_reverse_shell_1",
    desc: "Detects reverse shell attempts using /dev/tcp or /dev/udp redirections",
    default_severity: Severity::Critical,
    query: "(file_redirect destination: (word) @dest (#match? @dest \"^/dev/(tcp|udp)/(.*)\"))",
    capture: |node, source| {
        let evidence = node.utf8_text(source)?;
        Ok(EvaluateResult::hit(format!("Matched redirection: {}", evidence)))
    }
);



sec_bash_detector_rule_impl_base!(
    RuleRemoteExecution,
    name: "remote_execution",
    desc: "Detects remote execution payload via HTTP/HTTPS/IP",
    default_severity: Severity::Low,
    query: r#"
[
  (pipeline) @target
  (command) @target
]
"#,
    capture: |node, source| {
        if let Some(url) = detect_remote_execution(node, source) {
            match url_analyze(&url) {
                Ok(UrlAnalysisResult::HttpIp) => {
                    // 动态提升为 High
                    return Ok(EvaluateResult::hit_with_severity(
                        format!("High threat download & execute (Direct IP): {}", url),
                        Severity::High,
                    ));
                }
                Ok(UrlAnalysisResult::HttpDomain) => {
                    // 动态提升为 Medium
                    return Ok(EvaluateResult::hit_with_severity(
                        format!("Medium threat download & execute (HTTP Domain): {}", url),
                        Severity::Medium,
                    ));
                }
                Ok(UrlAnalysisResult::Https) => {
                    // 保持 Low 级别 (可以省略 severity 参数，使用默认值)
                    return Ok(EvaluateResult::hit(
                        format!("Low threat download & execute (HTTPS): {}", url)
                    ));
                }
                _ => {}
            }
        }
        // 未命中
        Ok(EvaluateResult::Miss)
    }
);

/// 集中暴露所有 Bash 规则，供探测器启动时加载
pub fn get_all_rules() -> Vec<Arc<dyn Rule>> {
    vec![
        Arc::new(RuleBashTcpUdpReverseShell1),

        Arc::new(RuleRemoteExecution),
    ]
}