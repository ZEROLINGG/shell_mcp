use crate::security::detect::{Rule, Severity};
use std::sync::Arc;
use crate::sec_bash_detector_rule_impl_base;
use crate::security::detect::bash::ast::detect_remote_execution;
use crate::security::utils::{url_analyze, UrlAnalysisResult};

sec_bash_detector_rule_impl_base!(
    RuleBashTcpUdpReverseShell1,
    name: "bash_tcp_udp_reverse_shell_1",
    desc: "Detects reverse shell attempts using /dev/tcp or /dev/udp redirections",
    severity: Severity::Critical,
    query: "(file_redirect destination: (word) @dest (#match? @dest \"^/dev/(tcp|udp)/(.*)\"))",
    capture: |node, source| {
        let evidence = node.utf8_text(source)?;
        Ok(Some(format!("Matched redirection: {}", evidence)))
    }
);
const REMOTE_EXEC_QUERY: &str = r#"
[
  (pipeline) @target
  (command) @target
]
"#;

sec_bash_detector_rule_impl_base!(
    RuleRemoteExecHigh,
    name: "remote_execution_direct_ip",
    desc: "Detects remote execution payload via HTTP Direct IP",
    severity: Severity::High,
    query: REMOTE_EXEC_QUERY,
    capture: |node, source| {
        if let Some(url) = detect_remote_execution(node, source) {
            if let Ok(UrlAnalysisResult::HttpIp) = url_analyze(&url) {
                return Ok(Some(format!("High threat download & execute: {}", url)));
            }
        }
        Ok(None)
    }
);
sec_bash_detector_rule_impl_base!(
    RuleRemoteExecMedium,
    name: "remote_execution_http_domain",
    desc: "Detects remote execution payload via HTTP Domain",
    severity: Severity::Medium,
    query: REMOTE_EXEC_QUERY,
    capture: |node, source| {
        if let Some(url) = detect_remote_execution(node, source) {
            if let Ok(UrlAnalysisResult::HttpDomain) = url_analyze(&url) {
                return Ok(Some(format!("Medium threat download & execute: {}", url)));
            }
        }
        Ok(None)
    }
);

sec_bash_detector_rule_impl_base!(
    RuleRemoteExecLow,
    name: "remote_execution_default",
    desc: "Detects remote execution payload (HTTPS or Fallback)",
    severity: Severity::Low,
    query: REMOTE_EXEC_QUERY,
    capture: |node, source| {
        if let Some(url) = detect_remote_execution(node, source) {
            let is_low = match url_analyze(&url) {
                Ok(UrlAnalysisResult::Https) => true,
                _ => false,
            };
            if is_low {
                return Ok(Some(format!("Low threat download & execute: {}", url)));
            }
        }
        Ok(None)
    }
);



/// 集中暴露所有 Bash 规则，供探测器启动时加载
pub fn get_all_rules() -> Vec<Arc<dyn Rule>> {
    vec![
        Arc::new(RuleBashTcpUdpReverseShell1),

        // Remote Execution 规则链
        Arc::new(RuleRemoteExecHigh),   // Direct IP HTTP -> High
        Arc::new(RuleRemoteExecMedium), // Domain HTTP -> Medium
        Arc::new(RuleRemoteExecLow),    // HTTPS/Others -> Low
    ]
}


