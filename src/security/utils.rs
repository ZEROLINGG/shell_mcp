#![allow(unused)]
use anyhow::{anyhow, Result};
use std::net::IpAddr;
use std::path::Path;
use tree_sitter::Node;
use crate::lazy_regex;

lazy_regex!(pub NAME_CLEAN_REGEX = r"[\d.].*$");

/// 从 AST 节点中提取文本
pub fn node_extract_text<'a>(node: &Node, source: &'a [u8]) -> Option<&'a str> {
    node.utf8_text(source).ok()
}


/// 对 Shell/程序路径名称进行归一化处理
pub fn name_normalize(shell: &str) -> Result<String> {
    let name = Path::new(shell)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("invalid shell path: {}", shell))?
        .to_lowercase();

    Ok(NAME_CLEAN_REGEX.replace(&name, "").into_owned())
}

/// 判断名称是否为 Unix Shell
pub fn shell_is_unix(name: &str) -> bool {
    if let Ok(sh) = name_normalize(name) {
        return matches!(sh.as_str(), "bash" | "sh" | "zsh" | "fish" | "ksh");
    }
    false
}

/// 判断名称是否为 Windows Shell
pub fn shell_is_win(name: &str) -> bool {
    if let Ok(sh) = name_normalize(name) {
        return matches!(sh.as_str(), "powershell" | "pwsh" | "cmd");
    }
    false
}

/// 判断名称是否为广义的 Shell / 脚本解释器
pub fn shell_is_valid(name: &str) -> bool {
    if shell_is_unix(name) || shell_is_win(name) {
        return true;
    }
    if let Ok(sh) = name_normalize(name) {
        return matches!(sh.as_str(), "node" | "python");
    }
    false
}

/// 判断名称是否为下载工具
pub fn process_is_downloader(name: &str) -> bool {
    if let Ok(p) = name_normalize(name) {
        return matches!(p.as_str(), "curl" | "wget" | "fetch");
    }
    false
}

pub enum UrlAnalysisResult {
    Https,
    HttpDomain,
    HttpIp,
}

/// 分析 URL 类型
pub fn url_analyze(url: &str) -> Result<UrlAnalysisResult> {
    let url = url::Url::parse(url)?;

    match url.scheme() {
        "https" => Ok(UrlAnalysisResult::Https),
        "http" => match url.host() {
            Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => Ok(UrlAnalysisResult::HttpIp),
            Some(url::Host::Domain(_)) => Ok(UrlAnalysisResult::HttpDomain),
            None => Err(anyhow!("missing host")),
        },
        s => Err(anyhow!("unsupported scheme: {}", s)),
    }
}