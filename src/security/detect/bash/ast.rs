use std::sync::LazyLock;
use tokio::sync::{Mutex, RwLock};
use tree_sitter::{Language, Node, Parser, Query, QueryCursor, QueryMatch, Tree};
use crate::security::utils::{node_extract_text, process_is_downloader, shell_is_unix};

pub fn language() -> Language {
    tree_sitter_bash::language()
}

pub struct CommittedBlock {
    pub source: String,
    pub tree: Tree,
    pub is_heredoc_body: bool,
    pub fragment_count: usize,
}

pub struct BashAstState {
    parser: Mutex<Parser>,
    pending: RwLock<String>,
    fragment_counter: RwLock<usize>,
    max_pending_bytes: usize,
}

impl BashAstState {
    pub fn new(max_pending_bytes: usize) -> Self {
        let mut parser = Parser::new();
        parser.set_language(language()).expect("Error loading Bash grammar");
        Self {
            parser: Mutex::new(parser),
            pending: RwLock::new(String::new()),
            fragment_counter: RwLock::new(0),
            max_pending_bytes,
        }
    }

    pub async fn push_and_commit(&self, data: &str) -> Vec<CommittedBlock> {
        let mut buf = self.pending.write().await;
        buf.push_str(data);

        let mut frag = self.fragment_counter.write().await;
        *frag += 1;

        if buf.len() > self.max_pending_bytes {
            if let Some(idx) = buf.rfind('\n') {
                let forced: String = buf.drain(..=idx).collect();
                tracing::warn!(command = %forced, "bash pending buffer overflow, forced flush");
            } else {
                buf.clear();
            }
            *frag = 0;
            return Vec::new();
        }

        if !buf.ends_with('\n') || ends_with_line_continuation(&buf) || ends_with_dangling_operator(&buf) {
            return Vec::new();
        }

        let mut parser = self.parser.lock().await;
        let Some(tree) = parser.parse(buf.as_str(), None) else { return Vec::new() };
        if tree.root_node().has_error() {
            return Vec::new();
        }

        let source = std::mem::take(&mut *buf);
        let fragment_count = std::mem::replace(&mut *frag, 0);

        let mut blocks: Vec<CommittedBlock> = extract_heredoc_bodies(&tree, source.as_bytes())
            .into_iter()
            .filter_map(|body| {
                parser.parse(&body, None).map(|t| CommittedBlock {
                    source: body, tree: t, is_heredoc_body: true, fragment_count: 0,
                })
            })
            .collect();

        blocks.push(CommittedBlock { source, tree, is_heredoc_body: false, fragment_count });
        blocks
    }
}

fn ends_with_line_continuation(buf: &str) -> bool {
    let line = buf.strip_suffix('\n').unwrap_or(buf);
    line.chars().rev().take_while(|&c| c == '\\').count() % 2 == 1
}

fn ends_with_dangling_operator(buf: &str) -> bool {
    let line = buf.trim_end_matches('\n').trim_end();
    line.ends_with('|') || line.ends_with("&&") || line.ends_with("||")
        || (line.ends_with('&') && !line.ends_with("&&"))
}

fn extract_heredoc_bodies(tree: &Tree, source: &[u8]) -> Vec<String> {
    static QUERY: LazyLock<Query> =
        LazyLock::new(|| Query::new(language(), "(heredoc_body) @body").expect("invalid query"));
    let mut cursor = QueryCursor::new();
    cursor.matches(&QUERY, tree.root_node(), source)
        .filter_map(|m| m.captures.first().map(|c| c.node))
        .filter_map(|n| n.utf8_text(source).ok().map(String::from))
        .collect()
}

pub struct CurrentAst {
    pub blocks: RwLock<Vec<CommittedBlock>>,
}

impl CurrentAst {
    pub fn new() -> Self { Self { blocks: RwLock::new(Vec::new()) } }
}


/// 按 capture 名称取节点，避免位置错位导致的 bug
pub fn capture_by_name<'a>(query: &Query, m: &QueryMatch<'a, 'a>, name: &str) -> Option<Node<'a>> {
    let idx = query.capture_index_for_name(name)?;
    m.captures.iter().find(|c| c.index == idx).map(|c| c.node)
}

/// 一次性把所有具名 capture 收集成 map，方便多 capture 关联判断
pub fn captures_map<'a>(
    query: &Query,
    m: &QueryMatch<'a, 'a>,
) -> std::collections::HashMap<String, Node<'a>> {
    let names = query.capture_names();

    m.captures
        .iter()
        .map(|c| (names[c.index as usize].clone(), c.node))
        .collect()
}

/// 提取命令节点的名字（跳过参数，处理嵌套）
pub fn get_command_name<'a>(node: &Node, source: &'a [u8]) -> Option<&'a str> {
    if node.kind() != "command" { return None; }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "command_name" {
            // 继续向下找具体的 word (跳过可能存在的语法包装)
            let mut wc = child.walk();
            for w in child.children(&mut wc) {
                if w.kind() == "word" || w.kind() == "string" {
                    return node_extract_text(&w, source);
                }
            }
            // Fallback 到 command_name 自身
            return node_extract_text(&child, source);
        }
    }
    None
}

/// 在节点树中 DFS 寻找下载器命令，并提取其中的 URL
pub fn extract_downloader_url(node: &Node, source: &[u8]) -> Option<String> {
    let mut stack = vec![*node];

    while let Some(n) = stack.pop() {
        if n.kind() == "command" {
            if let Some(cmd_name) = get_command_name(&n, source) {
                if process_is_downloader(cmd_name) {
                    // 找到了下载器，遍历其同级节点寻找 URL 参数
                    let mut arg_cursor = n.walk();
                    for child in n.children(&mut arg_cursor) {
                        if child.kind() == "word" || child.kind() == "string" {
                            if let Some(text) = node_extract_text(&child, source) {
                                // 清理两端的引号
                                let cleaned = text.trim_matches(|c| c == '\'' || c == '"');
                                if cleaned.starts_with("http://") || cleaned.starts_with("https://") {
                                    return Some(cleaned.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

pub fn detect_remote_execution(node: &Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "pipeline" => {
            // 场景 1: curl xxx | base64 -d | bash
            let mut cursor = node.walk();
            let mut commands = Vec::new();
            for child in node.children(&mut cursor) {
                // 仅收录管道顶层参与流转的命令或子 shell
                if child.kind() == "command" || child.kind() == "subshell" {
                    commands.push(child);
                }
            }

            if commands.len() >= 2 {
                let last_cmd = commands.last().unwrap();
                // 检查最终接收流的是否为 shell (Sink点)
                if let Some(last_name) = get_command_name(last_cmd, source) {
                    if shell_is_unix(last_name) {
                        // 忽略中间管道，从上游寻找下载器 (Source点)
                        for cmd in commands.iter().take(commands.len() - 1) {
                            if let Some(url) = extract_downloader_url(cmd, source) {
                                return Some(url);
                            }
                        }
                    }
                }
            }
        }
        "command" => {
            // 场景 2: bash <(curl xxx) 或 bash -c "$(curl xxx)"
            if let Some(cmd_name) = get_command_name(node, source) {
                if shell_is_unix(cmd_name) {
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        // 检索参数中是否包含了进程替换或命令替换
                        if child.kind() == "process_substitution" ||
                            child.kind() == "command_substitution" ||
                            child.kind() == "string"
                        {
                            if let Some(url) = extract_downloader_url(&child, source) {
                                return Some(url);
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    None
}