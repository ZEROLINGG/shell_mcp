// src/protocol/mod.rs
//! MCP 协议层：请求参数 DTO 与统一响应包装。本模块不依赖任何会话/Shell 内部
//! 细节，只描述“工具调用”的线上数据形状。

pub mod params;
pub mod response;

pub(crate) use response::{err, ok};
