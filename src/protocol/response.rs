// src/protocol/response.rs
//! 所有 MCP 工具调用统一返回的 JSON 信封。

use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ToolResponse<T: Serialize> {
    Ok { data: T },
    Err { message: String },
}

impl<T: Serialize> ToolResponse<T> {
    pub fn ok(data: T) -> String {
        serde_json::to_string(&Self::Ok { data })
            .unwrap_or_else(|e| format!(r#"{{"status":"err","message":"Serialization failed: {e}"}}"#))
    }
}

impl ToolResponse<()> {
    pub fn err(message: impl Into<String>) -> String {
        serde_json::to_string(&ToolResponse::<()>::Err {
            message: message.into(),
        })
            .unwrap_or_else(|e| format!(r#"{{"status":"err","message":"Serialization failed: {e}"}}"#))
    }
}

/// 将成功结果包装成统一的 `{"status":"ok","data":...}`。
macro_rules! ok {
    ($data:expr) => {
        $crate::protocol::response::ToolResponse::ok($data)
    };
}

/// 将错误信息包装成统一的 `{"status":"err","message":...}`。
macro_rules! err {
    ($msg:expr) => {
        $crate::protocol::response::ToolResponse::<()>::err($msg)
    };
}

pub(crate) use err;
pub(crate) use ok;