// src/resources.rs
//! `resources/list` 与 `resources/read` 的具体实现，完全从 `docs::ALL`
//! 派生 —— 保证只有一处地方知道“有哪些指南”，不会出现两处列表不同步的问题。

use crate::docs;
use rmcp::model::*;

pub fn list() -> ListResourcesResult {
    ListResourcesResult {
        resources: docs::ALL.iter().map(|g| Resource::new(g.uri, g.name)).collect(),
        next_cursor: None,
        meta: None,
    }
}

pub fn read(uri: &str) -> Result<ReadResourceResult, rmcp::ErrorData> {
    docs::find(uri)
        .map(|text| ReadResourceResult::new(vec![ResourceContents::text(text, uri)]))
        .ok_or_else(|| {
            rmcp::ErrorData::resource_not_found(
                "resource_not_found",
                Some(serde_json::json!({ "uri": uri })),
            )
        })
}