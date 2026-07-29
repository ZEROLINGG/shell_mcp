// src/server_handler.rs
use crate::{docs, resources, service::TerminalMcpService};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, model::*, prompt_handler,
    service::RequestContext, tool_handler,
};

#[tool_handler(router = self.tool_router.clone())]
#[prompt_handler(router = self.prompt_router.clone())]
impl ServerHandler for TerminalMcpService {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        );
        info.instructions = Some(docs::QUICK_START.to_string());
        info
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListResourcesResult, McpError> {
        Ok(resources::list())
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<ReadResourceResult, McpError> {
        resources::read(&request.uri)
    }
}