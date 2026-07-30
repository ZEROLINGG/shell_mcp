pub mod macros;
pub mod ast;
pub mod rules;
mod tests;
mod deobf;

use crate::security::detect::{Detector, Rule, ShellContext};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

use self::ast::{BashAstState, CurrentAst};

pub struct BashDetector {
    ctx: Arc<ShellContext>,
    rules: Vec<Arc<dyn Rule>>,
}

impl BashDetector {
    pub fn new(mut ctx: ShellContext, max_pending_bytes: usize) -> Self {
        ctx.extensions.insert(BashAstState::new(max_pending_bytes));
        ctx.extensions.insert(CurrentAst::new());

        let ctx = Arc::new(ctx);
        Self {
            ctx,
            rules: rules::get_all_rules(),
        }
    }
}

#[async_trait]
impl Detector for BashDetector {
    fn context(&self) -> &Arc<ShellContext> { &self.ctx }
    fn rules(&self) -> &[Arc<dyn Rule>] { &self.rules }

    async fn on_detect(&self, data: &str) -> Result<()> {
        let state = self.ctx.extensions.get::<BashAstState>()
            .ok_or_else(|| anyhow::anyhow!("BashAstState missing"))?;
        let blocks = state.push_and_commit(data).await;

        let current = self.ctx.extensions.get::<CurrentAst>()
            .ok_or_else(|| anyhow::anyhow!("CurrentAst missing"))?;
        *current.blocks.write().await = blocks;

        Ok(())
    }
}