#[macro_export]
macro_rules! sec_bash_detector_rule_metadata {
    ($name:expr, $desc:expr, $severity:expr) => {
        fn get_meta() -> &'static crate::security::detect::RuleMetadata {
            static META: std::sync::LazyLock<crate::security::detect::RuleMetadata> =
                std::sync::LazyLock::new(|| {
                    crate::security::detect::RuleMetadata {
                        name: $name.to_string(),
                        description: $desc.to_string(),
                        severity: $severity,
                    }
                });
            &META
        }
    };
}
#[macro_export]
macro_rules! sec_bash_detector_rule_query {
    ($rule_name:ident, $query:expr) => {
        fn get_query() -> &'static tree_sitter::Query {
            static QUERY: std::sync::LazyLock<tree_sitter::Query> =
                std::sync::LazyLock::new(|| {
                    tree_sitter::Query::new(tree_sitter_bash::language(), $query)
                        .expect(concat!("Invalid query for ", stringify!($rule_name)))
                });
            &QUERY
        }
    };
}



#[macro_export]
macro_rules! sec_bash_detector_rule_impl_base {
    ($rule_name:ident, name: $name:expr, desc: $desc:expr, severity: $severity:expr,
     query: $query:expr, capture: $capture_logic:expr) => {
        pub struct $rule_name;

        impl $rule_name {
            $crate::sec_bash_detector_rule_query!($rule_name, $query);
            $crate::sec_bash_detector_rule_metadata!($name, $desc, $severity);
        }

        #[async_trait::async_trait]
        impl crate::security::detect::Rule for $rule_name {
            fn meta(&self) -> &crate::security::detect::RuleMetadata {
                Self::get_meta()
            }

            async fn evaluate(&self, _data: &str, ctx: &crate::security::detect::ShellContext)
                -> anyhow::Result<crate::security::detect::EvaluateResult>
            {
                let current = ctx.extensions
                    .get::<crate::security::detect::bash::ast::CurrentAst>()
                    .ok_or_else(|| anyhow::anyhow!("CurrentAst missing"))?;
                let blocks = current.blocks.read().await;

                for block in blocks.iter() {
                    let mut cursor = tree_sitter::QueryCursor::new();
                    let source_bytes = block.source.as_bytes();

                    for m in cursor.matches(Self::get_query(), block.tree.root_node(), source_bytes) {
                        for capture in m.captures {
                            let logic: fn(&tree_sitter::Node, &[u8])
                                -> anyhow::Result<Option<String>> = $capture_logic;
                            if let Some(evidence) = logic(&capture.node, source_bytes)? {
                                return Ok(crate::security::detect::EvaluateResult::Hit(
                                    Some(evidence)
                                ));
                            }
                        }
                    }
                }
                Ok(crate::security::detect::EvaluateResult::Miss)
            }
        }
    };
}

#[macro_export]
macro_rules! sec_bash_detector_rule_impl_multi_capture {
    ($rule_name:ident, name: $name:expr, desc: $desc:expr, severity: $severity:expr,
     query: $query:expr, logic: $logic:expr) => {
        pub struct $rule_name;

        impl $rule_name {
            $crate::sec_bash_detector_rule_query!($rule_name, $query);
            $crate::sec_bash_detector_rule_metadata!($name, $desc, $severity);
        }

        #[async_trait::async_trait]
        impl crate::security::detect::Rule for $rule_name {
            fn meta(&self) -> &crate::security::detect::RuleMetadata {
                Self::get_meta()
            }

            async fn evaluate(&self, _data: &str, ctx: &crate::security::detect::ShellContext)
                -> anyhow::Result<crate::security::detect::EvaluateResult>
            {
                let current = ctx.extensions
                    .get::<crate::security::detect::bash::ast::CurrentAst>()
                    .ok_or_else(|| anyhow::anyhow!("CurrentAst missing"))?;
                let blocks = current.blocks.read().await;
                let query = Self::get_query();

                for block in blocks.iter() {
                    let mut cursor = tree_sitter::QueryCursor::new();
                    let source_bytes = block.source.as_bytes();

                    for m in cursor.matches(query, block.tree.root_node(), source_bytes) {
                        let caps = crate::security::detect::bash::ast::captures_map(query, &m);
                        let logic: fn(
                            &std::collections::HashMap<String, tree_sitter::Node>,
                            &[u8],
                        ) -> anyhow::Result<Option<String>> = $logic;

                        if let Some(evidence) = logic(&caps, source_bytes)? {
                            return Ok(crate::security::detect::EvaluateResult::Hit(
                                Some(evidence)
                            ));
                        }
                    }
                }
                Ok(crate::security::detect::EvaluateResult::Miss)
            }
        }
    };
}

#[macro_export]
macro_rules! sec_bash_detector_rule_impl_regex_base {
    ($rule_name:ident, name: $name:expr, desc: $desc:expr, severity: $severity:expr,
     regex: $regex:expr) => {
        pub struct $rule_name;

        $crate::lazy_regex!(static RE = $regex);

        impl $rule_name {
            $crate::sec_bash_detector_rule_metadata!($name, $desc, $severity);
        }

        #[async_trait::async_trait]
        impl crate::security::detect::Rule for $rule_name {
            fn meta(&self) -> &crate::security::detect::RuleMetadata {
                Self::get_meta()
            }

            async fn evaluate(&self, data: &str, _ctx: &crate::security::detect::ShellContext)
                -> anyhow::Result<crate::security::detect::EvaluateResult>
            {
                if let Some(mat) = RE.find(data) {
                    Ok(crate::security::detect::EvaluateResult::Hit(
                        Some(mat.as_str().to_string())
                    ))
                } else {
                    Ok(crate::security::detect::EvaluateResult::Miss)
                }
            }
        }
    };
}

