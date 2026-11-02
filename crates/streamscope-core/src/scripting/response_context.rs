//! ResponseBlockContext — the Rhai-visible data model for response-phase scripts.
//!
//! Operates on individual content blocks (text, tool_use, thinking) from the
//! response stream. Mirrors the `RequestContext` pattern with scope projection
//! and merge for enforced isolation.

use std::collections::HashMap;

use rhai::Dynamic;

/// The Rhai-visible response block context.
#[derive(Debug, Clone)]
pub struct ResponseBlockContext {
    /// Block type: "text", "tool_use", "thinking" (read-only)
    pub block_type: String,
    /// Text or thinking content
    pub content: String,
    /// Tool name (tool_use blocks only)
    pub tool_name: Option<String>,
    /// Tool call ID (read-only)
    pub tool_id: Option<String>,
    /// Tool arguments JSON (tool_use blocks only)
    pub arguments: Option<String>,
    /// Model name (read-only)
    pub model: String,
    /// User ID (read-only)
    pub user_id: String,
    /// App ID (read-only)
    pub app_id: Option<String>,
    /// API version (read-only)
    pub api_version: String,
    /// Script-writable metadata
    pub metadata: HashMap<String, String>,
    /// Script-writable labels for audit
    pub labels: Vec<String>,
}

impl ResponseBlockContext {
    /// The text a `trigger_regex` fast-find is tested against for a given scope.
    /// `tool`-scope scripts read `arguments`; every other scope reads `content`.
    /// `global` sees both so a global trigger can match either.
    pub fn scope_searchable_text(&self, scope: &str) -> String {
        match scope {
            "tool" => self.arguments.clone().unwrap_or_default(),
            "global" => {
                let mut out = self.content.clone();
                if let Some(args) = &self.arguments {
                    out.push('\n');
                    out.push_str(args);
                }
                out
            }
            _ => self.content.clone(),
        }
    }

    /// Apply a text transform to each writable text field of the given scope, in
    /// place, for span-mode transforms. `tool` scope rewrites `arguments`;
    /// `global` rewrites both `content` and `arguments`; every other scope
    /// rewrites `content`. Mirrors the read scopes of
    /// [`scope_searchable_text`](Self::scope_searchable_text). Returns whether any
    /// field changed; the first `Err` short-circuits for the caller's fail-mode.
    pub fn apply_text_transform<F>(&mut self, scope: &str, mut f: F) -> Result<bool, String>
    where
        F: FnMut(&str) -> Result<Option<String>, String>,
    {
        let mut changed = false;
        let want_content = scope != "tool";
        let want_arguments = scope == "tool" || scope == "global";
        if want_content
            && let Some(new) = f(&self.content)?
        {
            self.content = new;
            changed = true;
        }
        if want_arguments
            && let Some(args) = self.arguments.clone()
            && let Some(new) = f(&args)?
        {
            self.arguments = Some(new);
            changed = true;
        }
        Ok(changed)
    }

    /// Convert to a Rhai `Dynamic` map with all fields.
    pub fn to_dynamic(&self) -> Dynamic {
        let mut map = rhai::Map::new();

        map.insert("block_type".into(), self.block_type.clone().into());
        map.insert("content".into(), self.content.clone().into());
        map.insert(
            "tool_name".into(),
            self.tool_name
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );
        map.insert(
            "tool_id".into(),
            self.tool_id
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );
        map.insert(
            "arguments".into(),
            self.arguments
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );
        map.insert("model".into(), self.model.clone().into());
        map.insert("user_id".into(), self.user_id.clone().into());
        map.insert(
            "app_id".into(),
            self.app_id
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );
        map.insert("api_version".into(), self.api_version.clone().into());

        let meta: rhai::Map = self
            .metadata
            .iter()
            .map(|(k, v)| (k.clone().into(), Dynamic::from(v.clone())))
            .collect();
        map.insert("metadata".into(), Dynamic::from_map(meta));

        let labels: rhai::Array = self.labels.iter().map(|l| Dynamic::from(l.clone())).collect();
        map.insert("labels".into(), Dynamic::from_array(labels));

        Dynamic::from_map(map)
    }

    /// Convert from a Rhai `Dynamic` map back to ResponseBlockContext.
    pub fn from_dynamic(val: &Dynamic) -> Option<Self> {
        let map = val.read_lock::<rhai::Map>()?;

        let block_type = map
            .get("block_type")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_default();

        let content = map
            .get("content")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_default();

        let tool_name = map.get("tool_name").and_then(|v| {
            if v.is_unit() {
                None
            } else {
                v.clone().into_string().ok()
            }
        });

        let tool_id = map.get("tool_id").and_then(|v| {
            if v.is_unit() {
                None
            } else {
                v.clone().into_string().ok()
            }
        });

        let arguments = map.get("arguments").and_then(|v| {
            if v.is_unit() {
                None
            } else {
                v.clone().into_string().ok()
            }
        });

        let model = map
            .get("model")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_default();

        let user_id = map
            .get("user_id")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_default();

        let app_id = map.get("app_id").and_then(|v| {
            if v.is_unit() {
                None
            } else {
                v.clone().into_string().ok()
            }
        });

        let api_version = map
            .get("api_version")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_default();

        let metadata = map
            .get("metadata")
            .and_then(|v| v.read_lock::<rhai::Map>())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.clone().into_string().ok().map(|s| (k.to_string(), s)))
                    .collect()
            })
            .unwrap_or_default();

        let labels = map
            .get("labels")
            .and_then(|v| v.read_lock::<rhai::Array>())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.clone().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();

        Some(Self {
            block_type,
            content,
            tool_name,
            tool_id,
            arguments,
            model,
            user_id,
            app_id,
            api_version,
            metadata,
            labels,
        })
    }

    /// Build a projected Dynamic map for a specific response scope.
    ///
    /// - `"global"`: all fields, writable fields depend on block type
    /// - `"text"`: content + metadata + labels writable; tool fields hidden
    /// - `"tool"`: tool_name + arguments + metadata + labels writable; content hidden
    /// - `"thinking"`: content + metadata + labels writable; tool fields hidden
    pub fn project_for_scope(&self, scope: &str) -> Dynamic {
        let mut map = rhai::Map::new();

        // Read-only context (always included)
        map.insert("block_type".into(), self.block_type.clone().into());
        map.insert("model".into(), self.model.clone().into());
        map.insert("user_id".into(), self.user_id.clone().into());
        map.insert(
            "app_id".into(),
            self.app_id
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );
        map.insert("api_version".into(), self.api_version.clone().into());
        map.insert(
            "tool_id".into(),
            self.tool_id
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );

        // Metadata and labels (always writable)
        let meta: rhai::Map = self
            .metadata
            .iter()
            .map(|(k, v)| (k.clone().into(), Dynamic::from(v.clone())))
            .collect();
        map.insert("metadata".into(), Dynamic::from_map(meta));
        let labels: rhai::Array = self.labels.iter().map(|l| Dynamic::from(l.clone())).collect();
        map.insert("labels".into(), Dynamic::from_array(labels));

        match scope {
            "global" => {
                // All fields visible — writable fields depend on block type
                map.insert("content".into(), self.content.clone().into());
                map.insert(
                    "tool_name".into(),
                    self.tool_name
                        .as_ref()
                        .map_or(Dynamic::UNIT, |s| s.clone().into()),
                );
                map.insert(
                    "arguments".into(),
                    self.arguments
                        .as_ref()
                        .map_or(Dynamic::UNIT, |s| s.clone().into()),
                );
            }
            "text" | "thinking" => {
                // Content writable, tool fields hidden
                map.insert("content".into(), self.content.clone().into());
                // tool_name and arguments set to unit (hidden)
                map.insert("tool_name".into(), Dynamic::UNIT);
                map.insert("arguments".into(), Dynamic::UNIT);
            }
            "tool" => {
                // tool_name + arguments writable, content hidden
                map.insert("content".into(), Dynamic::UNIT);
                map.insert(
                    "tool_name".into(),
                    self.tool_name
                        .as_ref()
                        .map_or(Dynamic::UNIT, |s| s.clone().into()),
                );
                map.insert(
                    "arguments".into(),
                    self.arguments
                        .as_ref()
                        .map_or(Dynamic::UNIT, |s| s.clone().into()),
                );
            }
            _ => {
                // Unknown scope — treat as global
                return self.to_dynamic();
            }
        }

        Dynamic::from_map(map)
    }

    /// Merge writable fields from a scoped execution result back into this context.
    ///
    /// Only fields writable for the given scope + block type are read back.
    pub fn merge_from_scope(&mut self, scope: &str, result: &Dynamic) {
        let Some(map) = result.read_lock::<rhai::Map>() else {
            return;
        };

        // Always merge metadata and labels
        if let Some(meta) = map.get("metadata").and_then(|v| v.read_lock::<rhai::Map>()) {
            self.metadata = meta
                .iter()
                .filter_map(|(k, v)| v.clone().into_string().ok().map(|s| (k.to_string(), s)))
                .collect();
        }
        if let Some(arr) = map.get("labels").and_then(|v| v.read_lock::<rhai::Array>()) {
            self.labels = arr
                .iter()
                .filter_map(|v| v.clone().into_string().ok())
                .collect();
        }

        match scope {
            "global" => {
                // Writable fields depend on block type
                match self.block_type.as_str() {
                    "text" | "thinking" => {
                        if let Some(content) =
                            map.get("content").and_then(|v| v.clone().into_string().ok())
                        {
                            self.content = content;
                        }
                    }
                    "tool_use" => {
                        self.tool_name = map.get("tool_name").and_then(|v| {
                            if v.is_unit() {
                                None
                            } else {
                                v.clone().into_string().ok()
                            }
                        });
                        self.arguments = map.get("arguments").and_then(|v| {
                            if v.is_unit() {
                                None
                            } else {
                                v.clone().into_string().ok()
                            }
                        });
                    }
                    _ => {}
                }
            }
            "text" | "thinking" => {
                if let Some(content) =
                    map.get("content").and_then(|v| v.clone().into_string().ok())
                {
                    self.content = content;
                }
            }
            "tool" => {
                self.tool_name = map.get("tool_name").and_then(|v| {
                    if v.is_unit() {
                        None
                    } else {
                        v.clone().into_string().ok()
                    }
                });
                self.arguments = map.get("arguments").and_then(|v| {
                    if v.is_unit() {
                        None
                    } else {
                        v.clone().into_string().ok()
                    }
                });
            }
            _ => {
                // Unknown scope — merge all writable fields
                if let Some(full) = ResponseBlockContext::from_dynamic(result) {
                    self.content = full.content;
                    self.tool_name = full.tool_name;
                    self.arguments = full.arguments;
                    self.metadata = full.metadata;
                    self.labels = full.labels;
                }
            }
        }
    }

    /// Returns true if the block was modified compared to original values.
    pub fn was_modified(&self, original: &ResponseBlockContext) -> bool {
        self.content != original.content
            || self.tool_name != original.tool_name
            || self.arguments != original.arguments
    }
}

/// Does the given scope match the block type?
/// - `"global"` matches all block types
/// - `"text"` matches only `"text"` blocks
/// - `"tool"` matches only `"tool_use"` blocks
/// - `"thinking"` matches only `"thinking"` blocks
pub fn scope_matches_block_type(scope: &str, block_type: &str) -> bool {
    match scope {
        "global" => true,
        "text" => block_type == "text",
        "tool" => block_type == "tool_use",
        "thinking" => block_type == "thinking",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_text_ctx() -> ResponseBlockContext {
        ResponseBlockContext {
            block_type: "text".to_string(),
            content: "Hello world".to_string(),
            tool_name: None,
            tool_id: None,
            arguments: None,
            model: "gpt-4o".to_string(),
            user_id: "user-123".to_string(),
            app_id: Some("test-app".to_string()),
            api_version: "chat_completions".to_string(),
            metadata: HashMap::new(),
            labels: vec![],
        }
    }

    fn sample_tool_ctx() -> ResponseBlockContext {
        ResponseBlockContext {
            block_type: "tool_use".to_string(),
            content: String::new(),
            tool_name: Some("Bash".to_string()),
            tool_id: Some("call_123".to_string()),
            arguments: Some(r#"{"command":"ls"}"#.to_string()),
            model: "gpt-4o".to_string(),
            user_id: "user-123".to_string(),
            app_id: Some("test-app".to_string()),
            api_version: "chat_completions".to_string(),
            metadata: HashMap::new(),
            labels: vec![],
        }
    }

    fn sample_thinking_ctx() -> ResponseBlockContext {
        ResponseBlockContext {
            block_type: "thinking".to_string(),
            content: "Let me think about this...".to_string(),
            tool_name: None,
            tool_id: None,
            arguments: None,
            model: "gpt-4o".to_string(),
            user_id: "user-123".to_string(),
            app_id: None,
            api_version: "chat_completions".to_string(),
            metadata: HashMap::new(),
            labels: vec![],
        }
    }

    #[test]
    fn roundtrip_text_block() {
        let ctx = sample_text_ctx();
        let dyn_val = ctx.to_dynamic();
        let restored = ResponseBlockContext::from_dynamic(&dyn_val).unwrap();
        assert_eq!(restored.block_type, "text");
        assert_eq!(restored.content, "Hello world");
        assert!(restored.tool_name.is_none());
        assert_eq!(restored.model, "gpt-4o");
        assert_eq!(restored.user_id, "user-123");
        assert_eq!(restored.app_id.as_deref(), Some("test-app"));
    }

    #[test]
    fn roundtrip_tool_block() {
        let ctx = sample_tool_ctx();
        let dyn_val = ctx.to_dynamic();
        let restored = ResponseBlockContext::from_dynamic(&dyn_val).unwrap();
        assert_eq!(restored.block_type, "tool_use");
        assert_eq!(restored.tool_name.as_deref(), Some("Bash"));
        assert_eq!(restored.tool_id.as_deref(), Some("call_123"));
        assert!(restored.arguments.as_ref().unwrap().contains("ls"));
    }

    #[test]
    fn text_scope_hides_tool_fields() {
        let ctx = sample_tool_ctx();
        let projected = ctx.project_for_scope("text");
        let map = projected.read_lock::<rhai::Map>().unwrap();
        // tool fields should be unit
        assert!(map.get("tool_name").unwrap().is_unit());
        assert!(map.get("arguments").unwrap().is_unit());
        // content should be visible
        assert!(map.contains_key("content"));
    }

    #[test]
    fn tool_scope_hides_content() {
        let ctx = sample_text_ctx();
        let projected = ctx.project_for_scope("tool");
        let map = projected.read_lock::<rhai::Map>().unwrap();
        // content should be unit
        assert!(map.get("content").unwrap().is_unit());
        // tool_name should be visible (unit because text block has no tool_name)
        assert!(map.contains_key("tool_name"));
    }

    #[test]
    fn global_scope_shows_all_fields() {
        let ctx = sample_tool_ctx();
        let projected = ctx.project_for_scope("global");
        let map = projected.read_lock::<rhai::Map>().unwrap();
        assert!(!map.get("tool_name").unwrap().is_unit());
        assert!(!map.get("arguments").unwrap().is_unit());
        assert_eq!(
            map.get("block_type")
                .unwrap()
                .clone()
                .into_string()
                .unwrap(),
            "tool_use"
        );
    }

    #[test]
    fn merge_text_scope_updates_content() {
        let mut ctx = sample_text_ctx();
        let mut projected = ctx.project_for_scope("text");
        {
            let mut map = projected.write_lock::<rhai::Map>().unwrap();
            map.insert("content".into(), "Modified text".into());
        }
        ctx.merge_from_scope("text", &projected);
        assert_eq!(ctx.content, "Modified text");
    }

    #[test]
    fn merge_tool_scope_updates_tool_fields() {
        let mut ctx = sample_tool_ctx();
        let mut projected = ctx.project_for_scope("tool");
        {
            let mut map = projected.write_lock::<rhai::Map>().unwrap();
            map.insert("tool_name".into(), "Write".into());
            map.insert(
                "arguments".into(),
                r#"{"path":"/tmp/x"}"#.to_string().into(),
            );
        }
        ctx.merge_from_scope("tool", &projected);
        assert_eq!(ctx.tool_name.as_deref(), Some("Write"));
        assert!(ctx.arguments.as_ref().unwrap().contains("/tmp/x"));
        // tool_id should be unchanged (read-only)
        assert_eq!(ctx.tool_id.as_deref(), Some("call_123"));
    }

    #[test]
    fn merge_text_scope_does_not_affect_tool_fields() {
        let mut ctx = sample_tool_ctx();
        let original_tool = ctx.tool_name.clone();
        let original_args = ctx.arguments.clone();
        let projected = ctx.project_for_scope("text");
        ctx.merge_from_scope("text", &projected);
        // Tool fields preserved
        assert_eq!(ctx.tool_name, original_tool);
        assert_eq!(ctx.arguments, original_args);
    }

    #[test]
    fn merge_global_scope_text_block() {
        let mut ctx = sample_text_ctx();
        let mut projected = ctx.project_for_scope("global");
        {
            let mut map = projected.write_lock::<rhai::Map>().unwrap();
            map.insert("content".into(), "New content".into());
        }
        ctx.merge_from_scope("global", &projected);
        assert_eq!(ctx.content, "New content");
    }

    #[test]
    fn merge_global_scope_tool_block() {
        let mut ctx = sample_tool_ctx();
        let mut projected = ctx.project_for_scope("global");
        {
            let mut map = projected.write_lock::<rhai::Map>().unwrap();
            map.insert("tool_name".into(), "Read".into());
        }
        ctx.merge_from_scope("global", &projected);
        assert_eq!(ctx.tool_name.as_deref(), Some("Read"));
    }

    #[test]
    fn labels_are_always_merged() {
        let mut ctx = sample_text_ctx();
        let mut projected = ctx.project_for_scope("text");
        {
            let mut map = projected.write_lock::<rhai::Map>().unwrap();
            let labels = vec![Dynamic::from("pii_redacted".to_string())];
            map.insert("labels".into(), Dynamic::from_array(labels));
        }
        ctx.merge_from_scope("text", &projected);
        assert_eq!(ctx.labels, vec!["pii_redacted"]);
    }

    #[test]
    fn metadata_is_always_merged() {
        let mut ctx = sample_text_ctx();
        let mut projected = ctx.project_for_scope("tool");
        {
            let mut map = projected.write_lock::<rhai::Map>().unwrap();
            let mut meta = rhai::Map::new();
            meta.insert("key".into(), "value".into());
            map.insert("metadata".into(), Dynamic::from_map(meta));
        }
        ctx.merge_from_scope("tool", &projected);
        assert_eq!(ctx.metadata.get("key").unwrap(), "value");
    }

    #[test]
    fn was_modified_detects_content_change() {
        let original = sample_text_ctx();
        let mut modified = original.clone();
        modified.content = "Changed".to_string();
        assert!(modified.was_modified(&original));
    }

    #[test]
    fn was_modified_false_when_unchanged() {
        let original = sample_text_ctx();
        let same = original.clone();
        assert!(!same.was_modified(&original));
    }

    #[test]
    fn scope_matches_block_type_works() {
        assert!(scope_matches_block_type("global", "text"));
        assert!(scope_matches_block_type("global", "tool_use"));
        assert!(scope_matches_block_type("global", "thinking"));
        assert!(scope_matches_block_type("text", "text"));
        assert!(!scope_matches_block_type("text", "tool_use"));
        assert!(!scope_matches_block_type("text", "thinking"));
        assert!(scope_matches_block_type("tool", "tool_use"));
        assert!(!scope_matches_block_type("tool", "text"));
        assert!(scope_matches_block_type("thinking", "thinking"));
        assert!(!scope_matches_block_type("thinking", "text"));
    }

    #[test]
    fn thinking_scope_projection_roundtrip() {
        let mut ctx = sample_thinking_ctx();
        let mut projected = ctx.project_for_scope("thinking");
        {
            let mut map = projected.write_lock::<rhai::Map>().unwrap();
            map.insert("content".into(), "Redacted thinking".into());
        }
        ctx.merge_from_scope("thinking", &projected);
        assert_eq!(ctx.content, "Redacted thinking");
    }
}
