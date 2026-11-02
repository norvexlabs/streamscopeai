//! AST cache — compiled Rhai scripts keyed by `"{program_id}:{version_hash}"`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rhai::AST;

/// Cache for compiled Rhai ASTs. Read-lock fast path, write-lock only on miss.
pub struct AstCache {
    entries: RwLock<HashMap<String, Arc<AST>>>,
}

impl Default for AstCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AstCache {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Get a cached AST by key. Returns None on cache miss.
    pub fn get(&self, key: &str) -> Option<Arc<AST>> {
        self.entries
            .read()
            .ok()
            .and_then(|map| map.get(key).cloned())
    }

    /// Insert a compiled AST into the cache.
    pub fn insert(&self, key: String, ast: Arc<AST>) {
        if let Ok(mut map) = self.entries.write() {
            map.insert(key, ast);
        }
    }

    /// Clear all cached ASTs (e.g. on config sync).
    pub fn clear(&self) {
        if let Ok(mut map) = self.entries.write() {
            map.clear();
        }
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.read().map(|m| m.len()).unwrap_or(0)
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_miss_returns_none() {
        let cache = AstCache::new();
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn cache_insert_and_get() {
        let cache = AstCache::new();
        let engine = rhai::Engine::new();
        let ast = engine.compile("fn transform(ctx) { ctx }").unwrap();
        let key = "prog1:v1".to_string();

        cache.insert(key.clone(), Arc::new(ast));
        assert!(cache.get(&key).is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_clear() {
        let cache = AstCache::new();
        let engine = rhai::Engine::new();
        let ast = engine.compile("fn transform(ctx) { ctx }").unwrap();

        cache.insert("a:1".to_string(), Arc::new(ast.clone()));
        cache.insert("b:2".to_string(), Arc::new(ast));
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
