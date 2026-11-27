//! Whether a tool-policy profile applies its block and rewrite rules or only
//! records them: the profile's own value, resolved once per config snapshot.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What a tool-policy profile does with a `block` or `replace` rule that
/// matches. `classify`, `substitute` and `intercept_only` act the same in both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolEnforcement {
    /// A block refuses or removes, a rewrite rewrites.
    Enforce,
    /// The request and the answer go on as sent; what a block or a rewrite
    /// would have done is recorded on the audit row as not applied.
    Observe,
}

impl ToolEnforcement {
    /// The stored spelling — the `serde` one, and what the
    /// `profiles.tool_enforcement` CHECK accepts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Observe => "observe",
        }
    }

    /// The inverse of [`Self::as_str`]; `None` for any other text.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "enforce" => Some(Self::Enforce),
            "observe" => Some(Self::Observe),
            _ => None,
        }
    }

    pub fn observes(self) -> bool {
        self == Self::Observe
    }
}

/// The mode a tool profile runs in. A Layered profile with no value of its own
/// follows the Default; the Default or a Standalone profile with no value
/// observes, and never follows anything. A tool policy enforces only once an
/// administrator said so.
pub fn resolve(own: Option<ToolEnforcement>, layered: bool, default_mode: Option<ToolEnforcement>) -> ToolEnforcement {
    match own {
        Some(mode) => mode,
        None if layered => default_mode.unwrap_or(ToolEnforcement::Observe),
        None => ToolEnforcement::Observe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_mode_resolves_layered_to_the_default_and_null_to_observe() {
        use ToolEnforcement::{Enforce, Observe};
        // Its own value always wins, Layered or not.
        for layered in [false, true] {
            for default_mode in [None, Some(Enforce), Some(Observe)] {
                assert_eq!(resolve(Some(Observe), layered, default_mode), Observe);
                assert_eq!(resolve(Some(Enforce), layered, default_mode), Enforce);
            }
        }
        // A Layered profile follows the Default, whose missing value observes.
        assert_eq!(resolve(None, true, Some(Observe)), Observe);
        assert_eq!(resolve(None, true, Some(Enforce)), Enforce);
        assert_eq!(resolve(None, true, None), Observe);
        // The Default or a Standalone with no value observes, and never follows.
        assert_eq!(resolve(None, false, Some(Enforce)), Observe);
        assert_eq!(resolve(None, false, None), Observe);
    }

    #[test]
    fn the_stored_spelling_round_trips() {
        for mode in [ToolEnforcement::Enforce, ToolEnforcement::Observe] {
            assert_eq!(ToolEnforcement::parse(mode.as_str()), Some(mode));
            assert_eq!(serde_json::to_value(mode).unwrap(), serde_json::json!(mode.as_str()));
        }
        assert_eq!(ToolEnforcement::parse("Observe"), None);
    }
}
