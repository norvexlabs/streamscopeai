//! What the agent loop guard does on a workspace: the tenant default, a
//! workspace's own override, resolved once by the config builder.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What the guard does when a request's history repeats a tool-call cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoopGuardMode {
    /// Nothing: no detection, no badge.
    Off,
    /// Detect and badge only; the request is forwarded as sent.
    #[default]
    Observe,
    /// Observe + append a note to the request telling the model it repeats itself.
    Nudge,
    /// Nudge + at `stop_at`, refuse the model further tool calls for that turn.
    Stop,
}

impl LoopGuardMode {
    /// The stored spelling — the `serde` one, and what the
    /// `workspace_rate_limits.loop_guard_mode` CHECK accepts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Observe => "observe",
            Self::Nudge => "nudge",
            Self::Stop => "stop",
        }
    }

    /// The inverse of [`Self::as_str`]; `None` for any other text.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "observe" => Some(Self::Observe),
            "nudge" => Some(Self::Nudge),
            "stop" => Some(Self::Stop),
            _ => None,
        }
    }
}

/// The guard's mode and its two thresholds, counted in repetitions of the
/// cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LoopGuardSettings {
    pub mode: LoopGuardMode,
    /// Repetitions of the cycle at which the note is added (at least 2).
    pub nudge_at: u32,
    /// Repetitions at which tool calls are refused (at least nudge_at + 2, at most 50).
    pub stop_at: u32,
}

/// The highest `stop_at` a setting may carry.
pub const LOOP_GUARD_MAX_STOP_AT: u32 = 50;

/// A streak of 1 is a step that did not repeat.
pub const LOOP_GUARD_MIN_NUDGE_AT: u32 = 2;

impl Default for LoopGuardSettings {
    fn default() -> Self {
        Self { mode: LoopGuardMode::Observe, nudge_at: 3, stop_at: 8 }
    }
}

impl LoopGuardSettings {
    /// The guard on a workspace that runs none (the Agent workspace).
    pub const OFF: Self = Self { mode: LoopGuardMode::Off, nudge_at: 3, stop_at: 8 };

    /// `Err` names the broken bound; the admin API answers it as a 400.
    ///
    /// The thresholds are checked whatever the mode, so switching an `off` or
    /// `observe` setting to `stop` never activates a pair that was never valid.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.nudge_at < LOOP_GUARD_MIN_NUDGE_AT {
            return Err("nudge_at must be at least 2");
        }
        if self.stop_at < self.nudge_at.saturating_add(2) {
            return Err("stop_at must be at least nudge_at + 2");
        }
        if self.stop_at > LOOP_GUARD_MAX_STOP_AT {
            return Err("stop_at must be at most 50");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(nudge_at: u32, stop_at: u32) -> LoopGuardSettings {
        LoopGuardSettings { mode: LoopGuardMode::Stop, nudge_at, stop_at }
    }

    #[test]
    fn the_defaults_are_valid() {
        assert_eq!(LoopGuardSettings::default().validate(), Ok(()));
        assert_eq!(LoopGuardSettings::OFF.validate(), Ok(()));
        assert_eq!(LoopGuardSettings::default().mode, LoopGuardMode::Observe);
    }

    #[test]
    fn nudge_at_is_at_least_the_minimum() {
        assert!(s(0, 8).validate().is_err());
        assert!(s(LOOP_GUARD_MIN_NUDGE_AT - 1, 8).validate().is_err());
        assert_eq!(s(LOOP_GUARD_MIN_NUDGE_AT, 8).validate(), Ok(()));
    }

    #[test]
    fn stop_at_is_at_least_two_past_nudge_at() {
        assert!(s(3, 4).validate().is_err());
        assert!(s(3, 3).validate().is_err());
        assert_eq!(s(3, 5).validate(), Ok(()));
    }

    #[test]
    fn stop_at_is_at_most_the_cap() {
        assert!(s(3, LOOP_GUARD_MAX_STOP_AT + 1).validate().is_err());
        assert_eq!(s(3, LOOP_GUARD_MAX_STOP_AT).validate(), Ok(()));
        // nudge_at near the cap still needs its two-step gap below it.
        assert_eq!(s(LOOP_GUARD_MAX_STOP_AT - 2, LOOP_GUARD_MAX_STOP_AT).validate(), Ok(()));
        assert!(s(LOOP_GUARD_MAX_STOP_AT - 1, LOOP_GUARD_MAX_STOP_AT).validate().is_err());
        // No overflow at the type's edge.
        assert!(s(u32::MAX, u32::MAX).validate().is_err());
    }

    #[test]
    fn the_bounds_hold_in_every_mode() {
        for mode in [LoopGuardMode::Off, LoopGuardMode::Observe, LoopGuardMode::Nudge, LoopGuardMode::Stop] {
            assert!(LoopGuardSettings { mode, nudge_at: 3, stop_at: 4 }.validate().is_err());
        }
    }

    #[test]
    fn the_mode_spelling_is_the_serde_one() {
        for mode in [LoopGuardMode::Off, LoopGuardMode::Observe, LoopGuardMode::Nudge, LoopGuardMode::Stop] {
            assert_eq!(serde_json::to_value(mode).unwrap(), serde_json::json!(mode.as_str()));
            assert_eq!(LoopGuardMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(LoopGuardMode::parse("Stop"), None);
    }
}
