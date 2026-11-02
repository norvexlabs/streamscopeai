//! Throttled reporting of a condition that holds until an operator fixes it.
//!
//! A configuration error seen on every request, or on every configuration
//! change, would bury the log it is meant to surface; it is reported once per
//! subject every [`EVERY`].

/// How often one subject's condition is reported.
pub const EVERY: std::time::Duration = std::time::Duration::from_secs(300);

/// Whether the condition keyed `key` (kind + subject) is due a report at
/// `now`, recording it if so.
pub fn due(key: &str, now: std::time::Instant) -> bool {
    use dashmap::mapref::entry::Entry;
    static LAST: std::sync::LazyLock<dashmap::DashMap<String, std::time::Instant>> =
        std::sync::LazyLock::new(dashmap::DashMap::new);
    match LAST.entry(key.to_string()) {
        Entry::Vacant(v) => {
            v.insert(now);
            true
        }
        Entry::Occupied(mut o) => {
            let due = now.saturating_duration_since(*o.get()) >= EVERY;
            if due {
                o.insert(now);
            }
            due
        }
    }
}
