//! Dynamic log level management via tracing-subscriber reload handle.

use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::reload;

type ReloadHandle = reload::Handle<EnvFilter, tracing_subscriber::Registry>;

static RELOAD_HANDLE: OnceLock<ReloadHandle> = OnceLock::new();

/// Store the reload handle at startup. Must be called exactly once.
pub fn init(handle: ReloadHandle) {
    if RELOAD_HANDLE.set(handle).is_err() {
        tracing::warn!("log_level::init called more than once, ignoring");
    }
}

/// The level last applied: what a change is compared against. The process
/// starts at the default.
static CURRENT: std::sync::Mutex<&'static str> = std::sync::Mutex::new("info");

/// The level last applied.
pub fn current() -> &'static str {
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner())
}

/// Apply a new log level at runtime. Accepts: "error", "warn", "info", "debug";
/// anything else is "info".
pub fn apply(level: &str) {
    let (name, directive) = match level {
        "error" => ("error", "streamscope=error"),
        "warn" => ("warn", "streamscope=warn"),
        "debug" => ("debug", "streamscope=debug"),
        _ => ("info", "streamscope=info"),
    };
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = name;

    if let Some(handle) = RELOAD_HANDLE.get() {
        match directive.parse::<EnvFilter>() {
            Ok(new_filter) => {
                if let Err(e) = handle.reload(new_filter) {
                    eprintln!("failed to reload log filter: {e}");
                }
            }
            Err(e) => {
                eprintln!("invalid log filter directive '{directive}': {e}");
            }
        }
    }
}
