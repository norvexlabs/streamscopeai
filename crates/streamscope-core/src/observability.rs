//! Process-wide observability helpers shared by both binaries.

/// Route panics through the `tracing` pipeline.
///
/// Both binaries log as structured JSON (`tracing_subscriber::fmt().json()`).
/// The default panic hook writes to stderr as unstructured text, so a panic in
/// a request handler or background task would be invisible to a JSON log
/// aggregator. This hook emits the panic message, source location, and a
/// backtrace as a `tracing::error!` event so the panic lands in the same
/// pipeline as every other error.
///
/// Install once, immediately after the tracing subscriber is initialized —
/// before that point `tracing::error!` has no subscriber and would drop the
/// event.
pub fn install_panic_logger() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        // The panic payload is `&str` for `panic!("literal")` and `String`
        // for `panic!("{}", fmt)` / most `unwrap`/`expect` messages.
        let message: &str = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");

        // force_capture, not capture: a panic is rare, so always capture a
        // trace rather than gating it on a `RUST_BACKTRACE` set before the fact.
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::error!(
            location = %location,
            backtrace = %backtrace,
            "panic: {message}"
        );
    }));
}
