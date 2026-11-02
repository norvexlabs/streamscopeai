//! Prometheus text-format exposition (version 0.0.4) and the standalone
//! internal metrics listener.
//!
//! The gateway exposes operational metrics for external monitoring stacks on a
//! dedicated `METRICS_PORT` listener, never on the main service port: the
//! public Caddy vhosts reverse-proxy the whole main port unauthenticated, so a
//! `/metrics` route there would be internet-reachable. Isolation is by port —
//! each deploy shape decides whether (and to whom) the metrics port is
//! published.
//!
//! Rendering is a hand-rolled writer over the small fixed metric set: all
//! series are known at compile time with static label values, so no registry
//! machinery is needed. Histograms are CUMULATIVE (monotonic counters per
//! `le` bucket) — the consumer derives windowed views by differencing
//! successive scrapes, never the producer.

use std::fmt::Write as _;

use axum::response::IntoResponse;
use tokio_util::sync::CancellationToken;

/// Content type mandated by the Prometheus text exposition format v0.0.4.
pub const PROM_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// Gateway-overhead histogram upper bounds in microseconds (power-of-two,
/// 256µs..~262ms). The bucket array everywhere is `len + 1` — the final slot
/// is the `+Inf` overflow bucket.
///
/// Invariant: this is the SINGLE definition shared by the proxy (recording +
/// `/metrics` exposition) and the admin (heartbeat ingest + percentile
/// interpolation over `edge_stats_samples` deltas) — the wire and the DB
/// column carry per-bucket counts positioned against exactly these bounds.
pub const OVERHEAD_BOUNDS_US: [u64; 11] =
    [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144];

/// Number of overhead buckets on the wire / in `edge_stats_samples`
/// (`OVERHEAD_BOUNDS_US` + the `+Inf` overflow slot).
pub const OVERHEAD_BUCKET_COUNT: usize = OVERHEAD_BOUNDS_US.len() + 1;

/// Estimate quantile `q` (0.0..=1.0) from NON-cumulative per-bucket counts
/// (`counts.len() == bounds.len() + 1`, last slot = overflow) with linear
/// interpolation inside the target bucket — `histogram_quantile` semantics.
/// The overflow bucket clamps to the last finite bound (a value pinned there
/// is itself a signal). Returns 0.0 when no samples.
pub fn histogram_quantile(bounds: &[u64], counts: &[u64], q: f64) -> f64 {
    debug_assert_eq!(counts.len(), bounds.len() + 1);
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let target = (total as f64 * q.clamp(0.0, 1.0)).max(1.0);
    let mut cum = 0u64;
    for (i, &count) in counts.iter().enumerate() {
        if count == 0 {
            cum += count;
            continue;
        }
        let next = cum + count;
        if (next as f64) >= target {
            if i >= bounds.len() {
                // Overflow bucket: clamp to the last finite bound.
                return bounds[bounds.len() - 1] as f64;
            }
            let lower = if i == 0 { 0.0 } else { bounds[i - 1] as f64 };
            let upper = bounds[i] as f64;
            let frac = (target - cum as f64) / count as f64;
            return lower + (upper - lower) * frac;
        }
        cum = next;
    }
    bounds[bounds.len() - 1] as f64
}

/// Buffer building a Prometheus text-format payload.
#[derive(Default)]
pub struct PromBuf {
    buf: String,
}

/// Escape a label value per the exposition format: backslash, double-quote,
/// and newline must be escaped inside the quoted value.
fn write_escaped_label_value(buf: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '\\' => buf.push_str("\\\\"),
            '"' => buf.push_str("\\\""),
            '\n' => buf.push_str("\\n"),
            _ => buf.push(c),
        }
    }
}

impl PromBuf {
    pub fn new() -> Self {
        Self::default()
    }

    /// Write the `# HELP` / `# TYPE` header for a metric family.
    /// `kind` is one of `counter` | `gauge` | `histogram`.
    pub fn family(&mut self, name: &str, kind: &str, help: &str) {
        // HELP text escaping: backslash and newline only (no quotes here).
        let mut escaped = String::with_capacity(help.len());
        for c in help.chars() {
            match c {
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                _ => escaped.push(c),
            }
        }
        let _ = writeln!(self.buf, "# HELP {name} {escaped}");
        let _ = writeln!(self.buf, "# TYPE {name} {kind}");
    }

    fn write_name_and_labels(&mut self, name: &str, labels: &[(&str, &str)]) {
        self.buf.push_str(name);
        if !labels.is_empty() {
            self.buf.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    self.buf.push(',');
                }
                self.buf.push_str(k);
                self.buf.push_str("=\"");
                write_escaped_label_value(&mut self.buf, v);
                self.buf.push('"');
            }
            self.buf.push('}');
        }
    }

    /// Write one integer-valued sample line.
    pub fn sample_u64(&mut self, name: &str, labels: &[(&str, &str)], value: u64) {
        self.write_name_and_labels(name, labels);
        let _ = writeln!(self.buf, " {value}");
    }

    /// Write one integer-valued sample line for a signed value (gauges that can
    /// transiently dip below zero, e.g. relaxed inc/dec counters).
    pub fn sample_i64(&mut self, name: &str, labels: &[(&str, &str)], value: i64) {
        self.write_name_and_labels(name, labels);
        let _ = writeln!(self.buf, " {value}");
    }

    /// Write one float-valued sample line.
    pub fn sample_f64(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        self.write_name_and_labels(name, labels);
        let _ = writeln!(self.buf, " {value}");
    }

    /// Write a full histogram family: `_bucket` lines (cumulative counts per
    /// `le` upper bound, in seconds), the mandatory `+Inf` bucket, `_sum`
    /// (seconds) and `_count`.
    ///
    /// `upper_bounds_secs` and `cumulative_counts` are parallel; `count` is the
    /// all-time total (the `+Inf` bucket value) and MUST be >= the last
    /// cumulative count.
    pub fn histogram(
        &mut self,
        name: &str,
        help: &str,
        upper_bounds_secs: &[f64],
        cumulative_counts: &[u64],
        sum_secs: f64,
        count: u64,
    ) {
        debug_assert_eq!(upper_bounds_secs.len(), cumulative_counts.len());
        self.family(name, "histogram", help);
        let bucket = format!("{name}_bucket");
        for (le, cum) in upper_bounds_secs.iter().zip(cumulative_counts) {
            self.sample_u64(&bucket, &[("le", &format!("{le}"))], *cum);
        }
        self.sample_u64(&bucket, &[("le", "+Inf")], count);
        self.sample_f64(&format!("{name}_sum"), &[], sum_secs);
        self.sample_u64(&format!("{name}_count"), &[], count);
    }

    pub fn finish(self) -> String {
        self.buf
    }
}

/// Wrap a rendered payload in a `200` response with the exposition
/// content-type.
pub fn metrics_response(body: String) -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, PROM_CONTENT_TYPE)], body)
}

/// Bind the dedicated metrics listener. Called on the startup path so a
/// misconfigured port fails boot loudly instead of silently dropping the
/// monitoring surface.
pub async fn bind_metrics_listener(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(std::net::SocketAddr::from(([0, 0, 0, 0], port))).await
}

/// Serve a metrics router on its own listener until `shutdown` fires. Runs as
/// a detached task; serve errors are logged, never fatal to the main service.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    shutdown: CancellationToken,
) {
    let graceful = async move { shutdown.cancelled().await };
    if let Err(e) = axum::serve(crate::net::without_nagle(listener), router).with_graceful_shutdown(graceful).await {
        tracing::error!(error = %e, "metrics listener failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_and_gauge_render_exact() {
        let mut buf = PromBuf::new();
        buf.family("streamscope_proxy_requests_total", "counter", "Total requests.");
        buf.sample_u64("streamscope_proxy_requests_total", &[], 42);
        buf.family("streamscope_proxy_active_streams", "gauge", "Active streams.");
        buf.sample_i64("streamscope_proxy_active_streams", &[], -1);
        assert_eq!(
            buf.finish(),
            "# HELP streamscope_proxy_requests_total Total requests.\n\
             # TYPE streamscope_proxy_requests_total counter\n\
             streamscope_proxy_requests_total 42\n\
             # HELP streamscope_proxy_active_streams Active streams.\n\
             # TYPE streamscope_proxy_active_streams gauge\n\
             streamscope_proxy_active_streams -1\n"
        );
    }

    #[test]
    fn labels_render_and_escape() {
        let mut buf = PromBuf::new();
        buf.sample_u64(
            "m",
            &[("proto", "http/1.1"), ("weird", "a\"b\\c\nd")],
            7,
        );
        assert_eq!(buf.finish(), "m{proto=\"http/1.1\",weird=\"a\\\"b\\\\c\\nd\"} 7\n");
    }

    #[test]
    fn histogram_renders_cumulative_with_inf() {
        let mut buf = PromBuf::new();
        buf.histogram(
            "streamscope_proxy_overhead_seconds",
            "Gateway overhead.",
            &[0.000256, 0.000512, 0.262144],
            &[1, 3, 9],
            0.005,
            10,
        );
        assert_eq!(
            buf.finish(),
            "# HELP streamscope_proxy_overhead_seconds Gateway overhead.\n\
             # TYPE streamscope_proxy_overhead_seconds histogram\n\
             streamscope_proxy_overhead_seconds_bucket{le=\"0.000256\"} 1\n\
             streamscope_proxy_overhead_seconds_bucket{le=\"0.000512\"} 3\n\
             streamscope_proxy_overhead_seconds_bucket{le=\"0.262144\"} 9\n\
             streamscope_proxy_overhead_seconds_bucket{le=\"+Inf\"} 10\n\
             streamscope_proxy_overhead_seconds_sum 0.005\n\
             streamscope_proxy_overhead_seconds_count 10\n"
        );
    }

    #[test]
    fn quantile_interpolates_within_bucket() {
        // 10 samples all in the (256, 512] bucket: p50 lands mid-bucket.
        let mut counts = [0u64; OVERHEAD_BUCKET_COUNT];
        counts[1] = 10;
        let p50 = histogram_quantile(&OVERHEAD_BOUNDS_US, &counts, 0.50);
        assert!((256.0..=512.0).contains(&p50), "p50={p50}");
        // p100 = the bucket's upper bound.
        assert_eq!(histogram_quantile(&OVERHEAD_BOUNDS_US, &counts, 1.0), 512.0);
    }

    #[test]
    fn quantile_spans_buckets_and_clamps_overflow() {
        let mut counts = [0u64; OVERHEAD_BUCKET_COUNT];
        counts[0] = 50; // <=256µs
        counts[3] = 40; // (1024, 2048]
        counts[11] = 10; // overflow
        // The p50 target rank (50) sits exactly at bucket 0's cumulative
        // boundary → interpolates to that bucket's upper bound.
        assert_eq!(histogram_quantile(&OVERHEAD_BOUNDS_US, &counts, 0.50), 256.0);
        // p75 rank 75 falls 25/40 into the (1024, 2048] bucket.
        let p75 = histogram_quantile(&OVERHEAD_BOUNDS_US, &counts, 0.75);
        assert!((1024.0..2048.0).contains(&p75), "p75={p75}");
        // p99 falls in the overflow bucket → clamped to the last finite bound.
        assert_eq!(histogram_quantile(&OVERHEAD_BOUNDS_US, &counts, 0.99), 262144.0);
        // Empty histogram → 0.
        assert_eq!(histogram_quantile(&OVERHEAD_BOUNDS_US, &[0; OVERHEAD_BUCKET_COUNT], 0.95), 0.0);
    }

    #[test]
    fn float_values_render_minimal() {
        let mut buf = PromBuf::new();
        buf.sample_f64("m", &[], 123.0);
        buf.sample_f64("n", &[], 0.25);
        assert_eq!(buf.finish(), "m 123\nn 0.25\n");
    }
}
