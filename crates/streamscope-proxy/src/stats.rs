//! Live proxy metrics with zero-cost atomic counters.
//!
//! All counters use `Ordering::Relaxed` — no cross-thread synchronization,
//! just best-effort metrics. Every counter and histogram is CUMULATIVE
//! (monotonic since process start); consumers derive windowed views by
//! differencing successive reads — the heartbeat/`edge_stats_samples` chain on
//! the admin side and any Prometheus scraper both rely on this, so nothing
//! here may reset or drain. CPU/memory stats come from the process's cgroup
//! (real pod/container usage — matches `kubectl top` / `docker stats`),
//! falling back to `sysinfo` off-cgroup; both are read only at snapshot/scrape
//! time, never on the hot path.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use streamscope_core::metrics::{PromBuf, OVERHEAD_BOUNDS_US, OVERHEAD_BUCKET_COUNT};
use streamscope_core::proxy::response_cache::CacheStats;
use streamscope_core::proxy::ProxyStatsTrait;

/// Request-duration histogram upper bounds in milliseconds (total latency —
/// measured from when the gateway starts forwarding, any wait for capacity
/// included, so LLM generation time dominates). Proxy-local: only the
/// `/metrics` exposition consumes it.
const DURATION_BOUNDS_MS: [u64; 12] =
    [50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000, 60000, 120000, 300000];
const DURATION_BUCKET_COUNT: usize = DURATION_BOUNDS_MS.len() + 1;

/// HTTP status classes tracked by `responses_total`: 1xx..5xx + other.
const STATUS_CLASSES: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];

/// Index of the bucket `v` falls in: first bound >= v, else the overflow slot.
#[inline]
fn bucket_index(bounds: &[u64], v: u64) -> usize {
    bounds.iter().position(|b| v <= *b).unwrap_or(bounds.len())
}

fn load_buckets<const N: usize>(hist: &[AtomicU64; N]) -> [u64; N] {
    std::array::from_fn(|i| hist[i].load(Ordering::Relaxed))
}

/// Live proxy stats reported to admin-api via heartbeat and exposed on the
/// `/metrics` scrape endpoint.
///
/// All counters use `Ordering::Relaxed` — no synchronization needed, these are
/// best-effort metrics read only at snapshot/scrape cadence. One or two atomic
/// increments per event on the request hot path.
pub struct ProxyStats {
    requests_total: AtomicU64,
    errors_total: AtomicU64,
    active_streams: AtomicI64,
    http2_requests: AtomicU64,
    http11_requests: AtomicU64,
    startup_time: Instant,
    num_cores: u16,
    /// Persistent sysinfo::System for the off-cgroup CPU/memory fallback (local
    /// dev). cpu_usage() requires two consecutive refresh_processes() calls.
    sys: Mutex<sysinfo::System>,
    /// Last cgroup CPU sample `(cumulative usage_usec, instant)` for the
    /// utilization delta. `None` when not running under a cgroup.
    cpu_sampler: Mutex<Option<(u64, Instant)>>,
    /// Proxy overhead histogram (auth + transforms + routing, excluding the
    /// upstream call). Cumulative per-bucket counts against
    /// `OVERHEAD_BOUNDS_US`; last slot is the overflow (+Inf) bucket.
    overhead_hist: [AtomicU64; OVERHEAD_BUCKET_COUNT],
    /// Cumulative sum of recorded overhead, in µs (the histogram `_sum`).
    overhead_sum_us: AtomicU64,
    /// Completed requests by final HTTP status class (`STATUS_CLASSES` order).
    responses_by_class: [AtomicU64; 6],
    /// Total request latency histogram (from when the gateway starts
    /// forwarding, any wait for capacity included), cumulative per-bucket
    /// counts against `DURATION_BOUNDS_MS` + overflow slot.
    duration_hist: [AtomicU64; DURATION_BUCKET_COUNT],
    /// Cumulative sum of recorded durations, in ms.
    duration_sum_ms: AtomicU64,
    /// Content bodies sent to admin-api, and their bytes as they travel
    /// (`PendingShare::content_weight`, or a blob's decoded bytes sent up by
    /// itself): every attempt counts, a resend included.
    content_bodies_shipped: AtomicU64,
    content_bytes_shipped: AtomicU64,
    /// Unix seconds of the last config sync answer that left this process
    /// nothing more to receive; 0 until the first.
    config_synced_at: AtomicU64,
}

impl Default for ProxyStats {
    fn default() -> Self { Self::new() }
}

impl ProxyStats {
    pub fn new() -> Self {
        // The runtime's effective parallelism — the Tokio worker-thread count this
        // process actually runs, sized cgroup-/host-aware (see streamscope_core::
        // runtime), not the raw host core count.
        let num_cores = streamscope_core::runtime::worker_threads(
            streamscope_core::runtime::Role::DataPlane,
        )
        .min(u16::MAX as usize) as u16;

        // Create persistent System and do initial refresh so the next
        // refresh_processes() call can compute a CPU delta.
        let mut sys = sysinfo::System::new();
        let pid = sysinfo::Pid::from_u32(std::process::id());
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);

        // Prime the cgroup CPU sampler so the first heartbeat reports a real
        // delta over the startup→first-snapshot window (None off-cgroup).
        let cpu_sampler = streamscope_core::cgroup::cpu_usage_usec().map(|u| (u, Instant::now()));

        Self {
            requests_total: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
            active_streams: AtomicI64::new(0),
            http2_requests: AtomicU64::new(0),
            http11_requests: AtomicU64::new(0),
            startup_time: Instant::now(),
            num_cores,
            sys: Mutex::new(sys),
            cpu_sampler: Mutex::new(cpu_sampler),
            overhead_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            overhead_sum_us: AtomicU64::new(0),
            responses_by_class: std::array::from_fn(|_| AtomicU64::new(0)),
            duration_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            duration_sum_ms: AtomicU64::new(0),
            content_bodies_shipped: AtomicU64::new(0),
            content_bytes_shipped: AtomicU64::new(0),
            config_synced_at: AtomicU64::new(0),
        }
    }

    /// A config sync answer left this process nothing more to receive. Returns
    /// whether it is the first since the process started.
    pub fn record_config_synced(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            .max(1);
        self.config_synced_at.swap(now, Ordering::Relaxed) == 0
    }

    /// Count content sent to admin-api: `(bodies, bytes)`.
    pub fn record_content_shipped(&self, (bodies, bytes): (u64, u64)) {
        self.content_bodies_shipped.fetch_add(bodies, Ordering::Relaxed);
        self.content_bytes_shipped.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record proxy overhead in microseconds (auth + transforms + routing).
    /// Two relaxed atomic increments per call — zero contention.
    #[inline]
    pub fn record_overhead_us(&self, us: u64) {
        let idx = bucket_index(&OVERHEAD_BOUNDS_US, us);
        self.overhead_hist[idx].fetch_add(1, Ordering::Relaxed);
        self.overhead_sum_us.fetch_add(us, Ordering::Relaxed);
    }

    /// Per-process CPU% and RSS via sysinfo — the off-cgroup fallback. One
    /// refresh per call; cpu_usage() needs the prior refresh done in `new()`.
    fn sysinfo_proc(&self) -> (f32, u64) {
        let pid = sysinfo::Pid::from_u32(std::process::id());
        let mut sys = self.sys.lock().unwrap_or_else(|e| {
            tracing::warn!("sysinfo mutex was poisoned, recovering");
            e.into_inner()
        });
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        sys.process(pid).map(|p| (p.cpu_usage(), p.memory())).unwrap_or((0.0, 0))
    }

    /// Whole-host memory `(total, used)` in bytes via sysinfo — the VM
    /// appliance's platform-pressure figure. Inside a container sysinfo still
    /// reads the host/VM-wide totals, so this measures the entire appliance's
    /// memory (every service plus the OS), not just this process's cgroup.
    fn sysinfo_host_mem(&self) -> (u64, u64) {
        let mut sys = self.sys.lock().unwrap_or_else(|e| {
            tracing::warn!("sysinfo mutex was poisoned, recovering");
            e.into_inner()
        });
        sys.refresh_memory();
        let total = sys.total_memory();
        let used = total.saturating_sub(sys.available_memory());
        (total, used)
    }

    /// Snapshot current stats for heartbeat reporting.
    ///
    /// Called only on heartbeat (every 30s), NOT on request path. Pure relaxed
    /// loads over the cumulative counters — never resets anything (the admin
    /// differences successive samples for windowed views). Prefers cgroup
    /// accounting (real pod/container usage), falling back to sysinfo off-cgroup.
    pub fn snapshot(&self) -> StatsSnapshot {
        // Prefer the cgroup's own accounting — it matches what the orchestrator
        // sees (`kubectl top` / OOM killer on K8s, `docker stats` on the VM, where
        // each service runs in its own cgroup). Fall back to per-process sysinfo
        // only off-cgroup (local dev on bare metal / macOS). Both forms scale CPU
        // so 100% == one core.
        let cgroup_cpu_usec = streamscope_core::cgroup::cpu_usage_usec();

        // On the single-host VM appliance the meaningful memory signal is the
        // whole VM's pressure, not the proxy container's slice of its own 512M
        // cap — so the appliance opts into host-wide reporting. K8s and local dev
        // keep the per-cgroup working-set / `memory.max` (the real per-pod OOM
        // signal). Both paths land in the same heartbeat fields, so the dashboard
        // tile and history chart need no awareness of which is in play.
        let report_host_memory = crate::settings::proxy_settings().appliance_host_memory;
        let cgroup_mem =
            (!report_host_memory).then(streamscope_core::cgroup::memory_working_set_bytes).flatten();

        // Off-cgroup fallbacks (computed once, only when needed). Per-process
        // sysinfo memory is only the non-appliance fallback; the appliance reads
        // host-wide memory separately below.
        let need_sys_mem = !report_host_memory && cgroup_mem.is_none();
        let (sys_cpu, sys_mem) = if cgroup_cpu_usec.is_none() || need_sys_mem {
            self.sysinfo_proc()
        } else {
            (0.0, 0)
        };

        let cpu_percent = if let Some(usec) = cgroup_cpu_usec {
            let now = Instant::now();
            let mut last = self.cpu_sampler.lock().unwrap_or_else(|e| e.into_inner());
            let pct = last.map_or(0.0, |(prev_usec, prev_t)| {
                let elapsed_us = now.saturating_duration_since(prev_t).as_micros();
                if elapsed_us == 0 {
                    0.0
                } else {
                    (usec.saturating_sub(prev_usec) as f64 / elapsed_us as f64) * 100.0
                }
            });
            *last = Some((usec, now));
            pct as f32
        } else {
            sys_cpu
        };

        let (memory_rss_bytes, memory_limit_bytes) = if report_host_memory {
            // Whole-VM pressure: used RAM against total RAM (the denominator).
            let (total, used) = self.sysinfo_host_mem();
            (used, (total > 0).then_some(total))
        } else {
            // Per-cgroup working-set against the cgroup ceiling (`memory.max`) —
            // the "% of limit" denominator; None off-cgroup or unconstrained.
            (cgroup_mem.unwrap_or(sys_mem), streamscope_core::cgroup::memory_limit_bytes())
        };

        let overhead_buckets = load_buckets(&self.overhead_hist);

        StatsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            errors_total: self.errors_total.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed),
            cpu_percent,
            memory_rss_bytes,
            memory_limit_bytes,
            cores: self.num_cores,
            uptime_secs: self.startup_time.elapsed().as_secs(),
            http2_requests: self.http2_requests.load(Ordering::Relaxed),
            http11_requests: self.http11_requests.load(Ordering::Relaxed),
            overhead_count: overhead_buckets.iter().sum(),
            overhead_buckets,
            overhead_sum_us: self.overhead_sum_us.load(Ordering::Relaxed),
            pending_audit_count: 0,
            cache: CacheStats::default(),
        }
    }

    /// Render the proxy's Prometheus exposition into `buf`. The async-only
    /// series (pending audit records) is appended by the HTTP handler.
    pub fn render_prometheus(&self, buf: &mut PromBuf) {
        buf.family("streamscope_proxy_build_info", "gauge", "Build information (constant 1).");
        buf.sample_u64(
            "streamscope_proxy_build_info",
            &[("version", streamscope_core::VERSION)],
            1,
        );

        buf.family(
            "streamscope_proxy_requests_total",
            "counter",
            "LLM and media requests received.",
        );
        buf.sample_u64(
            "streamscope_proxy_requests_total",
            &[],
            self.requests_total.load(Ordering::Relaxed),
        );

        buf.family(
            "streamscope_proxy_errors_total",
            "counter",
            "Requests that failed in the gateway or upstream.",
        );
        buf.sample_u64(
            "streamscope_proxy_errors_total",
            &[],
            self.errors_total.load(Ordering::Relaxed),
        );

        buf.family(
            "streamscope_proxy_content_bodies_shipped_total",
            "counter",
            "Content bodies (messages, tool sets, system prompts, media) sent to admin-api, every attempt counted.",
        );
        buf.sample_u64(
            "streamscope_proxy_content_bodies_shipped_total",
            &[],
            self.content_bodies_shipped.load(Ordering::Relaxed),
        );
        buf.family(
            "streamscope_proxy_content_bytes_shipped_total",
            "counter",
            "Bytes of the content bodies sent to admin-api as they travel (inside an ingest request, or a media file sent up by itself), every attempt counted.",
        );
        buf.sample_u64(
            "streamscope_proxy_content_bytes_shipped_total",
            &[],
            self.content_bytes_shipped.load(Ordering::Relaxed),
        );

        buf.family(
            "streamscope_proxy_config_synced_timestamp_seconds",
            "gauge",
            "Unix time of the last config sync answer that left this gateway nothing more to receive; 0 from its start until the first.",
        );
        buf.sample_u64(
            "streamscope_proxy_config_synced_timestamp_seconds",
            &[],
            self.config_synced_at.load(Ordering::Relaxed),
        );

        buf.family(
            "streamscope_proxy_http_requests_total",
            "counter",
            "Requests by client HTTP protocol.",
        );
        buf.sample_u64(
            "streamscope_proxy_http_requests_total",
            &[("proto", "h2")],
            self.http2_requests.load(Ordering::Relaxed),
        );
        buf.sample_u64(
            "streamscope_proxy_http_requests_total",
            &[("proto", "http/1.1")],
            self.http11_requests.load(Ordering::Relaxed),
        );

        buf.family(
            "streamscope_proxy_responses_total",
            "counter",
            "Finalized requests by HTTP status class. Requests rejected before the upstream forward (auth, rate limit, routing) count in requests/errors totals only, so the sum here is <= requests_total.",
        );
        for (i, class) in STATUS_CLASSES.iter().enumerate() {
            buf.sample_u64(
                "streamscope_proxy_responses_total",
                &[("class", class)],
                self.responses_by_class[i].load(Ordering::Relaxed),
            );
        }

        buf.family(
            "streamscope_proxy_active_streams",
            "gauge",
            "Streaming responses currently in flight.",
        );
        buf.sample_i64(
            "streamscope_proxy_active_streams",
            &[],
            self.active_streams.load(Ordering::Relaxed),
        );

        write_histogram_us(
            buf,
            "streamscope_proxy_overhead_seconds",
            "Gateway processing overhead (auth + transforms + routing), excluding the upstream call.",
            &OVERHEAD_BOUNDS_US,
            &load_buckets(&self.overhead_hist),
            self.overhead_sum_us.load(Ordering::Relaxed),
        );

        write_histogram_ms(
            buf,
            "streamscope_proxy_request_duration_seconds",
            "Total request latency measured from when the gateway starts forwarding, including any wait for upstream capacity.",
            &DURATION_BOUNDS_MS,
            &load_buckets(&self.duration_hist),
            self.duration_sum_ms.load(Ordering::Relaxed),
        );

        // Process resources: per-cgroup form only (the per-process signal a
        // scraper expects) — never the appliance's host-wide memory mode, which
        // stays a heartbeat/dashboard concern. Lines are omitted off-cgroup.
        if let Some(usec) = streamscope_core::cgroup::cpu_usage_usec() {
            buf.family(
                "streamscope_proxy_cpu_seconds_total",
                "counter",
                "Cumulative cgroup CPU time.",
            );
            buf.sample_f64("streamscope_proxy_cpu_seconds_total", &[], usec as f64 / 1e6);
        }
        if let Some(bytes) = streamscope_core::cgroup::memory_working_set_bytes() {
            buf.family(
                "streamscope_proxy_memory_working_set_bytes",
                "gauge",
                "Cgroup memory working set.",
            );
            buf.sample_u64("streamscope_proxy_memory_working_set_bytes", &[], bytes);
        }
        if let Some(bytes) = streamscope_core::cgroup::memory_limit_bytes() {
            buf.family(
                "streamscope_proxy_memory_limit_bytes",
                "gauge",
                "Cgroup memory limit (memory.max).",
            );
            buf.sample_u64("streamscope_proxy_memory_limit_bytes", &[], bytes);
        }

        buf.family("streamscope_proxy_uptime_seconds", "gauge", "Seconds since process start.");
        buf.sample_u64(
            "streamscope_proxy_uptime_seconds",
            &[],
            self.startup_time.elapsed().as_secs(),
        );
    }
}

/// Append the dispatch-gate series: what the gateway held, refused and is
/// holding right now. Owned by the gate, like the cache's own series.
///
/// The totals are CUMULATIVE — a consumer derives a rate by differencing
/// them, never by reading a value this process reset.
pub fn render_gate_prometheus(
    buf: &mut PromBuf,
    gate: &streamscope_core::proxy::dispatch_gate::GateStats,
) {
    buf.family(
        "streamscope_proxy_dispatch_held_total",
        "counter",
        "Requests held for upstream capacity since this replica started.",
    );
    buf.sample_u64("streamscope_proxy_dispatch_held_total", &[], gate.held_total);

    buf.family(
        "streamscope_proxy_dispatch_shed_total",
        "counter",
        "Requests refused at once because their priority class is not queued.",
    );
    buf.sample_u64("streamscope_proxy_dispatch_shed_total", &[], gate.shed_total);

    buf.family(
        "streamscope_proxy_dispatch_timeout_total",
        "counter",
        "Requests refused after waiting for capacity without getting any.",
    );
    buf.sample_u64("streamscope_proxy_dispatch_timeout_total", &[], gate.timeout_total);

    buf.family(
        "streamscope_proxy_dispatch_overloaded_total",
        "counter",
        "Requests refused because this replica was already holding as many as it may.",
    );
    buf.sample_u64("streamscope_proxy_dispatch_overloaded_total", &[], gate.overloaded_total);

    buf.family(
        "streamscope_proxy_dispatch_superseded_total",
        "counter",
        "Waiting requests replaced by the same request sent again by its client.",
    );
    buf.sample_u64("streamscope_proxy_dispatch_superseded_total", &[], gate.superseded_total);

    buf.family(
        "streamscope_proxy_dispatch_queue_depth",
        "gauge",
        "Requests waiting for capacity right now.",
    );
    buf.sample_u64("streamscope_proxy_dispatch_queue_depth", &[], gate.queue_depth);

    buf.family(
        "streamscope_proxy_dispatch_in_flight",
        "gauge",
        "Requests this replica currently has in flight at capacity-limited endpoints.",
    );
    buf.sample_u64("streamscope_proxy_dispatch_in_flight", &[], gate.in_flight);
}

/// Append the response-cache series. Separate from
/// [`ProxyStats::render_prometheus`] because the cache owns this state, not
/// `ProxyStats` — same reason the heartbeat fills `StatsSnapshot::cache` in.
pub fn render_cache_prometheus(buf: &mut PromBuf, cache: &CacheStats) {
    buf.family(
        "streamscope_proxy_cache_entries",
        "gauge",
        "Responses currently held in the in-memory response cache.",
    );
    buf.sample_u64("streamscope_proxy_cache_entries", &[], cache.entries);

    buf.family(
        "streamscope_proxy_cache_bytes",
        "gauge",
        "Bytes those cached responses account for.",
    );
    buf.sample_u64("streamscope_proxy_cache_bytes", &[], cache.bytes);

    buf.family(
        "streamscope_proxy_cache_max_bytes",
        "gauge",
        "Global byte ceiling the cache enforces: RESPONSE_CACHE_MAX_MB, or by default a share of the replica's memory limit.",
    );
    buf.sample_u64("streamscope_proxy_cache_max_bytes", &[], cache.max_bytes);

    buf.family(
        "streamscope_proxy_cache_semantic_vectors",
        "gauge",
        "Prompt vectors indexed for semantic matching. Exceeding cache_entries \
         proves vectors are outliving their entries; a smaller leak hides \
         inside the exact-mode entries, which carry no vector.",
    );
    buf.sample_u64(
        "streamscope_proxy_cache_semantic_vectors",
        &[],
        cache.semantic_vectors,
    );

    buf.family(
        "streamscope_proxy_cache_semantic_buckets",
        "gauge",
        "Distinct prefix buckets holding those vectors.",
    );
    buf.sample_u64(
        "streamscope_proxy_cache_semantic_buckets",
        &[],
        cache.semantic_buckets,
    );

    buf.family(
        "streamscope_proxy_cache_stores_total",
        "counter",
        "Responses admitted to the cache.",
    );
    buf.sample_u64("streamscope_proxy_cache_stores_total", &[], cache.stores_total);

    buf.family(
        "streamscope_proxy_cache_evictions_total",
        "counter",
        "Entries dropped to make room for a new one — the cache is undersized \
         for its traffic when this rises against flat cache_entries.",
    );
    buf.sample_u64(
        "streamscope_proxy_cache_evictions_total",
        &[],
        cache.evictions_total,
    );

    buf.family(
        "streamscope_proxy_cache_expired_total",
        "counter",
        "Entries dropped for reaching their TTL.",
    );
    buf.sample_u64("streamscope_proxy_cache_expired_total", &[], cache.expired_total);
}

/// Write one histogram family from per-bucket counts (`counts.len() ==
/// bounds.len() + 1`, last slot = overflow) with bounds in µs.
fn write_histogram_us(
    buf: &mut PromBuf,
    name: &str,
    help: &str,
    bounds: &[u64],
    counts: &[u64],
    sum_raw: u64,
) {
    write_histogram_scaled(buf, name, help, bounds, counts, sum_raw, 1e-6);
}

/// Same as [`write_histogram_us`] with bounds/sum in ms.
fn write_histogram_ms(
    buf: &mut PromBuf,
    name: &str,
    help: &str,
    bounds: &[u64],
    counts: &[u64],
    sum_raw: u64,
) {
    write_histogram_scaled(buf, name, help, bounds, counts, sum_raw, 1e-3);
}

fn write_histogram_scaled(
    buf: &mut PromBuf,
    name: &str,
    help: &str,
    bounds: &[u64],
    counts: &[u64],
    sum_raw: u64,
    unit_to_secs: f64,
) {
    let bounds_secs: Vec<f64> = bounds.iter().map(|b| *b as f64 * unit_to_secs).collect();
    let mut cumulative = Vec::with_capacity(bounds.len());
    let mut acc = 0u64;
    for &c in &counts[..bounds.len()] {
        acc += c;
        cumulative.push(acc);
    }
    let total = acc + counts[bounds.len()];
    buf.histogram(name, help, &bounds_secs, &cumulative, sum_raw as f64 * unit_to_secs, total);
}

impl ProxyStatsTrait for ProxyStats {
    #[inline]
    fn inc_requests(&self) { self.requests_total.fetch_add(1, Ordering::Relaxed); }
    #[inline]
    fn inc_errors(&self) { self.errors_total.fetch_add(1, Ordering::Relaxed); }
    #[inline]
    fn inc_active_streams(&self) { self.active_streams.fetch_add(1, Ordering::Relaxed); }
    #[inline]
    fn dec_active_streams(&self) { self.active_streams.fetch_sub(1, Ordering::Relaxed); }
    #[inline]
    fn inc_http2(&self) { self.http2_requests.fetch_add(1, Ordering::Relaxed); }
    #[inline]
    fn inc_http11(&self) { self.http11_requests.fetch_add(1, Ordering::Relaxed); }
    #[inline]
    fn record_overhead_us(&self, us: u64) { self.record_overhead_us(us); }
    #[inline]
    fn record_request_outcome(&self, status_code: u16, total_ms: Option<u64>) {
        let class_idx = match status_code / 100 {
            c @ 1..=5 => (c - 1) as usize,
            _ => 5,
        };
        self.responses_by_class[class_idx].fetch_add(1, Ordering::Relaxed);
        if let Some(ms) = total_ms {
            let idx = bucket_index(&DURATION_BOUNDS_MS, ms);
            self.duration_hist[idx].fetch_add(1, Ordering::Relaxed);
            self.duration_sum_ms.fetch_add(ms, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StatsSnapshot {
    pub requests_total: u64,
    pub errors_total: u64,
    pub active_streams: i64,
    pub cpu_percent: f32,
    pub memory_rss_bytes: u64,
    /// Denominator for the memory-pressure reading: this process's cgroup ceiling
    /// (`memory.max`) normally, or — on the single-host VM appliance
    /// (`APPLIANCE_HOST_MEMORY`) — the host's total RAM, paired with a host-wide
    /// `memory_rss_bytes`. `None` off-cgroup (local dev) or when unconstrained.
    pub memory_limit_bytes: Option<u64>,
    /// Effective Tokio worker-thread count (the runtime's parallelism), not raw
    /// host cores — see `streamscope_core::runtime`.
    pub cores: u16,
    pub uptime_secs: u64,
    pub http2_requests: u64,
    pub http11_requests: u64,
    /// Proxy-overhead histogram (auth + transforms + routing, excluding the
    /// upstream call): CUMULATIVE per-bucket counts since process start,
    /// positioned against `streamscope_core::metrics::OVERHEAD_BOUNDS_US`
    /// (last slot = overflow). The admin differences successive samples per
    /// edge instance for windowed percentiles — never reset on the proxy.
    pub overhead_buckets: [u64; OVERHEAD_BUCKET_COUNT],
    /// Cumulative sum of recorded overhead in µs.
    pub overhead_sum_us: u64,
    /// Cumulative recorded-sample count (== sum of `overhead_buckets`).
    pub overhead_count: u64,
    /// Audit records buffered locally on this edge but not yet flushed
    /// upstream (the outbox plus the in-process queues). Set by the state
    /// report after snapshot() returns. 0 in any non-heartbeat context.
    #[serde(default)]
    pub pending_audit_count: u64,
    /// Response-cache occupancy and lifetime counters. Owned by the cache
    /// itself, so — like `pending_audit_count` — the heartbeat fills it in
    /// after `snapshot()` returns; all-zero in any other context.
    #[serde(default)]
    pub cache: CacheStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_index_at_boundaries() {
        // Exact bounds land in their own bucket (le = upper bound inclusive).
        assert_eq!(bucket_index(&OVERHEAD_BOUNDS_US, 0), 0);
        assert_eq!(bucket_index(&OVERHEAD_BOUNDS_US, 256), 0);
        assert_eq!(bucket_index(&OVERHEAD_BOUNDS_US, 257), 1);
        assert_eq!(bucket_index(&OVERHEAD_BOUNDS_US, 262144), 10);
        assert_eq!(bucket_index(&OVERHEAD_BOUNDS_US, 262145), 11);
        assert_eq!(bucket_index(&DURATION_BOUNDS_MS, 300000), 11);
        assert_eq!(bucket_index(&DURATION_BOUNDS_MS, 300001), 12);
    }

    #[test]
    fn snapshot_is_cumulative_never_drains() {
        let stats = ProxyStats::new();
        stats.record_overhead_us(300);
        stats.record_overhead_us(300);
        stats.record_overhead_us(500_000); // overflow bucket
        let a = stats.snapshot();
        assert_eq!(a.overhead_count, 3);
        assert_eq!(a.overhead_buckets[1], 2);
        assert_eq!(a.overhead_buckets[OVERHEAD_BUCKET_COUNT - 1], 1);
        assert_eq!(a.overhead_sum_us, 500_600);
        // A second snapshot sees the same cumulative values, not zeros.
        let b = stats.snapshot();
        assert_eq!(b.overhead_count, 3);
        assert_eq!(b.overhead_buckets, a.overhead_buckets);
    }

    #[test]
    fn render_emits_cumulative_buckets_and_classes() {
        let stats = ProxyStats::new();
        stats.record_overhead_us(300); // bucket 1 (256, 512]
        stats.record_request_outcome(200, Some(75));
        stats.record_request_outcome(502, None);
        stats.record_request_outcome(0, None); // unknown → other
        let mut buf = PromBuf::new();
        stats.render_prometheus(&mut buf);
        let out = buf.finish();
        // Cumulative across buckets: the 300µs sample counts in every le >= 512µs.
        assert!(out.contains("streamscope_proxy_overhead_seconds_bucket{le=\"0.000256\"} 0\n"));
        assert!(out.contains("streamscope_proxy_overhead_seconds_bucket{le=\"0.000512\"} 1\n"));
        assert!(out.contains("streamscope_proxy_overhead_seconds_bucket{le=\"+Inf\"} 1\n"));
        assert!(out.contains("streamscope_proxy_overhead_seconds_count 1\n"));
        assert!(out.contains("streamscope_proxy_responses_total{class=\"2xx\"} 1\n"));
        assert!(out.contains("streamscope_proxy_responses_total{class=\"5xx\"} 1\n"));
        assert!(out.contains("streamscope_proxy_responses_total{class=\"other\"} 1\n"));
        assert!(out.contains("streamscope_proxy_request_duration_seconds_bucket{le=\"0.05\"} 0\n"));
        assert!(out.contains("streamscope_proxy_request_duration_seconds_bucket{le=\"0.1\"} 1\n"));
        assert!(out.contains("streamscope_proxy_request_duration_seconds_count 1\n"));
        assert!(out
            .contains(&format!("streamscope_proxy_build_info{{version=\"{}\"}} 1\n", streamscope_core::VERSION)));
    }

    #[test]
    fn render_emits_the_content_shipped_counters_cumulatively() {
        let stats = ProxyStats::new();
        stats.record_content_shipped((2, 300));
        stats.record_content_shipped((1, 50));
        let mut buf = PromBuf::new();
        stats.render_prometheus(&mut buf);
        let text = buf.finish();
        assert!(text.contains("# TYPE streamscope_proxy_content_bodies_shipped_total counter"), "{text}");
        assert!(text.lines().any(|l| l == "streamscope_proxy_content_bodies_shipped_total 3"), "{text}");
        assert!(text.lines().any(|l| l == "streamscope_proxy_content_bytes_shipped_total 350"), "{text}");
    }

    #[test]
    fn the_config_sync_timestamp_is_zero_until_the_first_answer() {
        let stats = ProxyStats::new();
        let render = |stats: &ProxyStats| {
            let mut buf = PromBuf::new();
            stats.render_prometheus(&mut buf);
            buf.finish()
        };
        let text = render(&stats);
        assert!(text.contains("# TYPE streamscope_proxy_config_synced_timestamp_seconds gauge"), "{text}");
        assert!(text.lines().any(|l| l == "streamscope_proxy_config_synced_timestamp_seconds 0"), "{text}");
        assert!(stats.record_config_synced(), "the first answer");
        assert!(!stats.record_config_synced(), "a later answer");
        let text = render(&stats);
        let at: u64 = text
            .lines()
            .find_map(|l| l.strip_prefix("streamscope_proxy_config_synced_timestamp_seconds "))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(at > 0 && at <= now && now - at < 60, "{text}");
    }
}
