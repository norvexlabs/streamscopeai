//! Streamscope edge proxy — the request-handling binary.
//!
//! Receives LLM API requests, authenticates via cached credentials, routes to
//! upstream providers, applies request/response transforms, and forwards audit
//! records to the admin API. Polls admin-api for config (`/api/v2/edge/sync`)
//! and ships audit from a SQLite outbox (`/api/v2/edge/ingest`), so it serves
//! and buffers while admin-api is unreachable. Config and session state are
//! persisted to disk for crash recovery and cold start.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::Method;
use axum::routing::{any, get, post};
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowHeaders, Any, CorsLayer};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::reload;

use streamscope_core::api::sse::ApiVersion;
use streamscope_core::audit;
use streamscope_core::config;
use streamscope_core::error::envelope;
use streamscope_core::middleware::body_deadline;
use streamscope_core::proxy::client::UpstreamClient;
use streamscope_core::proxy::{self, AppState};

mod log_level;

mod a2a;
mod config_snapshot;
mod config_sync;
mod edge_link;
mod ip_rate_limit;
mod mcp;
mod outbox_v2;
mod sync_v2;
/// In-process tests over the production router built by `build_app`.
#[cfg(test)]
mod router_tests;
mod session_snapshot;
mod settings;
pub mod stats;

use settings::proxy_settings;

/// Last-resort panic boundary for the HTTP stack. A panic inside a request
/// handler is unwound here and turned into a sanitized 500 instead of dropping
/// the connection. The panic payload is intentionally discarded — the panic
/// hook (`install_panic_logger`) has already logged it with a backtrace during
/// unwinding; it is never echoed to the client.
fn handle_panic(_err: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
    use axum::response::IntoResponse;
    streamscope_core::error::AppError::Internal("request handler panicked".to_string())
        .into_response()
}

// Profiling defaults (internal, not worth exposing as settings)
#[cfg(feature = "pprof")]
const PPROF_DEFAULT_SECS: u64 = 10;
#[cfg(feature = "pprof")]
const PPROF_MAX_SECS: u64 = 120;
#[cfg(feature = "pprof")]
const PPROF_FREQUENCY: i32 = 99;

fn main() -> anyhow::Result<()> {
    // Size the Tokio runtime canonically (cgroup-aware in K8s; on a shared host
    // the proxy takes nearly all cores, leaving headroom for the control plane).
    // Built before tracing exists, so the chosen size is logged inside `run()`.
    streamscope_core::runtime::build_runtime(streamscope_core::runtime::Role::DataPlane)?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
    // Initialize settings from env vars (triggers lazy init + logs overrides).
    let s = proxy_settings();
    streamscope_core::settings::core_settings().log_non_defaults();
    s.log_non_defaults();

    // Initialize tracing with reload handle for dynamic log level changes.
    let env_filter = EnvFilter::from_default_env().add_directive("streamscope=info".parse()?);
    let (filter_layer, filter_reload_handle) = reload::Layer::new(env_filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    // Route panics into the JSON log pipeline now that the subscriber exists.
    streamscope_core::observability::install_panic_logger();

    // Store reload handle globally so config_sync can update log level at runtime.
    log_level::init(filter_reload_handle);

    tracing::info!(version = streamscope_core::VERSION, "starting streamscopeai");
    streamscope_core::runtime::log_sizing(streamscope_core::runtime::Role::DataPlane);

    // Require encryption key at startup — fail fast if not set.
    streamscope_core::crypto::require_encryption_key()
        .map_err(|msg| anyhow::anyhow!(msg))?;

    // No JWT secret check here, and deliberately none to add: the data plane
    // holds no signing secret at all. It verifies MCP OAuth tokens against the
    // per-tenant public keys admin-api puts on the config snapshot, so the key
    // material this process can reach is public by construction and a compromise
    // here mints nothing. The keys actually in force are logged as each snapshot
    // is applied (`config_sync::build_mcp_config`), which is also the only thing
    // that can change them — an operator confirming a rotation reads that, not
    // this process's environment.

    // Create tenant registry (per-tenant config, pre-populated with SYSTEM tenant defaults).
    let tenant_registry = config::new_tenant_registry();

    // All feature toggles are controlled via admin UI (system_settings table).
    // Defaults are in TenantConfig::default(). Config snapshots from admin-api override them.

    // Data directory for persistent state (audit buffer, config + session snapshots).
    let data_dir = s.data_dir.clone();
    let snapshot_data_dir = data_dir.clone(); // for session snapshot task + shutdown
    tokio::fs::create_dir_all(&data_dir).await.ok();

    // Readiness signal for the `/ready` probe — true once the proxy holds its
    // whole config: restored from disk below when an earlier process had it
    // whole, else set by the config sync when an answer leaves nothing unsent.
    let config_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Load config snapshot from disk if available (offline resilience).
    if let Ok(Some(mt_snapshot)) = config_snapshot::load_snapshot(&data_dir) {
        tracing::info!(
            tenants = mt_snapshot.tenants.len(),
            "loaded config snapshot from disk"
        );
        config_sync::apply_multi_tenant_snapshot(&tenant_registry, &mt_snapshot);
    }

    // The outbox: every record waits here until admin-api has it. It also
    // holds this instance's identity and its process epoch.
    let outbox = Arc::new(outbox_v2::OutboxV2::open(&data_dir).await?);
    let edge_instance = outbox.instance().await?;
    let process_epoch = outbox.start_process().await?;
    tracing::info!(instance = %edge_instance, process_epoch, "edge instance");
    let sink = edge_link::OutboxSink::new(outbox.clone());

    // Shutdown coordination tokens (Pingora-style graceful drain). After
    // `axum::serve` returns they are cancelled in order: the audit writer
    // tasks flush every queued record into the outbox, then the edge link
    // ships what it can of the outbox to admin-api, then the background loops
    // exit.
    let writers_shutdown_token = tokio_util::sync::CancellationToken::new();
    let edge_shutdown_token = tokio_util::sync::CancellationToken::new();
    let loops_shutdown_token = tokio_util::sync::CancellationToken::new();

    // Create audit channel.
    let (audit_tx, audit_rx) = audit::create_audit_channel();

    let audit_writer_handle = tokio::spawn(audit::audit_writer_task(
        audit_rx,
        Box::new(sink.clone()),
        writers_shutdown_token.clone(),
    ));

    // MCP, A2A and web-search audit pipelines: a dedicated channel each, into
    // the same outbox. admin-api dedupes on `(request_id, timestamp)`, so a
    // record delivered again is stored once.
    let (mcp_audit_tx, mcp_audit_rx) =
        streamscope_core::audit::mcp::create_mcp_audit_channel();
    // Per-(tenant, user) MCP event bus, shared by the MCP gateway (the
    // `tools/call` SSE pump and the GET-channel handler) and the edge link,
    // which publishes the events other instances relay through admin-api.
    let mcp_event_bus = mcp::event_bus::PerUserEventBus::new(
        proxy_settings().mcp_get_bus_capacity,
    );
    let mcp_audit_writer_handle = tokio::spawn(streamscope_core::audit::mcp::mcp_audit_writer_task(
        mcp_audit_rx,
        Box::new(sink.clone()),
        writers_shutdown_token.clone(),
    ));
    let (a2a_audit_tx, a2a_audit_rx) =
        streamscope_core::audit::a2a::create_a2a_audit_channel();
    let a2a_audit_writer_handle = tokio::spawn(streamscope_core::audit::a2a::a2a_audit_writer_task(
        a2a_audit_rx,
        Box::new(sink.clone()),
        writers_shutdown_token.clone(),
    ));
    // The MCP virtual server (`/mcp/web`) emits into `web_audit_tx`.
    let (web_audit_tx, web_audit_rx) =
        streamscope_core::web::create_web_audit_channel();
    let web_audit_writer_handle = tokio::spawn(streamscope_core::web::web_audit_writer_task(
        web_audit_rx,
        Box::new(sink.clone()),
        writers_shutdown_token.clone(),
    ));

    // MCP SSE event pipeline: bounded MPSC for `Last-Event-ID` replay rows.
    // A record that finds the channel full is dropped (the pumps `try_send`) —
    // durability is best-effort; the audit row is the long-term record. Capacity defaults to MCP_SSE_EVENT_TX_BUFFER.
    let (mcp_sse_event_tx, mcp_sse_event_rx) =
        streamscope_core::audit::counted_channel::<streamscope_core::mcp::sse_events::McpSseEventRecord>(
            proxy_settings().mcp_sse_event_tx_buffer,
        );
    let mcp_sse_writer_handle = tokio::spawn(edge_link::mcp_sse_event_writer_task(
        mcp_sse_event_rx,
        sink.clone(),
        writers_shutdown_token.clone(),
    ));

    // What `outbox_pending` counts: the LLM pipeline's unfinished stream audit
    // tasks, every audit channel's records not yet forwarded, and the outbox.
    let audit_task_tracker = tokio_util::task::TaskTracker::new();
    let pending = edge_link::Pending::new(
        audit_task_tracker.clone(),
        vec![
            audit_tx.pending_count(),
            mcp_audit_tx.pending_count(),
            a2a_audit_tx.pending_count(),
            web_audit_tx.pending_count(),
            mcp_sse_event_tx.pending_count(),
        ],
        outbox.clone(),
    );

    // Per-session SSE sequence allocator. Mounted on `McpAppState` so the
    // `tools/call` SSE pump and the GET-channel handler share one counter
    // per `(tenant_id, mcp_session_id)`.
    let mcp_sse_seq = mcp::sse_seq::McpSseSequenceMap::new();

    // Per-user OAuth refresh-token rotation: a rotated credential (already
    // ciphertext) goes into the outbox before admin-api has it, so a process
    // that dies between the refresh and the delivery still delivers it on its
    // next start — the previous refresh token is already spent upstream.
    let rotation_sink: std::sync::Arc<dyn mcp::oauth::RotationSink> = std::sync::Arc::new(sink.clone());

    // Create upstream HTTP client.
    let http_client = UpstreamClient::new()?;

    // Create script engine and active programs store.
    let script_engine = Arc::new(streamscope_core::scripting::ScriptEngine::new());
    let initial_programs = if let Ok(Some(snapshot)) = config_snapshot::load_snapshot(&data_dir) {
        config_sync::collect_multi_tenant_programs(&snapshot)
    } else {
        Vec::new()
    };
    let active_programs = Arc::new(arc_swap::ArcSwap::from_pointee(initial_programs));

    // Create live proxy stats (atomic counters, zero overhead on hot path).
    let proxy_stats = Arc::new(stats::ProxyStats::new());

    let session_capacity = s.session_detector_capacity;
    let session_max_entries = s.session_detector_max_entries;
    let session_ttl = s.session_detector_ttl;

    // SSRF-guarded clients for web search backend calls (the substitution
    // agent loop and `/mcp/web`) — sized for moderate-throughput one-shot
    // calls, separate from the LLM upstream client (different pool / timeout
    // profile). An internal address is reached only when the platform's
    // `extensions` egress list lists it.
    let web_search_clients = Arc::new(
        streamscope_core::extension_http::ExtensionClients::build(
            "search",
            || {
                streamscope_core::tls::add_custom_roots(
                    reqwest::Client::builder().pool_max_idle_per_host(8).timeout(
                        std::time::Duration::from_secs(
                            crate::settings::proxy_settings().mcp_http_client_timeout_secs,
                        ),
                    ),
                    streamscope_core::settings::core_settings().custom_ca_bundle.as_deref(),
                )
            },
        )
        .expect("build web search http clients"),
    );

    // Build app state.
    let usage = Arc::new(streamscope_core::usage::UsageTracker::new());

    // Passive per-upstream-server circuit breaker (data-plane, in-memory) plus
    // the channel its health transitions travel on to the edge connection, which
    // forwards them to admin as operator notifications.
    let circuit_breaker = Arc::new(streamscope_core::proxy::health::CircuitBreaker::new(
        proxy_settings().upstream_circuit_breaker_enabled,
        proxy_settings().upstream_circuit_breaker_failure_threshold,
        std::time::Duration::from_secs(proxy_settings().upstream_circuit_breaker_cooldown_secs),
    ));
    let (health_event_tx, health_event_rx) = tokio::sync::mpsc::channel(256);
    let dispatch_gate = Arc::new(streamscope_core::proxy::dispatch_gate::DispatchGate::new(
        streamscope_core::proxy::dispatch_gate::GateSettings {
            // Three polls: one missed read is ordinary, three in a row is an
            // engine that stopped answering, and its last word must not stand.
            load_max_age: std::time::Duration::from_secs(
                proxy_settings().qos_metrics_poll_secs.max(1) * 3,
            ),
            default_ttl: std::time::Duration::from_millis(proxy_settings().qos_queue_ttl_ms),
            max_ttl: std::time::Duration::from_millis(proxy_settings().qos_queue_ttl_max_ms),
            max_held: proxy_settings().qos_max_held_requests,
            // A quarter of the budget per pool: enough that one busy model can
            // queue properly, little enough that it cannot take the whole
            // gateway's capacity to hold and refuse everyone else.
            max_held_per_pool: (proxy_settings().qos_max_held_requests / 4).max(16),
            ..streamscope_core::proxy::dispatch_gate::GateSettings::default()
        },
    ));

    let state = Arc::new(AppState {
        usage: usage.clone(),
        http_client,
        tenant_registry: tenant_registry.clone(),
        audit_tx,
        session_detector: streamscope_core::proxy::content::SessionDetector::with_capacity(
            session_capacity,
            session_ttl,
            session_max_entries,
        ),
        inline_exchanges: streamscope_core::proxy::inline_exchange::InlineExchangeStore::default(),
        script_engine: script_engine.clone(),
        lb_counters: dashmap::DashMap::new(),
        circuit_breaker: circuit_breaker.clone(),
        health_event_tx: Some(health_event_tx),
        proxy_stats: proxy_stats.clone(),
        web_search_clients,
        web_audit_tx: Some(web_audit_tx.clone()),
        mixed_pending_cache: Arc::new(streamscope_core::web::MixedPendingCache::default()),
        response_cache: Arc::new({
            let max_bytes = proxy_settings().response_cache_max_bytes();
            tracing::info!(
                max_bytes,
                explicit = proxy_settings().response_cache_max_mb.is_some(),
                "response cache ceiling"
            );
            streamscope_core::proxy::response_cache::ResponseCache::new(
                usize::try_from(max_bytes).unwrap_or(usize::MAX),
                proxy_settings().response_cache_max_entries_per_tenant,
            )
        }),
        audit_task_tracker: audit_task_tracker.clone(),
        config_ready: config_ready.clone(),
        dispatch_gate: dispatch_gate.clone(),
    });

    // Read each capacity-limited endpoint's own load, so several replicas of
    // this gateway share one engine instead of each filling it.
    streamscope_core::proxy::qos_metrics::spawn_poller(
        dispatch_gate.clone(),
        tenant_registry.clone(),
        // Built with the deployment's own roots like every other outbound
        // client here: an engine whose /metrics is served under a private CA
        // would otherwise fail every read silently, and the gate would quietly
        // fall back to its in-flight count with nothing saying so. Guarded by
        // the `llm` egress list, as every call to a provider is.
        Box::new(|| {
            streamscope_core::proxy::client::provider_client_builder(
                streamscope_core::settings::core_settings().custom_ca_bundle.as_deref(),
            )
            .build()
            .or_else(|e| {
                tracing::error!("metrics poller client: {e}; falling back to the default roots");
                streamscope_core::proxy::client::provider_client_builder(None).build()
            })
        }),
        std::time::Duration::from_secs(proxy_settings().qos_metrics_poll_secs.max(1)),
        loops_shutdown_token.clone(),
    );

    // Spawn periodic mixed-pending cache pruning. The cache is per-edge and
    // grows on mixed-pending dispatches; prune at TTL/4 cadence so a quiet
    // proxy doesn't accumulate stale entries indefinitely.
    let mixed_pending_handle = {
        let prune_state = state.clone();
        let token = loops_shutdown_token.clone();
        tokio::spawn(async move {
            // Sweep cadence: TTL/4 with a 60s floor and 900s (15min) ceiling.
            let ttl = prune_state.mixed_pending_cache.ttl();
            let cadence = ttl
                .checked_div(4)
                .unwrap_or(std::time::Duration::from_secs(900))
                .max(std::time::Duration::from_secs(60))
                .min(std::time::Duration::from_secs(900));
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(cadence) => {
                        let pruned = prune_state.mixed_pending_cache.prune_expired();
                        if pruned > 0 {
                            tracing::debug!(
                                pruned,
                                sessions = prune_state.mixed_pending_cache.session_count(),
                                "mixed-pending cache pruned expired entries"
                            );
                        }
                        // Response cache shares the sweep: TTL-on-read alone
                        // would leave an entry nobody asks for again resident
                        // until eviction pressure reached it.
                        let expired = prune_state.response_cache.prune_expired();
                        if expired > 0 {
                            tracing::debug!(
                                expired,
                                entries = prune_state.response_cache.len(),
                                bytes = prune_state.response_cache.total_bytes(),
                                "response cache pruned expired entries"
                            );
                        }
                    }
                }
            }
        })
    };

    // Load session state snapshot from disk (startup recovery).
    match session_snapshot::load_snapshot(&snapshot_data_dir) {
        Ok(Some(entries)) => {
            let count: usize = entries.values().map(|v| v.len()).sum();
            tracing::info!(users = entries.len(), entries = count, "loaded session snapshot from disk");
            state.session_detector.import_entries(entries);
        }
        Ok(None) => tracing::debug!("no session snapshot found, starting with empty state"),
        Err(e) => tracing::warn!(error = %e, "failed to load session snapshot, starting with empty state"),
    }

    // Spawn periodic session detector pruning (removes expired user entries).
    let session_prune_handle = {
        let prune_state = state.clone();
        let token = loops_shutdown_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(proxy_settings().session_prune_interval) => {
                        prune_state.session_detector.prune_expired_users();
                        tracing::debug!("session detector pruned expired users");
                        // Finalize any inline-AI exchange whose response never
                        // arrived, so an analyzed request never loses its row.
                        streamscope_core::proxy::inline_exchange::sweep_abandoned(&prune_state);
                    }
                }
            }
        })
    };

    // Spawn periodic session state snapshot (idle-aware, forced max interval).
    let snapshot_handle = {
        let snap_state = state.clone();
        let snap_dir = snapshot_data_dir.clone();
        let max_interval = proxy_settings().session_snapshot_interval_secs;
        let token = loops_shutdown_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                        if snap_state.session_detector.should_snapshot(max_interval) {
                            let entries = snap_state.session_detector.export_entries();
                            let dir = snap_dir.clone();
                            if let Err(e) = tokio::task::spawn_blocking(move || {
                                session_snapshot::save_snapshot(&dir, &entries)
                            }).await.unwrap_or_else(|e| Err(anyhow::anyhow!("spawn_blocking panicked: {e}"))) {
                                tracing::warn!(error = %e, "failed to save session snapshot");
                            }
                        }
                    }
                }
            }
        })
    };

    // The edge link: config sync and events, and shipping the outbox.
    let edge_handle = {
        let targets = config_sync::ConfigTargets {
            tenant_registry: tenant_registry.clone(),
            script_engine: script_engine.clone(),
            active_programs: active_programs.clone(),
            config_ready: config_ready.clone(),
            response_cache: state.response_cache.clone(),
        };
        let sync = sync_v2::SyncV2::load(targets, &data_dir);
        // A config restored from disk serves at once only when it was whole.
        if sync.complete() {
            config_ready.store(true, std::sync::atomic::Ordering::Relaxed);
            // A start serving a whole snapshot from disk says so; a sync that
            // keeps failing warns on its own.
            tracing::info!(
                "serving the configuration saved on disk until the control plane answers a config sync"
            );
        }
        tokio::spawn(edge_link::run(edge_link::LinkConfig {
            admin_api_url: proxy_settings().admin_api_url.clone(),
            token: std::env::var("EDGE_TOKEN").unwrap_or_default(),
            instance: edge_instance,
            epoch: process_epoch,
            sync,
            outbox: outbox.clone(),
            pending: pending.clone(),
            tenant_registry: tenant_registry.clone(),
            usage: usage.clone(),
            proxy_stats: proxy_stats.clone(),
            response_cache: state.response_cache.clone(),
            dispatch_gate: dispatch_gate.clone(),
            circuit_breaker: circuit_breaker.clone(),
            health_event_rx,
            mcp_event_bus: mcp_event_bus.clone(),
            ship_now: sink.ship_now(),
            shutdown: edge_shutdown_token.clone(),
        }))
    };

    // Cancellation token signalled at SIGINT/SIGTERM so long-lived MCP
    // GET-channel SSE subscribers can close cleanly (final `: shutdown\n\n`
    // comment + EOF) before axum's graceful_shutdown force-closes them.
    // Without this, clients see TCP RST and can't tell "voluntary close"
    // from "crash"; with it, they reconnect via `Last-Event-ID` and replay.
    let mcp_shutdown_token = tokio_util::sync::CancellationToken::new();

    // MCP gateway router state — separate from `AppState` since it carries its
    // own audit channel + outbound HTTP client.
    let mcp_state = mcp::McpRouterState {
        app: state.clone(),
        mcp: mcp::McpAppState::with_rotation_sink(
            mcp_audit_tx,
            mcp_sse_event_tx,
            web_audit_tx,
            mcp_sse_seq.clone(),
            Some(rotation_sink),
            mcp_event_bus.clone(),
            mcp_shutdown_token.clone(),
        ),
    };

    // A2A gateway router state — the shared `AppState` plus the A2A audit
    // channel.
    let a2a_state = a2a::A2aRouterState {
        app: state.clone(),
        a2a_audit_tx,
    };

    // One limiter for both unauthenticated discovery documents — see
    // `ip_rate_limit`. Per replica, and per process: it is in-memory, so a
    // restart forgives whatever a source had accumulated.
    let metadata_limiter = Arc::new(
        streamscope_core::middleware::ip_rate_limit::RateLimiter::new(
            proxy_settings().public_metadata_rate_limit_max,
            proxy_settings().public_metadata_rate_limit_window.as_secs(),
            ip_rate_limit::PUBLIC_METADATA_LIMIT_CLEANUP_THRESHOLD,
        ),
    );

    #[allow(unused_mut)]
    let mut app = build_app(state.clone(), mcp_state, a2a_state, metadata_limiter);

    // Build the graceful-shutdown future. On SIGTERM/SIGINT we (1) cancel
    // the MCP shutdown token so live GET-channel subscribers send a clean
    // `: shutdown\n\n` SSE comment and close, (2) wait `mcp_get_drain_secs`
    // for that drain to land, then (3) return so axum proceeds with HTTP-
    // level graceful shutdown of in-flight POSTs. Without this ordering,
    // axum force-closes streams and clients can't tell voluntary close
    // from crash.
    let mcp_shutdown_for_signal = mcp_shutdown_token.clone();
    let mcp_drain_secs = proxy_settings().mcp_get_drain_secs;
    let gate_for_signal = dispatch_gate.clone();
    let graceful = async move {
        shutdown_signal().await;
        // A request waiting for capacity cannot be answered by a process that is
        // going away: refuse every hold now, while the caller is still connected
        // and can be told to retry.
        gate_for_signal.begin_shutdown();
        tracing::info!(
            drain_secs = mcp_drain_secs,
            "signalling MCP GET-channel drain"
        );
        mcp_shutdown_for_signal.cancel();
        tokio::time::sleep(std::time::Duration::from_secs(mcp_drain_secs)).await;
    };

    #[cfg(feature = "pprof")]
    {
        app = app.route("/debug/pprof", get(pprof_handler));
        tracing::info!("pprof profiling endpoint enabled at /debug/pprof");
    }

    // Opt-in outbox introspection (default off). Merged after the CORS/panic
    // layers like the pprof route; carries the outbox sink as its own state
    // so it reports the cumulative durable-record counters.
    if proxy_settings().audit_debug_endpoint {
        let debug_router = Router::new()
            .route("/debug/buffered-audit", get(buffered_audit_debug_handler))
            .with_state((sink.clone(), pending.clone()));
        app = app.merge(debug_router);
        tracing::info!("audit debug endpoint enabled at /debug/buffered-audit");
    }

    // Dedicated Prometheus /metrics listener (METRICS_PORT, default off). A
    // separate port by design: the main port rides the public Caddy vhosts
    // unauthenticated, so the scrape surface must never mount there. Bound on
    // the startup path — a misconfigured port fails boot loudly.
    if s.metrics_port > 0 {
        let metrics_router = Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state((
                proxy_stats.clone(),
                outbox.clone(),
                state.response_cache.clone(),
                state.dispatch_gate.clone(),
            ));
        let metrics_listener =
            streamscope_core::metrics::bind_metrics_listener(s.metrics_port).await?;
        tracing::info!("metrics listener on 0.0.0.0:{}", s.metrics_port);
        tokio::spawn(streamscope_core::metrics::serve(
            metrics_listener,
            metrics_router,
            loops_shutdown_token.clone(),
        ));
    }

    // Bind and serve.
    let addr = SocketAddr::from(([0, 0, 0, 0], s.port));
    tracing::info!("listening on {addr}");

    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(s.tcp_backlog)?;
    // Wrap the WHOLE router so `/fwd` path normalization runs BEFORE routing —
    // `Router::layer` runs after route matching and could not rescue an unmatched
    // provider-prefixed path (see build_app / normalize_fwd_path).
    use axum::ServiceExt as _;
    use tower::Layer as _;
    let app = axum::middleware::from_fn(normalize_fwd_path).layer(app);
    // `ConnectInfo` is what gives the public-metadata limiter a key when no
    // trusted forwarding header applies (`TRUSTED_PROXY_HOPS=0`, a directly
    // exposed gateway). A plain `into_make_service` would drop the peer address
    // and silently leave that deployment shape unthrottled.
    axum::serve(
        streamscope_core::net::without_nagle(listener),
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(graceful)
    .await?;

    // HTTP server has drained — no new audit records can be produced. Run the
    // bounded graceful drain: (1) cancel the audit writer tasks so they
    // exhaustively flush every queued record into the outbox, then (2) cancel
    // the edge link so it ships what it can of the outbox, and the background
    // loops so they exit. Writers are awaited before the edge link so its
    // final shipping includes their last flush. The whole sequence is bounded
    // by `graceful_drain_timeout_secs` — on timeout the process exits anyway
    // and undelivered records stay in the outbox, shipped on next startup.
    let drain_deadline =
        std::time::Duration::from_secs(proxy_settings().graceful_drain_timeout_secs);
    let drain = async move {
        // Detached streaming-audit finalization tasks (LLM `spawn_audit_task`,
        // MCP `tools/call` pump) send into the audit channels off the HTTP
        // connection future. Wait for them to finish FIRST — the writer tasks
        // must still be alive to absorb those sends; only then are they
        // cancelled for the exhaustive drain.
        audit_task_tracker.close();
        audit_task_tracker.wait().await;
        tracing::info!("detached audit tasks finished");

        writers_shutdown_token.cancel();
        let (a, b, c, d, e) = tokio::join!(
            audit_writer_handle,
            mcp_audit_writer_handle,
            a2a_audit_writer_handle,
            web_audit_writer_handle,
            mcp_sse_writer_handle,
        );
        for r in [a, b, c, d, e] {
            if let Err(e) = r {
                tracing::warn!(error = %e, "audit writer task join error");
            }
        }
        tracing::info!("audit writer tasks drained");

        edge_shutdown_token.cancel();
        loops_shutdown_token.cancel();
        let (e, f, g, h) = tokio::join!(
            edge_handle,
            mixed_pending_handle,
            session_prune_handle,
            snapshot_handle,
        );
        for r in [e, f, g, h] {
            if let Err(err) = r {
                tracing::warn!(error = %err, "background task join error");
            }
        }
        tracing::info!("edge link + background loops stopped");
    };
    match tokio::time::timeout(drain_deadline, drain).await {
        Ok(()) => tracing::info!("graceful drain complete"),
        Err(_) => tracing::warn!(
            timeout_secs = proxy_settings().graceful_drain_timeout_secs,
            "graceful drain timed out; proceeding to exit \
             (undelivered audit records stay in the outbox, shipped on next startup)"
        ),
    }

    // Graceful shutdown: save final session snapshot before exit. The snapshot
    // task is now stopped (joined above), so there is no double-write race.
    {
        let entries = state.session_detector.export_entries();
        match session_snapshot::save_snapshot(&snapshot_data_dir, &entries) {
            Ok(()) => {
                let count: usize = entries.values().map(|v| v.len()).sum();
                tracing::info!(users = entries.len(), entries = count, "saved session snapshot on shutdown");
            }
            Err(e) => tracing::warn!(error = %e, "failed to save session snapshot on shutdown"),
        }
    }

    tracing::info!("graceful shutdown complete");

    Ok(())
}

/// Outbox introspection: GET /debug/buffered-audit → cumulative
/// process-lifetime counters (monotonic, never decremented on shipping).
/// Gated behind `AUDIT_DEBUG_ENDPOINT` (default off).
///
/// - `mcp_audit_tools_call_durable`: successful `tools/call` MCP audit records
///   committed to the outbox. Lets the proxy-bounce e2e poll for "every call's
///   audit record is crash-durable" before SIGKILL.
/// - `llm_audit`: per-stage emission accounting for the LLM audit pipeline
///   (spawned → finalized → channel → outbox) plus the loss counters; in a
///   drained steady state `channel_sent == buffered + writer_dropped`
///   (`channel_lost` counts rejected sends, disjoint from `channel_sent`),
///   so a persistent gap localizes a lost record's stage (a record the
///   outbox itself dropped — too large to fit, or not serializable; logged —
///   counts in `writer_dropped`).
/// - `outbox_pending`: every record produced and not yet answered by admin-api,
///   counted at the moment of the request (`null` when the outbox cannot be
///   counted) — what a test harness's drain wait polls.
async fn buffered_audit_debug_handler(
    axum::extract::State((sink, pending)): axum::extract::State<(edge_link::OutboxSink, edge_link::Pending)>,
) -> axum::Json<serde_json::Value> {
    let mut llm = streamscope_core::audit::EMISSION_STATS.snapshot();
    llm["buffered"] = serde_json::json!(sink.buffered_llm());
    axum::Json(serde_json::json!({
        "mcp_audit_tools_call_durable": sink.durable_tools_call(),
        "llm_audit": llm,
        // Counted now, as the next sync request would report it: every
        // record produced and not yet answered by admin-api.
        // `null` when the outbox cannot be counted: never a 0 it did not read.
        "outbox_pending": pending.try_count().await.inspect_err(|e| tracing::warn!("debug outbox count failed: {e}")).ok(),
    }))
}

/// Prometheus exposition for the dedicated `METRICS_PORT` listener. The
/// synchronous counters render from `ProxyStats`; the outbox depth is
/// async-only (SQLite count) and the cache series are owned by the cache
/// itself, so both are appended here rather than inside `render_prometheus`.
/// What the metrics listener reads from: every subsystem that owns series of
/// its own.
type MetricsState = (
    Arc<stats::ProxyStats>,
    Arc<outbox_v2::OutboxV2>,
    Arc<streamscope_core::proxy::response_cache::ResponseCache>,
    Arc<streamscope_core::proxy::dispatch_gate::DispatchGate>,
);

async fn metrics_handler(
    axum::extract::State((stats, outbox, cache, gate)): axum::extract::State<MetricsState>,
) -> axum::response::Response {
    let mut buf = streamscope_core::metrics::PromBuf::new();
    stats.render_prometheus(&mut buf);
    stats::render_cache_prometheus(&mut buf, &cache.stats());
    stats::render_gate_prometheus(&mut buf, &gate.stats());
    buf.family(
        "streamscope_proxy_pending_audit_records",
        "gauge",
        "Audit records buffered locally, not yet flushed to the control plane.",
    );
    buf.sample_u64(
        "streamscope_proxy_pending_audit_records",
        &[],
        outbox.pending().await.unwrap_or(0),
    );
    axum::response::IntoResponse::into_response(streamscope_core::metrics::metrics_response(
        buf.finish(),
    ))
}

/// CPU profiling endpoint: GET /debug/pprof?seconds=10 → flamegraph SVG.
#[cfg(feature = "pprof")]
async fn pprof_handler(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;

    let seconds: u64 = params
        .get("seconds")
        .and_then(|s| s.parse().ok())
        .unwrap_or(PPROF_DEFAULT_SECS);
    let seconds = seconds.min(PPROF_MAX_SECS);

    tracing::info!(seconds, "starting CPU profiling");

    let guard = match pprof::ProfilerGuardBuilder::default()
        .frequency(PPROF_FREQUENCY)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
    {
        Ok(g) => g,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("pprof start failed: {e}"))
                .into_response();
        }
    };

    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;

    let report = match guard.report().build() {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("pprof report failed: {e}"))
                .into_response();
        }
    };

    let mut body = Vec::new();
    if let Err(e) = report.flamegraph(&mut body) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("flamegraph render failed: {e}"))
            .into_response();
    }

    tracing::info!(bytes = body.len(), "CPU profiling complete, returning flamegraph");

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/svg+xml")],
        body,
    )
        .into_response()
}

/// Assemble the production HTTP surface: the LLM + BYOK + media routes, the MCP
/// gateway router, and the global panic/CORS layers, in the exact shape `run`
/// serves. Kept a pure function of the two states (no listener, no I/O) so the
/// in-process router tests drive the SAME construction the binary does — a
/// dropped route or layer fails in `cargo test`, not only in an E2E run.
///
/// The opt-in `/debug/*` merges and the dedicated `METRICS_PORT` listener stay in
/// `run`: they carry their own state, and `/metrics` must NEVER mount here (the
/// public vhosts reverse-proxy this whole port unauthenticated).
/// Normalize a BYOK `/fwd/{key}/…` request path to its canonical API endpoint
/// BEFORE routing. A transparent inline gateway re-originates a recognized provider request
/// verbatim, so a provider whose base URL carries a path prefix — OpenRouter
/// (`openrouter.ai/api`), Groq (`/openai`), Fireworks (`/inference`), Cohere
/// (`/compatibility`), DeepInfra (`/v1/openai`), … — arrives as e.g.
/// `/fwd/{key}/api/v1/chat/completions`, which matches none of the canonical
/// `/fwd/{key}/v1/…` routes and 404s. The gateway re-emits canonically from
/// `X-Origin-Host`, so ONLY the endpoint type (chat / responses / messages /
/// gemini / media) matters, never the provider prefix — rewrite to the canonical
/// tail and the existing handlers apply unchanged. (This also routes a
/// `/v1/openai/chat/completions`-shaped path to the chat handler instead of the
/// media catch-all.)
async fn normalize_fwd_path(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(canon) = canonical_fwd_path(req.uri().path()) {
        // Rebuild via `from_parts`, replacing ONLY path_and_query — an h2 request
        // carries `:scheme`/`:authority` in the URI (no Host header), so reparsing a
        // bare path string would drop them.
        let pq = match req.uri().query() {
            Some(q) => format!("{canon}?{q}"),
            None => canon,
        };
        match pq.parse::<axum::http::uri::PathAndQuery>() {
            Ok(p) => {
                let mut parts = req.uri().clone().into_parts();
                parts.path_and_query = Some(p);
                match axum::http::Uri::from_parts(parts) {
                    Ok(uri) => *req.uri_mut() = uri,
                    Err(e) => tracing::warn!("fwd path normalize: rebuild uri failed: {e}"),
                }
            }
            Err(e) => tracing::warn!("fwd path normalize: bad path_and_query: {e}"),
        }
    }
    next.run(req).await
}

/// The canonical `/fwd/{key}/…` path for a request whose endpoint sits under a
/// provider base prefix, or `None` when it is already canonical / not a rewrite
/// target (left for the existing routes + catch-all). `{key}` is preserved
/// verbatim (raw `split_once` — an encoded slash cannot shift the key segment),
/// so the rewrite can only change which handler runs, never the auth key.
fn canonical_fwd_path(path: &str) -> Option<String> {
    let (key, tail) = path.strip_prefix("/fwd/")?.split_once('/')?;
    if key.is_empty() || tail.is_empty() {
        return None;
    }
    let canon_tail = canonical_fwd_endpoint(tail)?;
    if tail == canon_tail {
        return None;
    }
    Some(format!("/fwd/{key}/{canon_tail}"))
}

/// The canonical endpoint tail (`v1/…`) for a possibly-prefixed endpoint path,
/// matched by trailing SEGMENT so any provider base prefix is tolerated, or
/// `None` when unrecognized (left for the existing routes + catch-all). Preserves
/// the chat / responses / messages / completions distinction the forward handler
/// keys on.
fn canonical_fwd_endpoint(tail: &str) -> Option<String> {
    let t = tail.trim_end_matches('/');
    // MCP forward routes (`/fwd/{key}/mcp/{slug}`) are never LLM endpoints; a
    // tenant-chosen slug (`models`, `messages`, …) must never be rewritten into a
    // proxy handler.
    if t == "mcp" || t.starts_with("mcp/") {
        return None;
    }
    // Gemini keeps its whole `v1beta/models/{model}:verb` shape (variable segment);
    // anchor on a `/` boundary. The bare `…/v1beta/models` ListModels endpoint is
    // Gemini-format, so leave it untouched rather than fold it into the OpenAI list.
    if let Some(idx) = t.rfind("/v1beta/models/") {
        return Some(t[idx + 1..].to_string());
    }
    if t == "v1beta/models" || t.ends_with("/v1beta/models") {
        return None;
    }
    // A tail ALREADY rooted at `v1/` is canonical, or a canonical SUB-resource
    // (`v1/threads/{id}/messages`, `v1/chat/completions/{id}/messages`, …) that the
    // existing routes + `/fwd/{key}/v1/{*path}` catch-all serve verbatim — never
    // re-derive it from a trailing suffix, or a sub-resource ending in a known verb
    // would be hijacked into the wrong pipeline. A real provider BASE prefix never
    // starts with `v1/`; the one exception is the OpenAI-compat base
    // `v1/openai/<endpoint>` (DeepInfra), whose endpoint we canonicalize so it runs
    // the chat pipeline instead of the media catch-all.
    if let Some(rest) = t.strip_prefix("v1/openai/") {
        return endpoint_by_suffix(rest);
    }
    if t.starts_with("v1/") {
        return None;
    }
    endpoint_by_suffix(t)
}

/// The canonical `v1/…` endpoint for a path carrying a provider BASE prefix,
/// matched by trailing segment (most specific first — `chat/completions` precedes
/// bare `completions` so legacy `/v1/completions` maps distinctly), or `None`.
fn endpoint_by_suffix(t: &str) -> Option<String> {
    const MAP: &[(&str, &str)] = &[
        ("messages/count_tokens", "v1/messages/count_tokens"),
        ("chat/completions", "v1/chat/completions"),
        ("responses", "v1/responses"),
        ("completions", "v1/completions"),
        ("messages", "v1/messages"),
        ("complete", "v1/complete"),
        ("embeddings", "v1/embeddings"),
        ("audio/speech", "v1/audio/speech"),
        ("audio/transcriptions", "v1/audio/transcriptions"),
        ("audio/translations", "v1/audio/translations"),
        ("images/generations", "v1/images/generations"),
        ("images/edits", "v1/images/edits"),
        ("images/variations", "v1/images/variations"),
        ("videos/generations", "v1/videos/generations"),
        ("models", "v1/models"),
    ];
    for (suf, canon) in MAP {
        if ends_with_segment(t, suf) {
            return Some((*canon).to_string());
        }
    }
    None
}

/// `t` equals `suf`, or ends with `suf` on a path-segment boundary (the byte
/// before the suffix is `/`). Avoids a per-candidate `format!` allocation on the
/// hot path (this runs for every request).
fn ends_with_segment(t: &str, suf: &str) -> bool {
    t == suf
        || (t.len() > suf.len()
            && t.ends_with(suf)
            && t.as_bytes()[t.len() - suf.len() - 1] == b'/')
}

fn build_app(
    state: Arc<AppState>,
    mcp_state: mcp::McpRouterState,
    a2a_state: a2a::A2aRouterState,
    metadata_limiter: Arc<streamscope_core::middleware::ip_rate_limit::RateLimiter>,
) -> Router {
    // CORS layer — permissive by default (API-key authenticated), or locked
    // to a single origin via PROXY_CORS_ORIGIN env var.
    let cors = if let Some(origin) = &proxy_settings().cors_origin {
        CorsLayer::new()
            .allow_origin(
                origin
                    .parse::<axum::http::HeaderValue>()
                    .expect("invalid PROXY_CORS_ORIGIN value"),
            )
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(AllowHeaders::mirror_request())
    } else {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(AllowHeaders::mirror_request())
    };

    // Every gateway error is rendered in the grammar of the protocol its route
    // speaks (`error::envelope`): a client SDK parses an error only in its own
    // grammar, and prints any other as raw JSON. The protocol comes from the
    // route — each group below carries the layer for its protocol — never from
    // the request. The remaining routes speak the OpenAI grammar, which is
    // `AppError`'s own rendering, so they carry none.
    let anthropic_routes = Router::new()
        .route("/v1/messages", post(proxy::proxy_handler))
        .route(
            "/v1/messages/count_tokens",
            post(proxy::count_tokens_handler),
        )
        .route("/fwd/{key}/v1/messages", post(proxy::fwd_proxy_handler))
        .route(
            "/fwd/{key}/v1/messages/count_tokens",
            post(proxy::fwd_count_tokens_handler),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            ApiVersion::AnthropicMessages,
            envelope::render_errors_in,
        ));
    let gemini_routes = Router::new()
        // Google Gemini downstream routes (wildcard — axum doesn't allow {param}:suffix)
        // The generate verbs POST here; Google's `models.get` is a GET on the same
        // shape. Both ride the ONE wildcard rather than a `{model}` segment beside
        // it: an alias may contain a slash (`openrouter/free`), and a param route
        // next to a catch-all at the same position is a router conflict.
        .route(
            "/v1beta/models/{*gemini_path}",
            post(proxy::proxy_handler).get(proxy::gemini_model_get_handler),
        )
        // Gemini lists at its own path, so the shape is decided by the route
        // rather than by anything read off the request.
        .route("/v1beta/models", get(proxy::gemini_models_handler))
        // BYOK Google Gemini routes (wildcard — axum doesn't allow {param}:suffix).
        // Two path params (key + gemini_path) → dedicated 2-tuple handler.
        .route(
            "/fwd/{key}/v1beta/models/{*gemini_path}",
            post(proxy::fwd_gemini_handler).get(proxy::fwd_gemini_model_get_handler),
        )
        .route("/fwd/{key}/v1beta/models", get(proxy::fwd_gemini_models_handler))
        .route_layer(axum::middleware::from_fn_with_state(
            ApiVersion::GoogleGemini,
            envelope::render_errors_in,
        ));
    // `/v1/models` is the one path two specs share; its grammar — list and
    // errors alike — is the client's `anthropic-version` declaration.
    let model_list_routes = Router::new()
        .route("/v1/models", get(proxy::models_handler))
        .route("/fwd/{key}/v1/models", get(proxy::fwd_models_handler))
        .route_layer(axum::middleware::from_fn(proxy::render_model_list_errors));

    // Every inbound body must arrive whole within its surface's deadline: the
    // model, MCP and A2A routes share one, the media and pass-through routes —
    // larger uploads — have their own. `route_layer` keeps each to its group.
    let core = streamscope_core::settings::core_settings();
    let deadline = |limit: std::time::Duration| {
        axum::middleware::from_fn_with_state(limit, body_deadline::bound_request_body)
    };

    let media_routes = Router::new()
        .route("/v1/embeddings", post(proxy::media::media_handler))
        .route("/v1/audio/speech", post(proxy::media::media_handler))
        .route("/v1/audio/transcriptions", post(proxy::media::media_handler))
        .route("/v1/audio/translations", post(proxy::media::media_handler))
        .route("/v1/images/generations", post(proxy::media::media_handler))
        .route("/v1/images/edits", post(proxy::media::media_handler))
        .route("/v1/images/variations", post(proxy::media::media_handler))
        .route("/v1/videos/generations", post(proxy::media::media_handler))
        // BYOK forward-auth media routes
        .route("/fwd/{key}/v1/embeddings", post(proxy::media::fwd_media_handler))
        .route("/fwd/{key}/v1/audio/speech", post(proxy::media::fwd_media_handler))
        .route("/fwd/{key}/v1/audio/transcriptions", post(proxy::media::fwd_media_handler))
        .route("/fwd/{key}/v1/audio/translations", post(proxy::media::fwd_media_handler))
        .route("/fwd/{key}/v1/images/generations", post(proxy::media::fwd_media_handler))
        .route("/fwd/{key}/v1/images/edits", post(proxy::media::fwd_media_handler))
        .route("/fwd/{key}/v1/images/variations", post(proxy::media::fwd_media_handler))
        .route("/fwd/{key}/v1/videos/generations", post(proxy::media::fwd_media_handler))
        // Catch-all: forward unmatched /v1/* paths as-is
        .route("/v1/{*path}", any(proxy::media::catchall_handler))
        .route("/fwd/{key}/v1/{*path}", any(proxy::media::fwd_catchall_handler))
        .route_layer(deadline(core.media_request_body_deadline));

    let app = Router::new()
        .route("/v1/chat/completions", post(proxy::proxy_handler))
        .route("/v1/responses", post(proxy::proxy_handler))
        // Out-of-band analysis RPC: an external enforcement point (an inline gateway's
        // ICAP sidecar) submits an intercepted LLM request; the pipeline runs
        // (tool policy → transforms → inbound guardrail) and the verdict +
        // transformed body come back instead of an upstream forward.
        .route("/v1/analyze", post(proxy::analyze::analyze_handler))
        // BYOK forward-auth routes: /fwd/{key}/v1/...
        .route("/fwd/{key}/v1/chat/completions", post(proxy::fwd_proxy_handler))
        .route("/fwd/{key}/v1/responses", post(proxy::fwd_proxy_handler))
        .merge(anthropic_routes)
        .merge(gemini_routes)
        .merge(model_list_routes)
        .route_layer(deadline(core.request_body_deadline))
        .merge(media_routes)
        .route("/health", get(proxy::health_check))
        .route("/ready", get(proxy::readiness_check))
        .with_state(state.clone());

    let mcp_router = Router::new()
        // POST: synchronous JSON-RPC + streaming `tools/call` / `prompts/get`
        // SSE responses. GET: long-lived SSE channel for server-initiated
        // events (sampling, elicitation, list_changed) fanned via the
        // per-(tenant, user) bus. DELETE: per spec § Session Management —
        // sessions sweep on idle so we reply 405 (spec explicitly permits).
        .route(
            "/mcp/{slug}",
            post(mcp::mcp_handler)
                .get(mcp::mcp_get_handler)
                .delete(mcp::mcp_delete_handler),
        )
        // BYOK (`vk-*`) keys forward the client's bearer to the
        // single byot upstream bound to the slug. Same handler shape as
        // `/mcp/{slug}` after auth resolution; capability cache is bypassed.
        .route("/fwd/{key}/mcp/{slug}", post(mcp::mcp_fwd_handler))
        .route_layer(deadline(core.request_body_deadline))
        .with_state(mcp_state);

    let a2a_router = Router::new()
        // POST: the A2A JSON-RPC 2.0 binding.
        .route("/a2a/{slug}", post(a2a::a2a_handler))
        .route_layer(deadline(core.request_body_deadline))
        .with_state(a2a_state.clone());

    // The unauthenticated discovery documents, mounted apart from the routers
    // above solely so ONE per-source-IP limiter covers both of them: a client
    // must be able to read them before it holds any credential, and each
    // resolves its slug by scanning the tenant registry. `route_layer` keeps the
    // throttle off every other route, and off unmatched paths.
    //
    // The A2A card is served at BOTH well-known filenames — `agent-card.json` is
    // the spec path, `agent.json` the pre-0.3 legacy alias half the ecosystem
    // still requests. The MCP handler refers clients to its metadata document
    // via `WWW-Authenticate` on 401.
    let metadata_throttle = axum::middleware::from_fn_with_state(
        metadata_limiter,
        ip_rate_limit::public_metadata_rate_limit_mw,
    );
    let mcp_metadata_router: Router = Router::new()
        .route(
            "/.well-known/oauth-protected-resource/mcp/{slug}",
            get(mcp::spec_oauth::protected_resource_metadata_handler),
        )
        .with_state(state.clone());
    let a2a_card_router: Router = Router::new()
        .route(
            "/a2a/{slug}/.well-known/agent-card.json",
            get(a2a::agent_card_handler),
        )
        .route(
            "/a2a/{slug}/.well-known/agent.json",
            get(a2a::agent_card_handler),
        )
        .with_state(a2a_state);
    let public_metadata_router = mcp_metadata_router
        .merge(a2a_card_router)
        .route_layer(metadata_throttle);

    // NOTE: `/fwd` path normalization is NOT applied here — `Router::layer` runs
    // AFTER route matching, so a layer here could not rescue an unmatched
    // provider-prefixed path. `run` wraps the whole router with
    // `axum::middleware::from_fn(normalize_fwd_path)` at the serve site instead
    // (the axum-documented pattern for rewriting a request URI ahead of routing),
    // so it runs BEFORE routing.
    app.merge(mcp_router)
        .merge(a2a_router)
        .merge(public_metadata_router)
        .layer(CatchPanicLayer::custom(handle_panic))
        .layer(cors)
}

/// Wait for SIGINT (Ctrl+C) or SIGTERM, then signal graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT, starting graceful shutdown"),
        () = terminate => tracing::info!("received SIGTERM, starting graceful shutdown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    #[test]
    fn fwd_path_canonicalizes_provider_base_prefixes() {
        // OpenRouter (/api), Groq (/openai), Fireworks (/inference), Cohere
        // (/compatibility) — the client path carries the provider base, which the
        // canonical /fwd routes never match; normalize strips it to the endpoint.
        for (raw, want) in [
            ("/fwd/vk-x/api/v1/chat/completions", "/fwd/vk-x/v1/chat/completions"),
            ("/fwd/vk-x/openai/v1/chat/completions", "/fwd/vk-x/v1/chat/completions"),
            ("/fwd/vk-x/inference/v1/chat/completions", "/fwd/vk-x/v1/chat/completions"),
            ("/fwd/vk-x/compatibility/v1/chat/completions", "/fwd/vk-x/v1/chat/completions"),
            // DeepInfra's /v1/openai base — the endpoint tail is /chat/completions,
            // which would otherwise fall to the media catch-all, not the chat handler.
            ("/fwd/vk-x/v1/openai/chat/completions", "/fwd/vk-x/v1/chat/completions"),
            // Providers with versioned bases still resolve by suffix.
            ("/fwd/vk-x/v3/openai/chat/completions", "/fwd/vk-x/v1/chat/completions"),
            ("/fwd/vk-x/api/paas/v4/chat/completions", "/fwd/vk-x/v1/chat/completions"),
            // Anthropic-compat and models list under a base.
            ("/fwd/vk-x/anthropic/v1/messages", "/fwd/vk-x/v1/messages"),
            ("/fwd/vk-x/api/v1/models", "/fwd/vk-x/v1/models"),
        ] {
            assert_eq!(canonical_fwd_path(raw).as_deref(), Some(want), "raw={raw}");
        }
    }

    #[test]
    fn fwd_path_leaves_canonical_and_unrelated_paths_untouched() {
        // Already canonical → no rewrite.
        assert_eq!(canonical_fwd_path("/fwd/vk-x/v1/chat/completions"), None);
        assert_eq!(canonical_fwd_path("/fwd/vk-x/v1/messages"), None);
        // Gemini keeps its variable-model shape verbatim.
        assert_eq!(
            canonical_fwd_path("/fwd/vk-x/v1beta/models/gemini-2.0-flash:generateContent"),
            None
        );
        // MCP forward and non-fwd paths are never rewrite targets.
        assert_eq!(canonical_fwd_path("/fwd/vk-x/mcp/some-slug"), None);
        assert_eq!(canonical_fwd_path("/v1/chat/completions"), None);
        assert_eq!(canonical_fwd_path("/fwd/vk-x/"), None);
        // A canonical SUB-resource ending in a known verb must NOT be hijacked — it
        // is already `v1/`-rooted, so the existing routes/catch-all serve it verbatim.
        assert_eq!(
            canonical_fwd_path("/fwd/vk-x/v1/threads/thread_abc/messages"),
            None
        );
        assert_eq!(
            canonical_fwd_path("/fwd/vk-x/v1/chat/completions/cmpl_123/messages"),
            None
        );
        assert_eq!(canonical_fwd_path("/fwd/vk-x/v1/models/some-model"), None);
    }

    #[test]
    fn fwd_gemini_prefixed_base_keeps_the_beta_tail() {
        assert_eq!(
            canonical_fwd_path("/fwd/vk-x/base/v1beta/models/gemini-1.5-pro:generateContent")
                .as_deref(),
            Some("/fwd/vk-x/v1beta/models/gemini-1.5-pro:generateContent")
        );
    }

    #[test]
    fn fwd_path_never_rewrites_mcp_or_gemini_list() {
        // A tenant MCP slug that happens to match an endpoint suffix must NOT be
        // pulled into an LLM handler.
        assert_eq!(canonical_fwd_path("/fwd/vk-x/mcp/models"), None);
        assert_eq!(canonical_fwd_path("/fwd/vk-x/mcp/messages"), None);
        assert_eq!(canonical_fwd_path("/fwd/vk-x/mcp/chat/completions"), None);
        // Gemini ListModels is Gemini-format — not the OpenAI /v1/models list.
        assert_eq!(canonical_fwd_path("/fwd/vk-x/v1beta/models"), None);
        assert_eq!(canonical_fwd_path("/fwd/vk-x/base/v1beta/models"), None);
        // Legacy completions map distinctly from chat completions.
        assert_eq!(
            canonical_fwd_path("/fwd/vk-x/openai/v1/completions").as_deref(),
            Some("/fwd/vk-x/v1/completions")
        );
        assert_eq!(
            canonical_fwd_path("/fwd/vk-x/base/v1/complete").as_deref(),
            Some("/fwd/vk-x/v1/complete")
        );
    }

    #[test]
    fn ends_with_segment_respects_boundaries() {
        assert!(ends_with_segment("v1/chat/completions", "chat/completions"));
        assert!(ends_with_segment("completions", "completions"));
        // Not on a segment boundary — must not match.
        assert!(!ends_with_segment("v1/xcompletions", "completions"));
        assert!(!ends_with_segment("v1/chats", "chat"));
    }

    // The load-bearing test C1 needed: normalization must run BEFORE routing, so a
    // provider-prefixed path reaches the canonical handler rather than the 404
    // fallback. `Router::layer` would fail this; wrapping the whole router passes.
    #[tokio::test]
    async fn normalization_runs_before_routing() {
        use axum::routing::post;
        use tower::Layer as _;
        let router = Router::new()
            .route("/fwd/{key}/v1/chat/completions", post(|| async { "chat" }))
            .route("/fwd/{key}/v1/{*rest}", axum::routing::any(|| async { "catchall" }));
        let app = axum::middleware::from_fn(normalize_fwd_path).layer(router);
        // OpenRouter-shaped prefixed path → must reach the canonical chat route.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/fwd/vk-x/api/v1/chat/completions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(&body[..], b"chat");
    }

    async fn panicking_handler() -> StatusCode {
        panic!("handler boom")
    }

    /// A panic inside a handler must be unwound by `CatchPanicLayer` into a
    /// sanitized 500 — the connection is kept, the panic payload never leaks.
    #[tokio::test]
    async fn panic_in_handler_returns_sanitized_500() {
        let app = Router::new()
            .route("/boom", get(panicking_handler))
            .layer(CatchPanicLayer::custom(handle_panic));

        let resp = app
            .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["type"], "internal_error");
        assert_eq!(body["error"]["message"], "internal server error");
    }
}
