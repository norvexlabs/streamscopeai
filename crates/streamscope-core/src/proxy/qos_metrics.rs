//! Reading an engine's own load, so the gate knows when to stop releasing.
//!
//! The gateway's in-flight count is what THIS replica sent; the engine's queue
//! is what everyone sent, including other gateway replicas and anything else
//! pointed at the same engine. That shared reading is what lets N replicas share
//! one engine without each filling it on its own.
//!
//! An endpoint answers `/metrics` in the Prometheus exposition format. The three
//! gauges the gate acts on decide whether a document is an engine's at all — one
//! that carries none of them yields nothing: recording a zero for a server that
//! never reported would claim headroom nobody measured. Beside them, a handful
//! of the engine's cumulative counters ride along to the dashboards; the gate
//! decides nothing on those.
//!
//! An endpoint is read when its server asks for engine metrics, or when it
//! declares a waiting-queue bound — which cannot apply without the reading.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::dispatch_gate::{DispatchGate, EndpointLoad};
use crate::config::Registry;

/// What one engine said about itself.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EngineReading {
    pub waiting: u32,
    /// Requests running now, and KV-cache use as a fraction — `None` when the
    /// engine does not publish that gauge: a missing gauge is not a zero.
    pub running: Option<u32>,
    pub kv_usage: Option<f64>,
    pub counters: EngineCounters,
    pub info: EngineInfo,
    /// Data-parallel ranks that reported `running` (≥ 1): `running` is their
    /// sum, and an engine's batch cap is set per rank.
    pub ranks: u32,
}

/// An engine's own cumulative counters, as it publishes them: each only ever
/// rises until the engine restarts. A consumer differences two readings and
/// treats a fall as a restart. `None` = the engine does not publish it.
///
/// Summed across series: an engine publishes one series per model it serves
/// (and per data-parallel rank), and the work those count adds up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct EngineCounters {
    /// Requests preempted — evicted from the KV cache and recomputed later.
    pub preemptions: Option<f64>,
    pub prompt_tokens: Option<f64>,
    pub generation_tokens: Option<f64>,
    /// Prompt and answer tokens of the requests that FINISHED, each counted
    /// once its request ended (vLLM's per-request histograms' sums): unlike
    /// `prompt_tokens`, which counts a prompt when its prefill ends, and
    /// `generation_tokens`, which counts each answer token as it is made,
    /// these pair a request's whole prompt with its whole answer.
    pub finished_prompt_tokens: Option<f64>,
    pub finished_generation_tokens: Option<f64>,
    /// Prompt tokens looked up in the GPU prefix cache, and those not
    /// recomputed: found there, or loaded back from the engine's CPU tier
    /// (vLLM's KV offload counts a token it did not hold on the GPU as an
    /// external query, and one it loaded back as an external hit). A prompt
    /// loaded back from RAM costs no prefill, so a hit rate that left it out
    /// would read an engine with offload as recomputing what it does not.
    pub prefix_queries: Option<f64>,
    pub prefix_hits: Option<f64>,
    /// Seconds requests spent in the engine's own waiting queue, and how many.
    pub queue_time_sum: Option<f64>,
    pub queue_time_count: Option<f64>,
    /// Seconds to the first token, and how many requests.
    pub ttft_sum: Option<f64>,
    pub ttft_count: Option<f64>,
    /// Seconds between two output tokens of one request, and how many gaps.
    pub itl_sum: Option<f64>,
    pub itl_count: Option<f64>,
    /// The same gaps by length ([`GapHistogram`]): what this replica's
    /// adaptive window is held against. Read here only, never sent on.
    #[serde(skip)]
    pub itl_gaps: Option<GapHistogram>,
}

/// The most bucket bounds an inter-token histogram is read with (vLLM
/// publishes twenty). One with more is not read at all: a bucket left out
/// would move every quantile above it.
pub const GAP_BUCKETS_MAX: usize = 64;

/// An engine's inter-token latency histogram: for each bucket bound, in
/// seconds and ending at `+Inf`, the gaps between two tokens of one request
/// at or below it, summed across the series that share it — cumulative, as
/// the engine publishes them, so two readings difference into an interval's.
///
/// What it is for is the interval's MEDIAN gap ([`Self::since`]). The mean
/// is a prefill measure on an engine whose prompts outweigh its decode: a
/// prefill chunk scheduled beside the running decodes stalls each of them for
/// the chunk's time (a 2048-token chunk at a few hundred tokens a second is
/// seconds), and those few stalls carry most of the gaps' sum. A concurrency
/// limit cannot bound them — any one new prompt causes them — while the
/// median is the pace of the decode batch the limit sizes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GapHistogram {
    len: usize,
    bounds: [f64; GAP_BUCKETS_MAX],
    counts: [f64; GAP_BUCKETS_MAX],
}

/// The gaps an engine made between two readings of its histogram.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GapInterval {
    pub gaps: f64,
    /// The median gap, in seconds, linearly interpolated within its bucket
    /// (a median in the `+Inf` bucket reads as the last finite bound);
    /// `None` with no gap.
    pub median: Option<f64>,
}

impl Default for GapHistogram {
    fn default() -> Self {
        Self { len: 0, bounds: [0.0; GAP_BUCKETS_MAX], counts: [0.0; GAP_BUCKETS_MAX] }
    }
}

impl GapHistogram {
    /// Count `count` more gaps at or below `bound`: added to a bound already
    /// held, else inserted in order. `false` where no bound is left.
    pub fn add(&mut self, bound: f64, count: f64) -> bool {
        match self.bounds[..self.len].binary_search_by(|b| b.total_cmp(&bound)) {
            Ok(i) => self.counts[i] += count,
            Err(_) if self.len == GAP_BUCKETS_MAX => return false,
            Err(i) => {
                self.bounds.copy_within(i..self.len, i + 1);
                self.counts.copy_within(i..self.len, i + 1);
                self.bounds[i] = bound;
                self.counts[i] = count;
                self.len += 1;
            }
        }
        true
    }

    /// Count `n` more gaps of `seconds` each, at every bound at or above it.
    #[cfg(test)]
    pub fn record(&mut self, seconds: f64, n: f64) {
        for i in 0..self.len {
            if self.bounds[i] >= seconds {
                self.counts[i] += n;
            }
        }
    }

    /// Whether it reads as a histogram: a finite bound and the `+Inf` one,
    /// and counts finite and never falling from one bound to the next.
    fn is_whole(&self) -> bool {
        let counts = &self.counts[..self.len];
        self.len >= 2
            && self.bounds[self.len - 1] == f64::INFINITY
            && counts.iter().all(|c| c.is_finite())
            && counts.windows(2).all(|w| w[0] <= w[1])
    }

    /// The gaps made since `before` and their median ([`GapInterval`]).
    /// `None` where the two do not difference: other bounds, or a count that
    /// fell (a restart) or rose more below a bound than at the next.
    pub fn since(&self, before: &Self) -> Option<GapInterval> {
        if self.bounds[..self.len] != before.bounds[..before.len] {
            return None;
        }
        let mut rises = [0.0; GAP_BUCKETS_MAX];
        for i in 0..self.len {
            let rise = self.counts[i] - before.counts[i];
            if !(rise >= 0.0 && (i == 0 || rise >= rises[i - 1])) {
                return None;
            }
            rises[i] = rise;
        }
        let last = self.len.checked_sub(1)?;
        let gaps = rises[last];
        if gaps <= 0.0 {
            return Some(GapInterval { gaps: 0.0, median: None });
        }
        let half = gaps / 2.0;
        let i = rises[..self.len].iter().position(|r| *r >= half)?;
        let (lower, below) = if i == 0 { (0.0, 0.0) } else { (self.bounds[i - 1], rises[i - 1]) };
        let median = if self.bounds[i].is_finite() {
            lower + (self.bounds[i] - lower) * (half - below) / (rises[i] - below)
        } else {
            lower
        };
        Some(GapInterval { gaps, median: Some(median) })
    }
}

/// A histogram's buckets as one exposition reads them: `None` while none is
/// seen, and spoiled for good by a bucket that does not read.
#[derive(Default)]
struct GapBuckets {
    histogram: Option<GapHistogram>,
    spoiled: bool,
}

impl GapBuckets {
    fn add(&mut self, series: &str, count: f64) {
        let bound = match label_value(series, "le") {
            Some(v) if v.eq_ignore_ascii_case("+Inf") || v.eq_ignore_ascii_case("Inf") => Some(f64::INFINITY),
            Some(v) => v.parse::<f64>().ok().filter(|b| b.is_finite() && *b >= 0.0),
            None => None,
        };
        let added = bound.is_some_and(|b| count >= 0.0 && self.histogram.get_or_insert_default().add(b, count));
        self.spoiled |= !added;
    }

    /// Whether the exposition carried any bucket of it, read or not.
    fn seen(&self) -> bool {
        self.histogram.is_some() || self.spoiled
    }

    fn read(self) -> Option<GapHistogram> {
        self.histogram.filter(|h| !self.spoiled && h.is_whole())
    }
}

/// What an engine says about its own configuration (vLLM `cache_config_info`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineInfo {
    pub num_gpu_blocks: Option<u64>,
    pub block_size: Option<u64>,
}

impl EngineInfo {
    /// How many tokens the KV cache holds, when both halves are known.
    pub fn kv_capacity_tokens(&self) -> Option<u64> {
        self.num_gpu_blocks?.checked_mul(self.block_size?)
    }
}

/// Where an endpoint publishes its metrics: at the server root, whatever path
/// its API lives under. An endpoint is often entered with the `/v1` an OpenAI
/// client appends; vLLM serves `/metrics` beside `/v1`, never under it.
pub fn engine_metrics_url(endpoint_url: &str) -> String {
    let base = endpoint_url.trim_end_matches('/');
    let base = base.strip_suffix("/v1").unwrap_or(base).trim_end_matches('/');
    format!("{base}/metrics")
}

/// The value of one label in a `name{a="1",b="2"}` series.
///
/// Read the way the exposition format writes it: a value is a quoted string in
/// which `\"` and `\\` are escapes, so a comma, an `=` or a `}` inside a value is
/// part of that value — splitting on commas would let one label's value
/// masquerade as another label. `None` for a missing label or a malformed
/// set; the value is returned still escaped, which is exact for the plain
/// numbers this reads.
fn label_value<'a>(series: &'a str, label: &str) -> Option<&'a str> {
    let body = &series[series.find('{')? + 1..];
    let mut rest = body;
    loop {
        rest = rest.trim_start_matches([' ', ',']);
        if rest.starts_with('}') || rest.is_empty() {
            return None;
        }
        let eq = rest.find('=')?;
        let key = rest[..eq].trim();
        let after = rest[eq + 1..].trim_start().strip_prefix('"')?;
        // The closing quote is the first one not escaped.
        let mut end = None;
        let mut escaped = false;
        for (i, c) in after.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let end = end?;
        if key == label {
            return Some(&after[..end]);
        }
        rest = &after[end + 1..];
    }
}

/// The three gauges, read out of a Prometheus exposition.
///
/// An engine publishes one series per model it serves while the queue it
/// describes is shared, so the highest series is the honest reading: the pool is
/// as busy as its busiest member says it is.
pub fn parse_engine_metrics(text: &str) -> Option<EngineReading> {
    // Gauges per data-parallel rank (vLLM's `engine` label; absent = one rank).
    // Within a rank, series for several models describe ONE queue, so the
    // highest is the honest reading; ranks each run their own queue and batch,
    // so the endpoint's waiting and running are their SUM. KV use is a fraction
    // per rank: the fullest rank is the one that preempts first.
    let mut ranks: std::collections::BTreeMap<String, [Option<f64>; 3]> = std::collections::BTreeMap::new();
    let mut counters = EngineCounters::default();
    let mut old_itl: (Option<f64>, Option<f64>) = (None, None);
    let (mut gaps, mut old_gaps) = (GapBuckets::default(), GapBuckets::default());
    let mut external_hits: Option<f64> = None;
    let mut info = EngineInfo::default();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // `name{labels} value [timestamp]`. The value is the FIRST field after
        // the labels, not the last on the line: the exposition format allows a
        // millisecond timestamp after it, and reading from the right would take
        // that timestamp as the gauge — a number large enough to exceed any
        // threshold and wedge the endpoint. Labels may themselves contain
        // spaces, so the split is after the closing brace where there is one.
        let (name, rest) = match line.rfind('}') {
            Some(brace) => (&line[..=brace], &line[brace + 1..]),
            None => match line.split_once(char::is_whitespace) {
                Some(parts) => parts,
                None => continue,
            },
        };
        let Some(value) = rest.split_whitespace().next() else {
            continue;
        };
        let Ok(value) = value.parse::<f64>() else {
            continue;
        };
        if !value.is_finite() {
            continue;
        }
        let metric = name.split('{').next().unwrap_or("").trim();
        let gauge = match metric {
            "vllm:num_requests_waiting" => Some(0),
            "vllm:num_requests_running" => Some(1),
            // The same gauge under the name vLLM published before its rename.
            "vllm:kv_cache_usage_perc" | "vllm:gpu_cache_usage_perc" => Some(2),
            _ => None,
        };
        if let Some(i) = gauge {
            let rank = label_value(name, "engine").unwrap_or("").to_string();
            let slot = &mut ranks.entry(rank).or_default()[i];
            *slot = Some(slot.map_or(value, |current: f64| current.max(value)));
            continue;
        }
        match metric {
            "vllm:inter_token_latency_seconds_bucket" => {
                gaps.add(name, value);
                continue;
            }
            // Read where the new name is absent, as its sum and count are.
            "vllm:time_per_output_token_seconds_bucket" => {
                old_gaps.add(name, value);
                continue;
            }
            _ => {}
        }
        let counter = match metric {
            "vllm:num_preemptions_total" => Some(&mut counters.preemptions),
            "vllm:prompt_tokens_total" => Some(&mut counters.prompt_tokens),
            "vllm:generation_tokens_total" => Some(&mut counters.generation_tokens),
            "vllm:request_prompt_tokens_sum" => Some(&mut counters.finished_prompt_tokens),
            "vllm:request_generation_tokens_sum" => Some(&mut counters.finished_generation_tokens),
            // Also under the names published beside the older KV gauge name.
            "vllm:prefix_cache_queries_total" | "vllm:gpu_prefix_cache_queries_total" => {
                Some(&mut counters.prefix_queries)
            }
            "vllm:prefix_cache_hits_total" | "vllm:gpu_prefix_cache_hits_total" => Some(&mut counters.prefix_hits),
            // Prompt tokens loaded back from the CPU tier (folded in below).
            "vllm:external_prefix_cache_hits_total" => Some(&mut external_hits),
            "vllm:request_queue_time_seconds_sum" => Some(&mut counters.queue_time_sum),
            "vllm:request_queue_time_seconds_count" => Some(&mut counters.queue_time_count),
            "vllm:time_to_first_token_seconds_sum" => Some(&mut counters.ttft_sum),
            "vllm:time_to_first_token_seconds_count" => Some(&mut counters.ttft_count),
            "vllm:inter_token_latency_seconds_sum" => Some(&mut counters.itl_sum),
            "vllm:inter_token_latency_seconds_count" => Some(&mut counters.itl_count),
            // The name vLLM published before its rename: read only where the
            // new one is absent (below), never added to it — an engine in the
            // deprecation window publishes the same histogram under both.
            "vllm:time_per_output_token_seconds_sum" => Some(&mut old_itl.0),
            "vllm:time_per_output_token_seconds_count" => Some(&mut old_itl.1),
            _ => None,
        };
        if let Some(slot) = counter {
            if value >= 0.0 {
                *slot = Some(slot.unwrap_or(0.0) + value);
            }
            continue;
        }
        if metric == "vllm:cache_config_info" {
            let number = |label| label_value(name, label).and_then(|v| v.parse::<u64>().ok());
            info.num_gpu_blocks = info.num_gpu_blocks.or(number("num_gpu_blocks"));
            info.block_size = info.block_size.or(number("block_size"));
        }
    }
    let fold = |i: usize, across: fn(f64, f64) -> f64| {
        ranks.values().filter_map(|g| g[i]).reduce(across)
    };
    if counters.itl_sum.is_none() && counters.itl_count.is_none() {
        (counters.itl_sum, counters.itl_count) = old_itl;
    }
    counters.itl_gaps = if gaps.seen() { gaps.read() } else { old_gaps.read() };
    // A hit is a prompt token not recomputed, wherever it was found: the CPU
    // tier's hits join the GPU's, over the GPU's lookups (the CPU tier is
    // asked only for what the GPU did not hold). Folded only where the GPU's
    // lookups are published, as a rate needs them.
    if let Some(external) = external_hits
        && counters.prefix_queries.is_some()
    {
        counters.prefix_hits = Some(counters.prefix_hits.unwrap_or(0.0) + external);
    }
    let waiting = fold(0, |a, b| a + b);
    let running = fold(1, |a, b| a + b);
    let kv = fold(2, f64::max);
    if waiting.is_none() && running.is_none() && kv.is_none() {
        return None;
    }
    // A sum of finite values can still overflow: a counter that is no longer a
    // number is not a reading, and differencing it would chart NaN.
    for c in [
        &mut counters.preemptions,
        &mut counters.prompt_tokens,
        &mut counters.generation_tokens,
        &mut counters.finished_prompt_tokens,
        &mut counters.finished_generation_tokens,
        &mut counters.prefix_queries,
        &mut counters.prefix_hits,
        &mut counters.queue_time_sum,
        &mut counters.queue_time_count,
        &mut counters.ttft_sum,
        &mut counters.ttft_count,
        &mut counters.itl_sum,
        &mut counters.itl_count,
    ] {
        if c.is_some_and(|v| !v.is_finite()) {
            *c = None;
        }
    }
    Some(EngineReading {
        waiting: waiting.filter(|v| v.is_finite()).unwrap_or(0.0).max(0.0) as u32,
        running: running.filter(|v| v.is_finite()).map(|v| v.max(0.0) as u32),
        kv_usage: kv.map(|v| v.clamp(0.0, 1.0)),
        counters,
        info,
        ranks: u32::try_from(ranks.values().filter(|g| g[1].is_some()).count()).unwrap_or(u32::MAX).max(1),
    })
}

/// Every live endpoint's bounds as configured, in one walk of the registry.
/// Its keys are every endpoint the configuration has; the gated ones are those
/// that still declare a bound of any kind — what an operator has cleared is no
/// longer among them, which is how the gate learns to stop applying it to
/// whoever is already queued.
fn endpoint_bounds(registry: &Registry) -> std::collections::HashMap<Uuid, super::dispatch_gate::EndpointBounds> {
    let mut bounds = std::collections::HashMap::new();
    for cfg in registry.values() {
        for endpoints in cfg.endpoints.servers.values() {
            for e in endpoints {
                bounds.insert(e.id, super::dispatch_gate::EndpointBounds {
                    gated: e.gated(),
                    max_in_flight: e.max_in_flight,
                    waiting_threshold: e.waiting_threshold,
                    adaptive: e.adaptive_concurrency,
                    itl_target: e.adaptive_itl_target,
                    url: e.url.clone(),
                    engine_read: e.engine_read(),
                });
            }
        }
    }
    bounds
}

/// One endpoint a pass will ask, and what it takes to be let in.
struct PollTarget<'a> {
    id: Uuid,
    url: String,
    /// The owning server's stored credential, borrowed from the configuration
    /// the pass reads — `None` when it has none to present.
    credential: Option<Result<&'a str, crate::config::credentials::CredentialMiss>>,
}

/// What one pass asked, what answered, and why the rest did not.
///
/// Both halves are needed to say anything about an engine going quiet: the
/// difference between them is the event, and a count of answers cannot express
/// it. Endpoints are carried with their URL because that is what an operator
/// recognises in a log line, and the failures with the reason, because "this
/// endpoint is not answering" is not something anyone can act on: a refused
/// read, an unreachable host and an endpoint that is not an engine at all need
/// three different things done about them.
pub struct PollOutcome {
    /// Every endpoint this pass asked, and where.
    pub asked: std::collections::HashMap<Uuid, String>,
    /// Those that answered with a usable reading.
    pub answered: std::collections::HashSet<Uuid>,
    /// Why each of the others did not.
    pub failures: std::collections::HashMap<Uuid, ReadFailure>,
    /// Endpoints read where the configuration no longer places them: neither
    /// an answer nor a silence about where they are now.
    pub overtaken: std::collections::HashSet<Uuid>,
}

/// Why one endpoint's gauges did not arrive, in the terms an operator fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFailure {
    pub kind: FailureKind,
    /// What the read presented, so a refusal can be told apart from a refusal
    /// of something we never sent.
    pub credential: CredentialState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The endpoint answered, and said no.
    Refused(u16),
    /// Nothing answered: name resolution, connection, or the read deadline.
    Unreachable,
    /// A document arrived carrying none of the gauges the gate reads — which is
    /// what a non-vLLM endpoint, or the wrong path, looks like.
    NoGauges,
    /// A body arrived that could not be read as text.
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    /// The server has one and the read presented it.
    Presented,
    /// The server has none to present, which is the ordinary case.
    None,
    /// The server has one and this replica could not produce it.
    Unresolved(crate::config::credentials::CredentialMiss),
}

impl std::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            FailureKind::Refused(status) => write!(f, "refused the read with HTTP {status}")?,
            FailureKind::Unreachable => f.write_str("could not be reached")?,
            FailureKind::NoGauges => {
                f.write_str("answered without the queue gauges — is this an inference engine?")?
            }
            FailureKind::Unreadable => f.write_str("answered with a body that could not be read")?,
        }
        match self.credential {
            CredentialState::Presented => f.write_str(" (the server's credential was presented)"),
            CredentialState::None => Ok(()),
            CredentialState::Unresolved(miss) => {
                write!(f, " (no credential was presented: the server's is {})", miss.as_str())
            }
        }
    }
}

/// Every endpoint whose engine this gateway reads
/// ([`EndpointConfig::engine_read`](crate::config::endpoints::EndpointConfig::engine_read)):
/// one entry per (id, url), across every tenant, because one engine may serve
/// several of them.
///
/// Each carries the credential its own traffic is forwarded with. A plain
/// engine serves `/metrics` to anyone — vLLM's `--api-key` guards `/v1/*` and
/// nothing else — but an operator who puts an authenticating proxy in front of
/// one would otherwise be refused on every read, and a refused read is
/// indistinguishable from an idle engine: the bound they configured silently
/// stops applying. An engine that wants no credential ignores the header.
fn read_endpoints(registry: &Registry) -> Vec<PollTarget<'_>> {
    let mut seen: std::collections::HashMap<Uuid, PollTarget> = std::collections::HashMap::new();
    for cfg in registry.values() {
        for (server_id, endpoints) in &cfg.endpoints.servers {
            if !endpoints.iter().any(crate::config::endpoints::EndpointConfig::engine_read) {
                continue;
            }
            let credential = server_credential(cfg, server_id);
            for e in endpoints {
                if e.engine_read() {
                    seen.entry(e.id).or_insert_with(|| PollTarget {
                        id: e.id,
                        url: e.url.clone(),
                        credential,
                    });
                }
            }
        }
    }
    seen.into_values().collect()
}

/// A read server's stored credential, when it has one.
///
/// The endpoint table carries the credential of every server whose engine is
/// read — routed or not, so a server none of whose models is bound to an alias
/// yet is still asked with its own key. Only the default transport ships one:
/// every other transport mints or signs its credential per request from a
/// document this path has no business replaying.
fn server_credential<'a>(
    cfg: &'a crate::config::TenantConfig,
    server_id: &Uuid,
) -> Option<Result<&'a str, crate::config::credentials::CredentialMiss>> {
    cfg.endpoints
        .read_credentials
        .get(server_id)
        .filter(|c| c.transport == crate::config::upstream_transport::UpstreamTransport::Default)
        .map(|_| cfg.credentials.get(&server_id.to_string()))
}

/// Requests one replica holds for a server, of one class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassHeld {
    /// `None`: a tenant with no classes.
    pub class_id: Option<Uuid>,
    pub held: u32,
    /// The most of this class held at once since the replica's previous beat
    /// (≥ `held`).
    pub held_peak: u32,
}

/// One gated or read endpoint's live load, as a proxy replica reports it to
/// admin on every heartbeat. The gateway's own figures are gauges, read as they
/// are; the engine's counters are the engine's cumulatives, which a consumer
/// differences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointLoadReport {
    pub tenant_id: Uuid,
    pub server_id: Uuid,
    pub endpoint_id: Uuid,
    /// Requests this replica has in flight at the endpoint — counted only
    /// where the endpoint is `gated`; an endpoint read only for its metrics
    /// takes the ungated fast path and is never counted, so its 0 means
    /// nothing.
    pub in_flight: u32,
    /// The most in flight at once since the replica's previous beat (≥
    /// `in_flight`): the beat is an instant, and a burst between two beats
    /// would otherwise be lost.
    pub in_flight_peak: u32,
    /// Whether the endpoint declares a bound, so `in_flight` is a count.
    pub gated: bool,
    /// Requests this replica is holding for want of capacity on the endpoint's
    /// SERVER. A held request waits for the server's pool, not for one replica,
    /// so every endpoint row of one server carries the same figure: take it
    /// once per (replica, server), never sum it across a server's endpoints.
    pub server_held: u32,
    /// The most held at once since the previous beat, per pool of the server,
    /// summed over its pools (≥ `server_held`; an upper bound when the server
    /// has several pools, whose peaks need not coincide).
    pub server_held_peak: u32,
    /// The same held requests, per class — repeated on every endpoint row of
    /// the server like `server_held`.
    pub server_held_by_class: Vec<ClassHeld>,
    /// Whether this replica reads the engine's own gauges here: its server asks
    /// for engine metrics, or the endpoint declares a waiting-queue bound.
    pub engine_read: bool,
    /// The engine's gauges, while the last reading is fresh enough for the gate
    /// to act on. `None` on an endpoint that is read means the engine has gone
    /// quiet — its queue bound is not being applied.
    pub engine: Option<EngineGauges>,
    /// Where the endpoint's learned in-flight limit stands; `None` when the
    /// limit is not learned.
    pub adaptive: Option<super::dispatch_gate::AdaptiveStatus>,
}

/// An engine's own gauges, and how old the reading is.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EngineGauges {
    /// The waiting count the gate acts on (0 when the engine publishes none).
    pub waiting: u32,
    /// `None` when the engine does not publish the gauge.
    pub running: Option<u32>,
    /// KV-cache use, a fraction in `[0, 1]`; `None` when not published.
    pub kv_usage: Option<f64>,
    /// The highest of each gauge over the readings taken since the previous
    /// beat (each ≥ the instant above). `None` for a gauge the engine does
    /// not publish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_peak: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running_peak: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kv_usage_peak: Option<f64>,
    /// The most running in one reading that also had a queue, since the
    /// previous beat — where the engine queues. `None` when no reading queued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running_queued_peak: Option<u32>,
    pub age_ms: u64,
    /// The engine's cumulative counters.
    pub counters: EngineCounters,
}

/// One server's held requests per class: every class held now or at any
/// moment since the previous beat — one that peaked and drained in between is
/// listed holding 0, with its peak — in class order.
fn classes_held(
    held: Option<&std::collections::BTreeMap<Option<Uuid>, u32>>,
    peak: Option<&std::collections::BTreeMap<Option<Uuid>, u32>>,
) -> Vec<ClassHeld> {
    let mut classes: std::collections::BTreeMap<Option<Uuid>, u32> = held.cloned().unwrap_or_default();
    for class_id in peak.into_iter().flat_map(|p| p.keys()) {
        classes.entry(*class_id).or_insert(0);
    }
    classes
        .into_iter()
        .map(|(class_id, held)| ClassHeld {
            class_id,
            held,
            held_peak: peak.and_then(|p| p.get(&class_id)).copied().unwrap_or(0).max(held),
        })
        .collect()
}

/// The live load of every endpoint the configuration has that is gated (a bound
/// of either kind) or read ([`EndpointConfig::engine_read`](crate::config::endpoints::EndpointConfig::engine_read)). Any other is not reported: the gate
/// keeps no count for it and nobody reads its engine, so a row of zeros would
/// read as an idle engine.
pub fn load_report(gate: &DispatchGate, registry: &Registry) -> Vec<EndpointLoadReport> {
    let snapshot = gate.report_snapshot();
    // A held queue is keyed by endpoint ids, all of one server; charge it to
    // that server through any of them.
    let mut server_of: std::collections::HashMap<Uuid, Uuid> = std::collections::HashMap::new();
    for cfg in registry.values() {
        for (server_id, endpoints) in &cfg.endpoints.servers {
            server_of.extend(endpoints.iter().map(|e| (e.id, *server_id)));
        }
    }
    let mut held: std::collections::HashMap<Uuid, u32> = std::collections::HashMap::new();
    let mut held_by_class: std::collections::HashMap<Uuid, std::collections::BTreeMap<Option<Uuid>, u32>> =
        std::collections::HashMap::new();
    for h in &snapshot.held {
        if let Some(server_id) = h.endpoints.first().and_then(|e| server_of.get(e)) {
            let total = held.entry(*server_id).or_default();
            *total = total.saturating_add(h.count);
            let per_class = held_by_class.entry(*server_id).or_default().entry(h.class_id).or_default();
            *per_class = per_class.saturating_add(h.count);
        }
    }
    // The peaks the same way: per pool, summed over the server's pools.
    let mut held_peak: std::collections::HashMap<Uuid, u32> = std::collections::HashMap::new();
    for (pool, peak) in &snapshot.peaks.held_pool {
        if let Some(server_id) = pool.first().and_then(|e| server_of.get(e)) {
            let total = held_peak.entry(*server_id).or_default();
            *total = total.saturating_add(*peak);
        }
    }
    let mut class_peak: std::collections::HashMap<Uuid, std::collections::BTreeMap<Option<Uuid>, u32>> =
        std::collections::HashMap::new();
    for ((pool, class_id), peak) in &snapshot.peaks.held_class {
        if let Some(server_id) = pool.first().and_then(|e| server_of.get(e)) {
            let total = class_peak.entry(*server_id).or_default().entry(*class_id).or_default();
            *total = total.saturating_add(*peak);
        }
    }
    let mut out = Vec::new();
    for (tenant_id, cfg) in registry.iter() {
        for (server_id, endpoints) in &cfg.endpoints.servers {
            // The same for every endpoint row of the server; built at its first.
            let mut by_class: Option<Vec<ClassHeld>> = None;
            for e in endpoints {
                if e.max_in_flight.is_none() && !e.engine_read() {
                    continue;
                }
                let gated = e.gated();
                out.push(EndpointLoadReport {
                    tenant_id: tenant_id.0,
                    server_id: *server_id,
                    endpoint_id: e.id,
                    in_flight: snapshot.in_flight.get(&e.id).copied().unwrap_or(0),
                    in_flight_peak: snapshot.peaks.in_flight.get(&e.id).copied().unwrap_or(0),
                    gated,
                    server_held: held.get(server_id).copied().unwrap_or(0),
                    server_held_peak: held_peak.get(server_id).copied().unwrap_or(0),
                    server_held_by_class: by_class
                        .get_or_insert_with(|| classes_held(held_by_class.get(server_id), class_peak.get(server_id)))
                        .clone(),
                    engine_read: e.engine_read(),
                    engine: snapshot.engine.get(&e.id).map(|(load, age)| EngineGauges {
                        waiting: load.waiting,
                        running: load.running,
                        kv_usage: load.kv_usage,
                        waiting_peak: snapshot.peaks.engine.get(&e.id).map(|p| p.waiting),
                        running_peak: snapshot.peaks.engine.get(&e.id).and_then(|p| p.running),
                        kv_usage_peak: snapshot.peaks.engine.get(&e.id).and_then(|p| p.kv_usage),
                        running_queued_peak: snapshot.peaks.engine.get(&e.id).and_then(|p| p.running_queued),
                        age_ms: u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
                        counters: load.counters,
                    }),
                    // Before the poller has given the endpoint its window, the
                    // gate holds it to its ceiling, which is what is reported.
                    adaptive: e.adaptive_concurrency.then(|| {
                        snapshot.adaptive.get(&e.id).copied().unwrap_or(super::dispatch_gate::AdaptiveStatus {
                            limit: e.max_in_flight,
                            state: super::adaptive_concurrency::AdaptiveState::Starting,
                            low_load_itl_us: None,
                            decisions: None,
                        })
                    }),
                });
            }
        }
    }
    out
}

/// Read every gated endpoint once, and report what answered.
pub async fn poll_once(
    gate: &Arc<DispatchGate>,
    registry: &Registry,
    client: &reqwest::Client,
    timeout: Duration,
    only: Option<&std::collections::HashSet<Uuid>>,
) -> PollOutcome {
    let mut targets = read_endpoints(registry);
    if let Some(only) = only {
        targets.retain(|t| only.contains(&t.id));
    }

    // Read them all at once. Sequentially, a handful of slow or unreachable
    // engines make one pass take longer than a reading's shelf life, and every
    // HEALTHY endpoint's reading expires too — the gate then silently falls
    // back to the in-flight count and loses the cross-replica coordination this
    // whole path exists for.
    let readings = futures::future::join_all(targets.iter().map(|t| {
        read_one(gate, client, t.id, &t.url, t.credential.transpose(), timeout)
    }))
    .await;

    let mut answered = std::collections::HashSet::new();
    let mut failures = std::collections::HashMap::new();
    // A reading the configuration has overtaken (the endpoint moved or went
    // during the pass) is no answer about where the endpoint is now — and no
    // silence either: it was not asked there. Only a moved one is `overtaken`
    // (its silence carries on); a dropped one is simply no longer asked.
    let mut overtaken = std::collections::HashSet::new();
    let mut dropped = std::collections::HashSet::new();
    for (target, reading) in targets.iter().zip(readings) {
        // One answer from the gate, under one lock: where the configuration
        // places the endpoint now, relative to where it was read. A failed
        // read of where it no longer is says nothing about where it is.
        let placement = match reading {
            Ok(load) => gate.record_read(target.id, &target.url, load),
            Err(failure) => {
                let placement = gate.placement(target.id, &target.url);
                if placement == super::dispatch_gate::Placement::Here {
                    failures.insert(target.id, failure);
                }
                placement
            }
        };
        match placement {
            super::dispatch_gate::Placement::Here => {
                if !failures.contains_key(&target.id) {
                    answered.insert(target.id);
                }
            }
            super::dispatch_gate::Placement::Moved => {
                overtaken.insert(target.id);
            }
            super::dispatch_gate::Placement::Dropped => {
                dropped.insert(target.id);
            }
        }
    }
    PollOutcome {
        asked: targets
            .into_iter()
            .filter(|t| !overtaken.contains(&t.id) && !dropped.contains(&t.id))
            .map(|t| (t.id, t.url))
            .collect(),
        overtaken,
        answered,
        failures,
    }
}

/// Which endpoints have gone quiet for long enough to matter, and which have
/// just started answering again.
///
/// The edge is the event. A per-poll count would write a line every few seconds
/// saying nothing, while the thing an operator has to know — that a bound they
/// configured has quietly stopped applying — happens once and then looks like
/// an idle engine for ever. `misses` carries that state between passes.
///
/// An endpoint that has never answered is reported like any other: a knob set
/// against an engine the gateway cannot read has never done anything, which is
/// exactly the case worth naming.
fn reading_transitions(
    outcome: &PollOutcome,
    threshold: u32,
    misses: &mut std::collections::HashMap<Uuid, u32>,
) -> (Vec<Uuid>, Vec<Uuid>) {
    // An endpoint an operator has un-gated or deleted is not silent — it is no
    // longer asked. Forgetting it here is what makes it report again if it
    // comes back. One moved during the pass keeps its count: its silence
    // carries on until where it is now answers.
    misses.retain(|id, _| outcome.asked.contains_key(id) || outcome.overtaken.contains(id));

    let mut went_quiet = Vec::new();
    let mut came_back = Vec::new();
    for id in outcome.asked.keys() {
        if outcome.answered.contains(id) {
            // Coming back is only worth saying if the silence was.
            if misses.remove(id).is_some_and(|n| n >= threshold) {
                came_back.push(*id);
            }
        } else {
            let seen = misses.entry(*id).or_insert(0);
            *seen += 1;
            // Exactly at the threshold, so a lasting outage is named once
            // rather than on every pass for as long as it lasts.
            if *seen == threshold {
                went_quiet.push(*id);
            }
        }
    }
    (went_quiet, came_back)
}

/// How many passes in a row an endpoint must fail to answer before it is worth
/// reporting.
///
/// DERIVED from what the gate actually does, never chosen: the gate applies a
/// reading until it is `load_max_age` old, so this is the first pass on which
/// nothing of that endpoint's is being applied any more — which is exactly what
/// the report claims. A constant would be the same number today and a lie the
/// moment either setting moved, in whichever direction: too low and it cries
/// wolf while the last reading is still in force, too high and the outage it
/// exists to name goes unreported.
///
/// Never below two, so one missed read is never an outage. A read can be lost
/// to a slow engine, a dropped packet, or a pass the configuration overtook,
/// and an alarm that fires on
/// any of those is one an operator learns to ignore.
fn silent_passes_before_reporting(load_max_age: Duration, interval: Duration) -> u32 {
    let interval = interval.as_millis().max(1);
    let passes = load_max_age.as_millis() / interval;
    // `+ 1`: at exactly `load_max_age` the reading is still applied, so the
    // pass after it is the first on which the bound has stopped.
    u32::try_from(passes.saturating_add(1)).unwrap_or(u32::MAX).max(2)
}

/// One endpoint's reading, or why there is none.
///
/// Unreachable, refusing, and answering with a document that carries none of
/// the gauges all mean the same thing to the gate — nothing was measured, so
/// nothing is recorded — and three different things to whoever has to fix it.
async fn read_one(
    gate: &Arc<DispatchGate>,
    client: &reqwest::Client,
    id: Uuid,
    url: &str,
    credential: Result<Option<&str>, crate::config::credentials::CredentialMiss>,
    timeout: Duration,
) -> Result<EndpointLoad, ReadFailure> {
    let endpoint = engine_metrics_url(url);
    let mut request = client.get(&endpoint).timeout(timeout);
    // As a bearer token, whatever scheme the server's own API uses: `/metrics`
    // is not that API, and what stands in front of an engine checks the one
    // scheme. A front door expecting another scheme refuses the read, which the
    // poller reports as the endpoint going quiet.
    let state = match credential {
        Ok(Some(credential)) if !credential.trim().is_empty() => {
            request = request.bearer_auth(credential);
            CredentialState::Presented
        }
        Ok(_) => CredentialState::None,
        // The read still goes out: an engine that wants no credential answers
        // it, and only a refusal makes the missing one worth naming.
        Err(miss) => CredentialState::Unresolved(miss),
    };
    let failed = |kind: FailureKind| ReadFailure { kind, credential: state };

    // An IP literal never reaches the client's resolver: vetted here against
    // the `llm` egress list, as every provider call is.
    if super::client::check_provider_url(&endpoint).is_err() {
        return Err(failed(FailureKind::Unreachable));
    }
    let response = request.send().await.map_err(|_| failed(FailureKind::Unreachable))?;
    if !response.status().is_success() {
        return Err(failed(FailureKind::Refused(response.status().as_u16())));
    }
    let body = crate::http_body::read_body_capped(response, METRICS_BODY_CAP)
        .await
        .map_err(|_| failed(FailureKind::Unreadable))?;
    // Both taken when the engine answered, not when the pass finished
    // collecting: the readings are gathered concurrently, so stamping them
    // together would date a fast engine's answer by however long the slowest
    // one took — and every request dispatched in that window would be counted
    // against neither the gauge nor the mark.
    let read_at = Instant::now();
    let mark = gate.dispatch_mark(id);
    let text = String::from_utf8(body.to_vec()).map_err(|_| failed(FailureKind::Unreadable))?;
    let reading = parse_engine_metrics(&text).ok_or_else(|| failed(FailureKind::NoGauges))?;
    Ok(EndpointLoad {
        waiting: reading.waiting,
        running: reading.running,
        kv_usage: reading.kv_usage,
        read_at,
        mark,
        counters: reading.counters,
        ranks: reading.ranks,
    })
}

/// An engine's exposition is a few hundred series; anything far larger is not
/// one, and reading it would charge this replica's memory for a stranger's
/// document.
pub const METRICS_BODY_CAP: u64 = 2 * 1024 * 1024;

/// Hand the gate the bounds `snapshot` states, and forget the endpoints it no
/// longer has. Returns the endpoints the gate now needs a reading of
/// ([`DispatchGate::adopt_configuration`]).
fn adopt_configuration(gate: &DispatchGate, snapshot: &Registry) -> std::collections::HashSet<Uuid> {
    let bounds = endpoint_bounds(snapshot);
    let live = bounds.keys().copied().collect();
    let gated = bounds.iter().filter(|(_, b)| b.gated).map(|(id, _)| *id).collect();
    gate.retain_endpoints(&live, &gated);
    gate.adopt_configuration(&bounds)
}

/// Whether every tenant's endpoint table is the same in both registries — a
/// change elsewhere in the configuration leaves the gate's bounds as they are.
fn endpoints_unchanged(previous: &Registry, next: &Registry) -> bool {
    previous.len() == next.len()
        && next.iter().all(|(tenant, cfg)| {
            previous.get(tenant).is_some_and(|was| Arc::ptr_eq(was, cfg) || was.endpoints == cfg.endpoints)
        })
}

/// The engines' client, built by `build_client` and rebuilt when the egress
/// lists change, so an idle pooled connection never outlives the listing it
/// was opened under. A pass whose client cannot be built reads nothing.
pub type PollerClient = Box<dyn Fn() -> Result<reqwest::Client, reqwest::Error> + Send + Sync>;

/// Poll every gated endpoint on a timer until the process shuts down, and
/// adopt each new configuration as it arrives.
pub fn spawn_poller(
    gate: Arc<DispatchGate>,
    registry: crate::config::TenantRegistry,
    build_client: PollerClient,
    interval: Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    // Every configuration's bounds are adopted as it is published, before
    // anything can route on it (`on_publish` runs ahead of the store, and under
    // the same lock as that store), so a limit holds from the first request the
    // new configuration serves; the registry this process holds now is adopted
    // here, under that lock too. The poller's own loop only reads. Endpoints a
    // configuration leaves without the reading they need are read on their
    // own, ahead of the next pass — only they, so a stream of changes never
    // becomes a stream of reads of every engine.
    let unread: Arc<std::sync::Mutex<std::collections::HashSet<Uuid>>> = Arc::default();
    let clients: streamscope_mcp_auth::egress::Cached<reqwest::Client> = streamscope_mcp_auth::egress::Cached::new();
    registry.on_publish(
        |current| {
            adopt_configuration(&gate, current);
        },
        {
            let (gate, unread, shutdown) = (gate.clone(), unread.clone(), shutdown.clone());
            move |previous, next| {
                // A process shutting down reads nothing more; what it still
                // routes keeps the bounds it has.
                if shutdown.is_cancelled() || endpoints_unchanged(previous, next) {
                    return;
                }
                let ids = adopt_configuration(&gate, next);
                unread.lock().unwrap_or_else(std::sync::PoisonError::into_inner).extend(ids);
                // A raised or removed bound may free what is waiting now.
                gate.reconsider();
            }
        },
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // How many passes in a row each endpoint has failed to answer, so only
        // the edges are reported. Lives with the poller: it is a fact about
        // this replica's reads, not about the configuration.
        let mut misses: std::collections::HashMap<Uuid, u32> = std::collections::HashMap::new();
        let threshold = silent_passes_before_reporting(gate.settings().load_max_age, interval);
        let take_unread = || std::mem::take(&mut *unread.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        let mut changes = registry.changes();
        loop {
            let pending = !unread.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty();
            // A pass that is due comes first: it reads every engine, unread
            // ones included, and is where silence is judged — a stream of
            // changes must not put it off.
            let full = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => true,
                () = std::future::ready(()), if pending => false,
                Ok(()) = changes.changed() => continue,
            };
            // Built before the unread set is taken, so a pass that cannot read
            // leaves it for the next one — which waits for the next tick: the
            // set is still pending, and retrying at once would spin.
            let client = match clients.get_or_try_build(super::client::LLM_EGRESS, &build_client) {
                Ok(client) => client,
                Err(e) => {
                    tracing::error!("engine metrics poller: could not build its client: {e}");
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = ticker.tick() => {}
                    }
                    continue;
                }
            };
            // Under the publish lock: the ids and the registry are from the
            // same side of any publish, so an endpoint a publish leaves unread
            // is in the registry read here, or still in the set for the next
            // read. A full pass also states the configuration to the gate once
            // more — its source of truth, so bounds a request recorded from an
            // older snapshot, and what was kept for an endpoint dropped while
            // busy, do not outlive it — and reads every endpoint, unread ones
            // included. (A moved endpoint's last reading, kept while it was
            // busy, stands until the new machine answers or it ages out.)
            let (unread_now, snapshot) = registry.locked(|current| {
                if full {
                    adopt_configuration(&gate, current);
                }
                (take_unread(), current.clone())
            });
            let only = (!full).then_some(unread_now);
            // Half the interval: a reading that has not arrived by the time
            // the next one is due is of no use to anyone.
            let outcome = tokio::select! {
                _ = shutdown.cancelled() => return,
                outcome = poll_once(&gate, &snapshot, &client, interval / 2, only.as_ref()) => outcome,
            };
            // Silence is judged over whole passes only: a read of a few
            // endpoints says nothing about the others.
            if full {
                let (went_quiet, came_back) =
                    reading_transitions(&outcome, threshold, &mut misses);
                for id in went_quiet {
                    tracing::warn!(
                        endpoint = %id,
                        url = outcome.asked.get(&id).map(String::as_str).unwrap_or(""),
                        reason = %outcome
                            .failures
                            .get(&id)
                            .map(ReadFailure::to_string)
                            .unwrap_or_else(|| "unknown".to_string()),
                        "no engine metrics from this endpoint — a queue bound on it is not being \
                         applied (its fixed in-flight limit, if any, still is), a learned in-flight \
                         limit holds at its ceiling or else its last learned value, and its engine \
                         charts have a gap"
                    );
                }
                for id in came_back {
                    tracing::info!(
                        endpoint = %id,
                        url = outcome.asked.get(&id).map(String::as_str).unwrap_or(""),
                        "engine metrics are answering again"
                    );
                }
            }
            // And this is the only thing that runs when a reading simply ages
            // out, so it is where a queue held against an expired reading gets
            // looked at again.
            gate.reconsider();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_gauges_are_read_from_an_exposition() {
        let text = "\
# HELP vllm:num_requests_running Number of requests currently running on GPU.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{model_name=\"m\"} 4.0
vllm:num_requests_waiting{model_name=\"m\"} 7.0
vllm:kv_cache_usage_perc{model_name=\"m\"} 0.42
";
        assert_eq!(
            parse_engine_metrics(text),
            Some(EngineReading { waiting: 7, running: Some(4), kv_usage: Some(0.42), counters: Default::default(), info: Default::default(), ranks: 1 })
        );
    }

    #[test]
    fn the_kv_gauge_is_read_under_its_older_name_and_ranks_are_counted() {
        let text = "\
vllm:num_requests_running{engine=\"0\"} 4
vllm:num_requests_running{engine=\"1\"} 6
vllm:num_requests_waiting{engine=\"0\"} 1
vllm:gpu_cache_usage_perc{engine=\"0\"} 0.3
vllm:gpu_cache_usage_perc{engine=\"1\"} 0.5
vllm:gpu_prefix_cache_queries_total 100
vllm:gpu_prefix_cache_hits_total 40
";
        let reading = parse_engine_metrics(text).expect("a reading");
        assert_eq!((reading.running, reading.kv_usage, reading.ranks), (Some(10), Some(0.5), 2));
        assert_eq!((reading.counters.prefix_queries, reading.counters.prefix_hits), (Some(100.0), Some(40.0)));
    }

    #[test]
    fn the_busiest_series_is_the_reading() {
        // One engine, several models, one queue: the highest is the honest one.
        let text = "\
vllm:num_requests_waiting{model_name=\"a\"} 2
vllm:num_requests_waiting{model_name=\"b\"} 9
";
        assert_eq!(parse_engine_metrics(text).expect("read").waiting, 9);
    }

    #[test]
    fn a_sample_with_a_timestamp_reads_the_value_not_the_timestamp() {
        // The exposition format allows `value [timestamp_ms]`. Reading from the
        // right takes the timestamp — a number that exceeds every threshold and
        // reads as an engine that will never be free again.
        let text = "vllm:num_requests_waiting{model_name=\"m\"} 7 1699999999000\n";
        assert_eq!(parse_engine_metrics(text).expect("read").waiting, 7);
    }

    #[test]
    fn a_label_containing_a_space_does_not_confuse_the_value() {
        let text = "vllm:num_requests_running{model_name=\"a b\"} 3\n";
        assert_eq!(parse_engine_metrics(text).expect("read").running, Some(3));
    }

    #[test]
    fn a_document_carrying_none_of_them_reports_nothing() {
        // Not a zero — claiming headroom nobody measured is how a saturated pool
        // gets flooded.
        let text = "http_requests_total{code=\"200\"} 12\n# TYPE foo gauge\nfoo 1\n";
        assert_eq!(parse_engine_metrics(text), None);
    }

    #[test]
    fn a_missing_gauge_beside_a_present_one_is_absent_not_zero() {
        // The two reported gauges are absent — a dashboard must not draw a
        // zero for a gauge the engine never published.
        let text = "vllm:num_requests_waiting 3\n";
        assert_eq!(
            parse_engine_metrics(text),
            Some(EngineReading { waiting: 3, running: None, kv_usage: None, counters: Default::default(), info: Default::default(), ranks: 1 })
        );
        // The waiting count the gate acts on still reads as zero when it alone
        // is missing: the gate needs a number, and no queue is the reading.
        let text = "vllm:num_requests_running 2\n";
        assert_eq!(parse_engine_metrics(text).expect("read").waiting, 0);
    }

    #[test]
    fn values_that_are_not_numbers_are_skipped() {
        let text = "vllm:num_requests_waiting{model_name=\"m\"} NaN\nvllm:num_requests_running 2\n";
        let reading = parse_engine_metrics(text).expect("read");
        assert_eq!(reading.waiting, 0);
        assert_eq!(reading.running, Some(2));
    }

    #[test]
    fn kv_usage_stays_a_fraction() {
        let text = "vllm:kv_cache_usage_perc 42\n";
        assert_eq!(parse_engine_metrics(text).expect("read").kv_usage, Some(1.0));
    }

    #[test]
    fn the_engines_counters_are_read_and_summed_across_its_series() {
        let text = "\
vllm:num_requests_waiting{model_name=\"m\",engine=\"0\"} 0
vllm:num_preemptions_total{model_name=\"m\",engine=\"0\"} 3
vllm:num_preemptions_total{model_name=\"m\",engine=\"1\"} 4
vllm:num_preemptions_created{model_name=\"m\",engine=\"0\"} 1.7e9
vllm:prompt_tokens_total{model_name=\"m\"} 1000
vllm:generation_tokens_total{model_name=\"m\"} 250
vllm:prefix_cache_queries_total{model_name=\"m\"} 800
vllm:prefix_cache_hits_total{model_name=\"m\"} 600
vllm:request_queue_time_seconds_sum{model_name=\"m\"} 1.5
vllm:request_queue_time_seconds_count{model_name=\"m\"} 10
vllm:request_queue_time_seconds_bucket{model_name=\"m\",le=\"0.3\"} 9
vllm:time_to_first_token_seconds_sum{model_name=\"m\"} 2.0
vllm:time_to_first_token_seconds_count{model_name=\"m\"} 8
vllm:inter_token_latency_seconds_sum{model_name=\"m\"} 3.0
vllm:inter_token_latency_seconds_count{model_name=\"m\"} 100
";
        let c = parse_engine_metrics(text).expect("read").counters;
        // Two data-parallel ranks: their work adds up. A `_created` timestamp
        // and a histogram bucket are other series, never folded into a count.
        assert_eq!(c.preemptions, Some(7.0));
        assert_eq!((c.prompt_tokens, c.generation_tokens), (Some(1000.0), Some(250.0)));
        assert_eq!((c.prefix_queries, c.prefix_hits), (Some(800.0), Some(600.0)));
        assert_eq!((c.queue_time_sum, c.queue_time_count), (Some(1.5), Some(10.0)));
        assert_eq!((c.ttft_sum, c.ttft_count), (Some(2.0), Some(8.0)));
        assert_eq!((c.itl_sum, c.itl_count), (Some(3.0), Some(100.0)));
    }

    #[test]
    fn finished_requests_tokens_are_their_histograms_sums_across_ranks() {
        // One series per data-parallel rank: the sums add up. The flow
        // counters are not the finished requests' tokens, and the buckets and
        // counts are not their sums.
        let text = "vllm:num_requests_waiting 0\n\
vllm:request_prompt_tokens_sum{engine=\"0\"} 3000\n\
vllm:request_prompt_tokens_sum{engine=\"1\"} 1000\n\
vllm:request_prompt_tokens_count{engine=\"0\"} 3\n\
vllm:request_prompt_tokens_bucket{engine=\"0\",le=\"+Inf\"} 3\n\
vllm:request_generation_tokens_sum{engine=\"0\"} 500\n\
vllm:request_generation_tokens_sum{engine=\"1\"} 250\n\
vllm:prompt_tokens_total 90000\n\
vllm:generation_tokens_total 9000\n";
        let c = parse_engine_metrics(text).expect("read").counters;
        assert_eq!((c.finished_prompt_tokens, c.finished_generation_tokens), (Some(4000.0), Some(750.0)));
        assert_eq!((c.prompt_tokens, c.generation_tokens), (Some(90000.0), Some(9000.0)));
        let c = parse_engine_metrics("vllm:num_requests_waiting 0\n").expect("read").counters;
        assert_eq!((c.finished_prompt_tokens, c.finished_generation_tokens), (None, None), "not published");
    }

    #[test]
    fn prompt_tokens_loaded_back_from_the_cpu_tier_are_hits() {
        // 1 000 prompt tokens looked up on the GPU, 300 found there; of the
        // 700 it did not hold the CPU tier was asked and loaded back 500. Hits
        // are 800 of 1 000: only 200 are recomputed.
        let gpu = "vllm:num_requests_waiting 0\n\
vllm:prefix_cache_queries_total 1000\n\
vllm:prefix_cache_hits_total 300\n";
        let offload = format!("{gpu}vllm:external_prefix_cache_queries_total 700\nvllm:external_prefix_cache_hits_total 500\n");
        let c = parse_engine_metrics(&offload).expect("read").counters;
        assert_eq!((c.prefix_queries, c.prefix_hits), (Some(1000.0), Some(800.0)));
        // No CPU tier: the GPU's hits alone.
        let c = parse_engine_metrics(gpu).expect("read").counters;
        assert_eq!((c.prefix_queries, c.prefix_hits), (Some(1000.0), Some(300.0)));
        // CPU hits with no GPU lookups to read them against make no rate.
        let c = parse_engine_metrics("vllm:num_requests_waiting 0\nvllm:external_prefix_cache_hits_total 500\n")
            .expect("read")
            .counters;
        assert_eq!((c.prefix_queries, c.prefix_hits), (None, None));
    }

    #[test]
    fn the_inter_token_histogram_is_read_bucket_by_bucket_and_summed_across_ranks() {
        let text = "\
vllm:num_requests_waiting 0
vllm:inter_token_latency_seconds_bucket{engine=\"0\",le=\"0.05\"} 6
vllm:inter_token_latency_seconds_bucket{engine=\"0\",le=\"0.1\"} 8
vllm:inter_token_latency_seconds_bucket{engine=\"0\",le=\"+Inf\"} 10
vllm:inter_token_latency_seconds_bucket{engine=\"1\",le=\"0.05\"} 4
vllm:inter_token_latency_seconds_bucket{engine=\"1\",le=\"0.1\"} 8
vllm:inter_token_latency_seconds_bucket{engine=\"1\",le=\"+Inf\"} 10
";
        let gaps = parse_engine_metrics(text).expect("read").counters.itl_gaps.expect("a histogram");
        let mut none = gaps;
        none.counts = [0.0; GAP_BUCKETS_MAX];
        // 20 gaps: 10 at or under 50 ms, 16 under 100 ms. The median is the
        // tenth: the last of the first bucket.
        assert_eq!(gaps.since(&none), Some(GapInterval { gaps: 20.0, median: Some(0.05) }));
        // Under the older name where the new one is absent; never mixed.
        let old = text.replace("inter_token_latency_seconds_bucket", "time_per_output_token_seconds_bucket");
        assert_eq!(parse_engine_metrics(&old).expect("read").counters.itl_gaps, Some(gaps));
        let both = format!("{text}vllm:time_per_output_token_seconds_bucket{{le=\"0.01\"}} 1\n");
        assert_eq!(parse_engine_metrics(&both).expect("read").counters.itl_gaps, Some(gaps));
        // The overflow bound in any case, with or without its sign.
        for inf in ["Inf", "+inf", "INF"] {
            let spelled = text.replace("le=\"+Inf\"", &format!("le=\"{inf}\""));
            assert_eq!(parse_engine_metrics(&spelled).expect("read").counters.itl_gaps, Some(gaps), "{inf}");
        }
        // A bucket that does not read, or no `+Inf`, or counts that fall from
        // one bound to the next: no histogram, while the rest reads.
        for broken in [
            format!("{text}vllm:inter_token_latency_seconds_bucket{{le=\"soon\"}} 1\n"),
            format!("{text}vllm:inter_token_latency_seconds_bucket 1\n"),
            text.replace("le=\"+Inf\"", "le=\"5\""),
            text.replace("} 8", "} 30"),
        ] {
            let r = parse_engine_metrics(&broken).expect("read");
            assert_eq!(r.counters.itl_gaps, None, "{broken}");
        }
        // More bounds than are kept: none rather than some.
        let many: String = (1..=GAP_BUCKETS_MAX)
            .map(|i| format!("vllm:inter_token_latency_seconds_bucket{{le=\"{i}\"}} 1\n"))
            .collect();
        let r = parse_engine_metrics(&format!("vllm:num_requests_waiting 0\n{many}vllm:inter_token_latency_seconds_bucket{{le=\"+Inf\"}} 1\n"));
        assert_eq!(r.expect("read").counters.itl_gaps, None);
    }

    #[test]
    fn an_interval_median_is_interpolated_within_its_bucket_and_needs_two_readings_that_difference() {
        let histogram = |counts: [f64; 3]| {
            let mut h = GapHistogram::default();
            for (bound, count) in [0.1, 0.2, f64::INFINITY].into_iter().zip(counts) {
                h.add(bound, count);
            }
            h
        };
        let before = histogram([10.0, 10.0, 10.0]);
        // 40 gaps since: 10 under 100 ms, 30 from 100 to 200 ms. The 20th is
        // a third of the way through the second bucket.
        let median = histogram([20.0, 50.0, 50.0]).since(&before).and_then(|i| i.median).expect("a median");
        assert!((median - (0.1 + 0.1 / 3.0)).abs() < 1e-12, "{median}");
        // Most gaps above every bound: the last finite bound.
        assert_eq!(histogram([10.0, 11.0, 50.0]).since(&before).and_then(|i| i.median), Some(0.2));
        // No gap: an interval with no median.
        assert_eq!(before.since(&before), Some(GapInterval { gaps: 0.0, median: None }));
        // A count that fell (a restart), or other bounds: no interval.
        assert_eq!(histogram([5.0, 60.0, 60.0]).since(&before), None);
        let mut other = before;
        other.add(0.3, 10.0);
        assert_eq!(other.since(&before), None);
        let mut moved = GapHistogram::default();
        for (bound, count) in [(0.1, 20.0), (0.25, 50.0), (f64::INFINITY, 50.0)] {
            moved.add(bound, count);
        }
        assert_eq!(moved.since(&before), None, "as many bounds, not the same");
        // A bound that rose more than the next: not a histogram's interval.
        assert_eq!(histogram([30.0, 20.0, 50.0]).since(&before), None);
    }

    #[test]
    fn the_inter_token_latency_is_read_under_its_older_name_too() {
        let text = "vllm:num_requests_waiting 0\n\
vllm:time_per_output_token_seconds_sum 1.5\n\
vllm:time_per_output_token_seconds_count 30\n";
        let c = parse_engine_metrics(text).expect("read").counters;
        assert_eq!((c.itl_sum, c.itl_count), (Some(1.5), Some(30.0)));
        // Both names, as in vLLM's deprecation window: the new one, alone.
        let both = format!("{text}vllm:inter_token_latency_seconds_sum 1.5\nvllm:inter_token_latency_seconds_count 30\n");
        let c2 = parse_engine_metrics(&both).expect("read").counters;
        assert_eq!((c2.itl_sum, c2.itl_count), (Some(1.5), Some(30.0)));
    }

    #[test]
    fn data_parallel_ranks_add_up_and_the_fullest_rank_sets_the_kv_use() {
        let text = "\
vllm:num_requests_waiting{model_name=\"m\",engine=\"0\"} 3
vllm:num_requests_waiting{model_name=\"m\",engine=\"1\"} 4
vllm:num_requests_running{model_name=\"m\",engine=\"0\"} 16
vllm:num_requests_running{model_name=\"m\",engine=\"1\"} 16
vllm:kv_cache_usage_perc{model_name=\"m\",engine=\"0\"} 0.2
vllm:kv_cache_usage_perc{model_name=\"m\",engine=\"1\"} 0.9
";
        let r = parse_engine_metrics(text).expect("read");
        assert_eq!((r.waiting, r.running, r.kv_usage), (7, Some(32), Some(0.9)));
    }

    #[test]
    fn a_counter_whose_series_overflow_together_is_not_a_reading() {
        let text = "vllm:num_requests_waiting 0\n\
vllm:prompt_tokens_total{engine=\"0\"} 1.7e308\n\
vllm:prompt_tokens_total{engine=\"1\"} 1.7e308\n";
        assert_eq!(parse_engine_metrics(text).expect("read").counters.prompt_tokens, None);
    }

    #[test]
    fn a_counter_the_engine_does_not_publish_is_absent_not_zero() {
        let c = parse_engine_metrics("vllm:num_requests_waiting 0\n").expect("read").counters;
        assert_eq!(c, EngineCounters::default());
        assert_eq!(c.prompt_tokens, None);
    }

    #[test]
    fn counters_alone_are_not_an_engine_reading() {
        // The gauges decide whether this is an engine's document at all.
        assert!(parse_engine_metrics("vllm:prompt_tokens_total 5\n").is_none());
    }

    #[test]
    fn the_kv_capacity_comes_from_the_cache_config() {
        let text = "vllm:num_requests_waiting 0\n\
vllm:cache_config_info{block_size=\"16\",cache_dtype=\"auto\",num_gpu_blocks=\"2048\"} 1.0\n";
        let info = parse_engine_metrics(text).expect("read").info;
        assert_eq!((info.block_size, info.num_gpu_blocks), (Some(16), Some(2048)));
        assert_eq!(info.kv_capacity_tokens(), Some(32_768));
        let partial = EngineInfo { num_gpu_blocks: Some(10), block_size: None };
        assert_eq!(partial.kv_capacity_tokens(), None, "half a product is no capacity");
    }

    #[test]
    fn metrics_are_read_at_the_server_root_whatever_path_the_api_is_under() {
        // vLLM serves `/metrics` beside `/v1`, never under it: an endpoint given
        // as an OpenAI-style base ending in `/v1` is read at its root, or the
        // read 404s and a queue bound on it silently never applies.
        assert_eq!(engine_metrics_url("http://vllm:8000/v1"), "http://vllm:8000/metrics");
        assert_eq!(engine_metrics_url("http://vllm:8000/v1/"), "http://vllm:8000/metrics");
        assert_eq!(engine_metrics_url("http://vllm:8000"), "http://vllm:8000/metrics");
        assert_eq!(engine_metrics_url("http://vllm:8000/"), "http://vllm:8000/metrics");
        // A path that merely ends in the letters is not the version segment.
        assert_eq!(engine_metrics_url("http://host/mockv1"), "http://host/mockv1/metrics");
        assert_eq!(engine_metrics_url("http://mock/disco/tok"), "http://mock/disco/tok/metrics");
    }

    #[test]
    fn a_label_value_holding_a_comma_or_an_equals_does_not_become_another_label() {
        let series = r#"vllm:cache_config_info{x="a,num_gpu_blocks=999999",block_size="16",num_gpu_blocks="2048"}"#;
        assert_eq!(label_value(series, "num_gpu_blocks"), Some("2048"));
        assert_eq!(label_value(series, "block_size"), Some("16"));
        assert_eq!(label_value(series, "x"), Some("a,num_gpu_blocks=999999"));
        let escaped = r#"m{x="say \"num_gpu_blocks=1\"",num_gpu_blocks="7"}"#;
        assert_eq!(label_value(escaped, "num_gpu_blocks"), Some("7"));
        assert_eq!(label_value("m{unterminated=\"1}", "unterminated"), None);
        assert_eq!(label_value("no_labels 1", "x"), None);
    }

    proptest::proptest! {
        /// The claim: whatever an endpoint sends, the reader never panics, and
        /// what it keeps is a reading — KV a fraction, every counter a finite
        /// non-negative sum. NOT claimed: that the reading is the engine's truth
        /// (a hostile document can state any numbers it likes).
        #[test]
        fn any_document_reads_as_a_reading_or_nothing(text in "(?s).{0,400}") {
            if let Some(r) = parse_engine_metrics(&text) {
                proptest::prop_assert!(r.kv_usage.is_none_or(|kv| (0.0..=1.0).contains(&kv)));
                let c = r.counters;
                for v in [c.preemptions, c.prompt_tokens, c.generation_tokens, c.prefix_queries,
                          c.prefix_hits, c.queue_time_sum, c.queue_time_count, c.ttft_sum, c.ttft_count,
                          c.itl_sum, c.itl_count]
                    .into_iter()
                    .flatten()
                {
                    proptest::prop_assert!(v.is_finite() && v >= 0.0, "counter {v}");
                }
            }
        }

        /// Built from lines the reader recognises, with any labels: a counter
        /// is the sum of its series; a gauge is the busiest series WITHIN a
        /// data-parallel rank (several models, one queue) and the SUM across
        /// ranks (each rank its own queue).
        #[test]
        fn counters_sum_and_gauges_fold_by_rank(
            tokens in proptest::collection::vec(0u32..1_000_000, 1..6),
            per_rank in proptest::collection::vec(proptest::collection::vec(0u32..1000, 1..4), 1..4),
        ) {
            let mut text = String::new();
            for (i, t) in tokens.iter().enumerate() {
                text.push_str(&format!("vllm:generation_tokens_total{{engine=\"{i}\",x=\"a,b\"}} {t}\n"));
            }
            for (rank, models) in per_rank.iter().enumerate() {
                for (m, w) in models.iter().enumerate() {
                    text.push_str(&format!(
                        "vllm:num_requests_waiting{{model_name=\"m{m}\",engine=\"{rank}\"}} {w} 1700000000000\n"
                    ));
                }
            }
            let r = parse_engine_metrics(&text).expect("a gauge is present");
            proptest::prop_assert_eq!(r.counters.generation_tokens, Some(tokens.iter().map(|t| f64::from(*t)).sum::<f64>()));
            let expected: u32 = per_rank.iter().map(|models| *models.iter().max().expect("non-empty")).sum();
            proptest::prop_assert_eq!(r.waiting, expected);
        }

        /// A label's value is returned whatever other labels contain — commas,
        /// equals signs, escaped quotes, braces.
        #[test]
        fn a_label_is_found_whatever_its_neighbours_hold(
            noise in "[a-z,={} \"\\\\]{0,20}",
            value in "[0-9]{1,6}",
        ) {
            let escaped = noise.replace('\\', "\\\\").replace('"', "\\\"");
            let series = format!("m{{a=\"{escaped}\",target=\"{value}\",b=\"{escaped}\"}}");
            proptest::prop_assert_eq!(label_value(&series, "target"), Some(value.as_str()));
        }
    }

    /// The threshold a default deployment runs with: the gate holds a reading
    /// for three polling intervals, so it reports on the fourth silent pass.
    const PASSES: u32 = 4;

    fn outcome(asked: &[(Uuid, &str)], answered: &[Uuid]) -> PollOutcome {
        let answered: std::collections::HashSet<Uuid> = answered.iter().copied().collect();
        PollOutcome {
            failures: asked
                .iter()
                .filter(|(id, _)| !answered.contains(id))
                .map(|(id, _)| {
                    (
                        *id,
                        ReadFailure {
                            kind: FailureKind::Unreachable,
                            credential: CredentialState::None,
                        },
                    )
                })
                .collect(),
            asked: asked.iter().map(|(id, url)| (*id, (*url).to_string())).collect(),
            answered,
            overtaken: Default::default(),
        }
    }

    /// Ask `n` times in a row, answering or not, and collect what was reported.
    fn passes(
        asked: &[(Uuid, &str)],
        answered: &[Uuid],
        n: u32,
        misses: &mut std::collections::HashMap<Uuid, u32>,
    ) -> (Vec<Uuid>, Vec<Uuid>) {
        let (mut quiet, mut back) = (Vec::new(), Vec::new());
        for _ in 0..n {
            let (q, b) = reading_transitions(&outcome(asked, answered), PASSES, misses);
            quiet.extend(q);
            back.extend(b);
        }
        (quiet, back)
    }

    #[test]
    fn an_engine_that_stops_answering_is_named_once_and_again_when_it_returns() {
        // The whole point of reporting the edge rather than the count: an
        // operator hears about it when it happens, and is not told again every
        // few seconds for as long as it lasts.
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut misses = std::collections::HashMap::new();
        let both = [(a, "http://a"), (b, "http://b")];

        let (quiet, back) = passes(&both, &[a, b], 2, &mut misses);
        assert!(quiet.is_empty() && back.is_empty(), "nothing happened yet");

        let (quiet, back) = passes(&both, &[a], PASSES, &mut misses);
        assert_eq!(quiet, vec![b], "the one that went quiet is named, once");
        assert!(back.is_empty());

        let (quiet, back) = passes(&both, &[a], 5, &mut misses);
        assert!(quiet.is_empty(), "and not named again while it stays quiet");
        assert!(back.is_empty());

        let (quiet, back) = passes(&both, &[a, b], 1, &mut misses);
        assert!(quiet.is_empty());
        assert_eq!(back, vec![b], "coming back is an event too");
    }

    #[test]
    fn a_pass_that_finds_an_endpoint_moved_neither_ends_nor_restarts_its_silence() {
        let id = Uuid::new_v4();
        let mut misses = std::collections::HashMap::new();
        reading_transitions(&outcome(&[(id, "http://a")], &[]), 2, &mut misses);
        let moved = PollOutcome {
            asked: Default::default(),
            answered: Default::default(),
            failures: Default::default(),
            overtaken: [id].into(),
        };
        reading_transitions(&moved, 2, &mut misses);
        let (quiet, _) = reading_transitions(&outcome(&[(id, "http://b")], &[]), 2, &mut misses);
        assert_eq!(quiet, vec![id], "two silent passes around the move are one outage, reported once");
    }

    #[test]
    fn a_single_missed_read_is_not_an_outage() {
        // One pass can miss for reasons that have changed nothing: a slow
        // engine, a dropped packet, or the moment a configuration refresh
        // repopulates the credential this read carries. The gate keeps the
        // last reading across it, so nothing has stopped applying — and an
        // alarm that fires here is one an operator learns to ignore.
        let ep = Uuid::new_v4();
        let asked = [(ep, "http://e")];
        let mut misses = std::collections::HashMap::new();
        passes(&asked, &[ep], 1, &mut misses);

        for blip in 1..PASSES {
            let (quiet, back) = passes(&asked, &[], 1, &mut misses);
            assert!(quiet.is_empty(), "reported after only {blip} missed pass(es)");
            assert!(back.is_empty());
            // It answers again, so the count starts over rather than
            // accumulating across unrelated blips.
            let (quiet, back) = passes(&asked, &[ep], 1, &mut misses);
            assert!(quiet.is_empty() && back.is_empty(), "a blip is not worth a word either way");
        }

        // An answer does not just interrupt the run, it clears it: otherwise
        // blips accumulate over an uptime and eventually report an outage that
        // never happened, which is the same false alarm by a slower route.
        let (quiet, back) = passes(&asked, &[], PASSES - 1, &mut misses);
        assert!(
            quiet.is_empty() && back.is_empty(),
            "earlier blips were still being counted against this one"
        );

        // Sustained, it is reported — the positive control on all of the above.
        let (quiet, _) = passes(&asked, &[ep], 1, &mut misses);
        assert!(quiet.is_empty());
        let (quiet, _) = passes(&asked, &[], PASSES, &mut misses);
        assert_eq!(quiet, vec![ep], "an engine that really stopped is still named");
    }

    #[test]
    fn an_engine_that_has_never_answered_is_named_like_any_other() {
        // A threshold set against an engine the gateway cannot read has never
        // done anything. That is the case this exists for, and it has no
        // earlier reading to lose.
        let ep = Uuid::new_v4();
        let mut misses = std::collections::HashMap::new();
        let (quiet, _) = passes(&[(ep, "http://e")], &[], PASSES, &mut misses);
        assert_eq!(quiet, vec![ep]);
    }

    #[test]
    fn an_endpoint_no_longer_asked_is_forgotten_rather_than_left_silent() {
        // An operator who clears the threshold, or deletes the endpoint, has
        // not got a broken engine — and if the same endpoint comes back later
        // and still does not answer, that is worth saying again.
        let ep = Uuid::new_v4();
        let asked = [(ep, "http://e")];
        let mut misses = std::collections::HashMap::new();
        passes(&asked, &[], PASSES, &mut misses);
        assert!(misses.contains_key(&ep));

        let (quiet, back) = passes(&[], &[], 1, &mut misses);
        assert!(quiet.is_empty() && back.is_empty(), "it is not an event, it is a removal");
        assert!(misses.is_empty(), "and nothing is remembered about it");

        let (quiet, _) = passes(&asked, &[], PASSES, &mut misses);
        assert_eq!(quiet, vec![ep], "so it is reported again if it returns still silent");
    }

    #[test]
    fn the_report_waits_for_the_gate_to_stop_applying_the_reading() {
        // The threshold is not a number someone picked, it is a consequence of
        // how long the gate keeps a reading. Raise that and the report must
        // wait longer, because until it expires nothing has stopped for anyone.
        let interval = Duration::from_secs(2);
        assert_eq!(silent_passes_before_reporting(Duration::from_secs(6), interval), 4);
        assert_eq!(
            silent_passes_before_reporting(Duration::from_secs(12), interval),
            7,
            "a gate told to hold readings longer is not contradicted by an earlier alarm"
        );
        assert_eq!(
            silent_passes_before_reporting(Duration::from_secs(30), interval),
            16,
            "including the gate's own default, which is not three intervals"
        );

        // Never on the first miss, whatever the arithmetic says: one lost read
        // is a blip, and the gate still has the reading before it.
        assert_eq!(silent_passes_before_reporting(Duration::ZERO, interval), 2);
        assert_eq!(silent_passes_before_reporting(interval, interval), 2);
        // And never a division by zero on a degenerate interval: it answers
        // something large and finite instead, which reports nothing rather
        // than reporting everything.
        assert!(silent_passes_before_reporting(Duration::from_secs(6), Duration::ZERO) >= 2);
    }

    #[test]
    fn a_read_that_failed_says_which_way_it_failed() {
        // "This endpoint is not answering" is not something anyone can act on.
        // A refusal, an unreachable host and an endpoint that is not an engine
        // need three different things done, and the refusal needs to say
        // whether a credential was even presented.
        let rendered = |kind, credential| ReadFailure { kind, credential }.to_string();

        let refused = rendered(FailureKind::Refused(401), CredentialState::Presented);
        assert!(refused.contains("401"), "{refused}");
        assert!(refused.contains("credential was presented"), "{refused}");

        let bare = rendered(
            FailureKind::Refused(401),
            CredentialState::Unresolved(crate::config::credentials::CredentialMiss::Absent),
        );
        assert!(bare.contains("no credential was presented"), "{bare}");
        assert!(bare.contains("not in this replica's configuration"), "{bare}");
        assert_ne!(refused, bare, "the same status with and without a credential reads the same");

        // A server with nothing to present says nothing about credentials: that
        // is the ordinary case and mentioning it would be noise.
        let open = rendered(FailureKind::Unreachable, CredentialState::None);
        assert!(!open.contains("credential"), "{open}");

        // Each kind is its own sentence.
        let all = [
            rendered(FailureKind::Refused(503), CredentialState::None),
            open.clone(),
            rendered(FailureKind::NoGauges, CredentialState::None),
            rendered(FailureKind::Unreadable, CredentialState::None),
        ];
        let distinct: std::collections::HashSet<&String> = all.iter().collect();
        assert_eq!(distinct.len(), all.len(), "two failure kinds read the same: {all:?}");
    }

    /// A server with a stored credential, as the snapshot ships it and config
    /// sync opens it. None of its models is routed: the endpoint table alone
    /// carries the credential. Returns the credential.
    fn server_with_credential(cfg: &mut crate::config::TenantConfig, server: Uuid) -> String {
        const KEY: [u8; 32] = [9; 32];
        let plaintext = format!("key-{server}");
        cfg.endpoints.read_credentials.insert(
            server,
            crate::config::endpoints::ReadCredential {
                encrypted: crate::crypto::encrypt(&plaintext, &KEY).unwrap(),
                transport: crate::config::upstream_transport::UpstreamTransport::Default,
            },
        );
        cfg.credentials = crate::config::credentials::ServerCredentials::open(
            cfg.endpoints.read_credentials.iter().map(|(s, c)| (s.to_string(), c.encrypted.as_str())),
            Some(&KEY),
        );
        plaintext
    }

    #[tokio::test]
    async fn a_limit_the_configuration_sets_holds_before_the_pollers_next_pass() {
        use super::super::dispatch_gate::{GateEndpoint, GateRequest, GateSettings};
        let id = Uuid::new_v4();
        let server = Uuid::new_v4();
        // One tenant throughout: the change is to ITS endpoint table, the case
        // the hook must not skip as unchanged.
        let tenant = crate::config::TenantId(Uuid::new_v4());
        let registry_with = |max_in_flight: Option<u32>| {
            let mut cfg = crate::config::TenantConfig::default();
            cfg.endpoints.servers.insert(
                server,
                vec![crate::config::endpoints::EndpointConfig {
                    id,
                    url: format!("http://engine-{id}"),
                    weight: 1,
                    max_in_flight,
                    waiting_threshold: None,
                    engine_metrics: false,
                    adaptive_concurrency: false,
                    adaptive_itl_target: Default::default(),
                }],
            );
            Registry::new(std::collections::HashMap::from([(tenant, Arc::new(cfg))]))
        };
        // The request's own snapshot already names the limit, as one routed
        // after the change does.
        let request = move || GateRequest {
            endpoints: vec![GateEndpoint { id, max_in_flight: Some(1), waiting_threshold: None, adaptive: false }],
            preferred: None,
            rank: None,
            class_id: None,
            sheddable: false,
            scope: (Uuid::new_v4(), Uuid::new_v4()),
            weight: 1,
            input_tokens: 0,
            output_weight: 2.0,
            ttl: Duration::from_secs(5),
            resend_key: None,
        };
        let gate = Arc::new(DispatchGate::new(GateSettings::default()));
        let registry: crate::config::TenantRegistry = Arc::new(crate::config::RegistryCell::new(registry_with(None)));
        let shutdown = tokio_util::sync::CancellationToken::new();
        // A pass far longer than the test: only the change signal can apply the
        // new limit in time. The first pass runs at once and adopts "no limit".
        spawn_poller(
            gate.clone(),
            registry.clone(),
            Box::new(|| Ok(reqwest::Client::new())),
            Duration::from_secs(60),
            shutdown.clone(),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let quick = Duration::from_millis(200);

        // Positive control: under the adopted "no limit", two run at once.
        let a = tokio::time::timeout(quick, gate.acquire(request())).await.expect("dispatched").expect("permit");
        let b = tokio::time::timeout(quick, gate.acquire(request())).await.expect("ungated: not held").expect("permit");
        drop((a, b));

        crate::config::publish(&registry, registry_with(Some(1)));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _running = tokio::time::timeout(quick, gate.acquire(request())).await.expect("dispatched").expect("permit");
        assert!(
            tokio::time::timeout(quick, gate.acquire(request())).await.is_err(),
            "the limit the new configuration set must hold the second request"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn a_limit_published_while_the_poller_reads_holds_before_the_read_ends() {
        use super::super::dispatch_gate::{GateEndpoint, GateRequest, GateSettings};
        use std::sync::atomic::{AtomicUsize, Ordering};
        // An engine that takes the connection and never answers: the pass that
        // reads it lasts its whole timeout (half the interval, 30 s here).
        // The loopback server is a private address the `llm` list must list.
        crate::test_egress::install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let asked = Arc::new(AtomicUsize::new(0));
        tokio::spawn({
            let asked = asked.clone();
            async move {
                let mut held = Vec::new();
                while let Ok((socket, _)) = listener.accept().await {
                    asked.fetch_add(1, Ordering::SeqCst);
                    held.push(socket);
                }
            }
        });
        let (slow, id) = (Uuid::new_v4(), Uuid::new_v4());
        let endpoint = |id: Uuid, url: String, max_in_flight: Option<u32>, engine_metrics: bool| {
            crate::config::endpoints::EndpointConfig {
                id,
                url,
                weight: 1,
                max_in_flight,
                waiting_threshold: None,
                engine_metrics,
                adaptive_concurrency: false,
                adaptive_itl_target: Default::default(),
            }
        };
        let tenant = crate::config::TenantId(Uuid::new_v4());
        let registry_with = |max_in_flight: Option<u32>| {
            let mut cfg = crate::config::TenantConfig::default();
            cfg.endpoints.servers.insert(Uuid::new_v4(), vec![endpoint(slow, format!("http://{addr}"), Some(4), true)]);
            cfg.endpoints.servers.insert(Uuid::new_v4(), vec![endpoint(id, format!("http://engine-{id}"), max_in_flight, false)]);
            Registry::new(std::collections::HashMap::from([(tenant, Arc::new(cfg))]))
        };
        let request = move || GateRequest {
            endpoints: vec![GateEndpoint { id, max_in_flight: Some(1), waiting_threshold: None, adaptive: false }],
            preferred: None,
            rank: None,
            class_id: None,
            sheddable: false,
            scope: (Uuid::new_v4(), Uuid::new_v4()),
            weight: 1,
            input_tokens: 0,
            output_weight: 2.0,
            ttl: Duration::from_secs(5),
            resend_key: None,
        };
        let gate = Arc::new(DispatchGate::new(GateSettings::default()));
        let registry: crate::config::TenantRegistry = Arc::new(crate::config::RegistryCell::new(registry_with(None)));
        let shutdown = tokio_util::sync::CancellationToken::new();
        spawn_poller(
            gate.clone(),
            registry.clone(),
            Box::new(|| Ok(reqwest::Client::new())),
            Duration::from_secs(60),
            shutdown.clone(),
        );
        // The first pass is under way, held by the silent engine.
        for _ in 0..100 {
            if asked.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(asked.load(Ordering::SeqCst) > 0, "the pass never reached the silent engine");
        let quick = Duration::from_millis(200);

        // Positive control: with no limit configured, two run at once.
        let a = tokio::time::timeout(quick, gate.acquire(request())).await.expect("dispatched").expect("permit");
        let b = tokio::time::timeout(quick, gate.acquire(request())).await.expect("ungated: not held").expect("permit");
        drop((a, b));

        crate::config::publish(&registry, registry_with(Some(1)));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _running = tokio::time::timeout(quick, gate.acquire(request())).await.expect("dispatched").expect("permit");
        assert!(
            tokio::time::timeout(quick, gate.acquire(request())).await.is_err(),
            "a limit published mid-read must hold before that read ends"
        );
        shutdown.cancel();
    }

    /// An engine serving a minimal vLLM exposition on a loopback port, and how
    /// many times it has been read.
    async fn counting_engine() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // The loopback server is a private address the `llm` list must list.
        crate::test_egress::install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn({
            let reads = reads.clone();
            async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut buf = [0u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let body = "vllm:num_requests_running{model_name=\"m\"} 0\nvllm:num_requests_waiting{model_name=\"m\"} 0\nvllm:kv_cache_usage_perc{model_name=\"m\"} 0\n";
                    let reply = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                    let _ = socket.write_all(reply.as_bytes()).await;
                }
            }
        });
        (url, reads)
    }

    #[tokio::test]
    async fn a_change_reads_only_the_engines_it_left_unread_and_at_once() {
        use std::sync::atomic::Ordering;
        let ((a_url, a_reads), (b_url, b_reads)) = (counting_engine().await, counting_engine().await);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let endpoint = |id: Uuid, url: &str, waiting_threshold: Option<u32>| crate::config::endpoints::EndpointConfig {
            id,
            url: url.to_string(),
            weight: 1,
            max_in_flight: Some(4),
            waiting_threshold,
            engine_metrics: false,
            adaptive_concurrency: false,
            adaptive_itl_target: Default::default(),
        };
        let tenant = crate::config::TenantId(Uuid::new_v4());
        let (server_a, server_b) = (Uuid::new_v4(), Uuid::new_v4());
        let registry_with = |b_threshold: Option<u32>| {
            let mut cfg = crate::config::TenantConfig::default();
            cfg.endpoints.servers.insert(server_a, vec![endpoint(a, &a_url, Some(2))]);
            cfg.endpoints.servers.insert(server_b, vec![endpoint(b, &b_url, b_threshold)]);
            Registry::new(std::collections::HashMap::from([(tenant, Arc::new(cfg))]))
        };
        let gate = Arc::new(DispatchGate::new(super::super::dispatch_gate::GateSettings::default()));
        let registry: crate::config::TenantRegistry = Arc::new(crate::config::RegistryCell::new(registry_with(None)));
        let shutdown = tokio_util::sync::CancellationToken::new();
        // A pass far longer than the test: anything read after the first one
        // was read because of the change.
        spawn_poller(
            gate.clone(),
            registry.clone(),
            Box::new(|| Ok(reqwest::Client::new())),
            Duration::from_secs(60),
            shutdown.clone(),
        );
        let wait_for = |reads: &Arc<std::sync::atomic::AtomicUsize>, n: usize| {
            let reads = reads.clone();
            async move {
                for _ in 0..200 {
                    if reads.load(Ordering::SeqCst) >= n {
                        return true;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                false
            }
        };
        // The first pass reads the one engine anything asks a reading of.
        assert!(wait_for(&a_reads, 1).await, "the first pass reads A");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(b_reads.load(Ordering::SeqCst), 0, "B is not read while nothing needs it");

        // B is given a queue bound: B is read now, A is not read again.
        crate::config::publish(&registry, registry_with(Some(2)));
        assert!(wait_for(&b_reads, 1).await, "the engine the change left unread is read at once");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(a_reads.load(Ordering::SeqCst), 1, "an engine the change did not touch is not read again");
        shutdown.cancel();
    }

    #[tokio::test]
    async fn the_load_report_names_each_gated_endpoint_and_its_servers_held_requests() {
        use super::super::dispatch_gate::{GateEndpoint, GateRequest, GateSettings};
        let endpoint = |id: Uuid, max_in_flight: Option<u32>, waiting_threshold: Option<u32>| {
            crate::config::endpoints::EndpointConfig {
                id,
                url: format!("http://engine-{id}"),
                weight: 1,
                max_in_flight,
                waiting_threshold,
                engine_metrics: false,
                adaptive_concurrency: false,
                adaptive_itl_target: Default::default(),
            }
        };
        let (busy, read, ungated) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let (server, other_server) = (Uuid::new_v4(), Uuid::new_v4());
        let mut cfg = crate::config::TenantConfig::default();
        cfg.endpoints.servers.insert(server, vec![endpoint(busy, Some(1), None), endpoint(read, Some(1), Some(0))]);
        cfg.endpoints.servers.insert(other_server, vec![endpoint(ungated, None, None)]);
        let tenant = crate::config::TenantId(Uuid::new_v4());
        let registry = Registry::new(std::collections::HashMap::from([(tenant, Arc::new(cfg))]));

        let gate = Arc::new(DispatchGate::new(GateSettings::default()));
        let request = move || GateRequest {
            endpoints: vec![GateEndpoint { id: busy, max_in_flight: Some(1), waiting_threshold: None, adaptive: false }],
            preferred: None,
            rank: None,
            class_id: None,
            sheddable: false,
            scope: (Uuid::new_v4(), Uuid::new_v4()),
            weight: 1,
            input_tokens: 0,
            output_weight: 2.0,
            ttl: Duration::from_secs(5),
            resend_key: None,
        };
        let _running = gate.acquire(request()).await.expect("dispatched");
        let waiting = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request()).await.is_ok() }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        gate.record_load(
            read,
            EndpointLoad { ranks: 1, waiting: 4, running: Some(2), kv_usage: Some(0.5), read_at: Instant::now(), mark: 0, counters: Default::default() },
        );

        let report = load_report(&gate, &registry);
        let by_id: std::collections::HashMap<Uuid, &EndpointLoadReport> =
            report.iter().map(|r| (r.endpoint_id, r)).collect();
        // An endpoint with no bound is not the gate's, so it is not reported.
        assert_eq!(report.len(), 2, "{report:?}");
        assert!(!by_id.contains_key(&ungated));
        let b = by_id[&busy];
        assert_eq!((b.tenant_id, b.server_id, b.in_flight), (tenant.0, server, 1));
        // The held request waits for the server's pool: every row of the
        // server carries it, which is why a reader takes it once per replica.
        assert_eq!((b.server_held, by_id[&read].server_held), (1, 1));
        assert_eq!(b.server_held_by_class, vec![ClassHeld { class_id: None, held: 1, held_peak: 1 }]);
        assert!(b.gated && by_id[&read].gated);
        // Only the endpoint with a queue bound has its engine read.
        assert!(!b.engine_read && b.engine.is_none());
        let r = by_id[&read];
        assert!(r.engine_read);
        let engine = r.engine.expect("a fresh reading");
        assert_eq!((engine.waiting, engine.running, engine.kv_usage), (4, Some(2), Some(0.5)));
        assert_eq!((engine.waiting_peak, engine.running_peak, engine.kv_usage_peak), (Some(4), Some(2), Some(0.5)));
        assert_eq!((b.in_flight_peak, b.server_held_peak), (1, 1));

        // The held request runs and finishes between two beats, then the
        // engine reads idle: the next report's instants say so, its peaks keep
        // what happened — and the class that drained is still listed, holding
        // nothing now, with the peak it reached.
        drop(_running);
        assert!(waiting.await.expect("task"));
        for kv in [0.8, 0.0] {
            gate.record_load(
                read,
                EndpointLoad { ranks: 1, waiting: 0, running: Some(0), kv_usage: Some(kv), read_at: Instant::now(), mark: 0, counters: Default::default() },
            );
        }
        let report = load_report(&gate, &registry);
        let b = report.iter().find(|r| r.endpoint_id == busy).expect("busy");
        assert_eq!((b.in_flight, b.in_flight_peak), (0, 1));
        assert_eq!((b.server_held, b.server_held_peak), (0, 1));
        assert_eq!(b.server_held_by_class, vec![ClassHeld { class_id: None, held: 0, held_peak: 1 }]);
        let engine = report.iter().find(|r| r.endpoint_id == read).and_then(|r| r.engine).expect("read");
        // The 0.5 was the previous beat's; this interval's highest is 0.8.
        assert_eq!((engine.kv_usage, engine.kv_usage_peak), (Some(0.0), Some(0.8)));
    }

    #[test]
    fn a_poll_carries_the_credential_of_the_server_it_is_reading() {
        // And of no other. Two servers on one gateway are two operators'
        // engines as often as not; sending one's key to the other would be a
        // credential leak dressed as a health check.
        let mut cfg = crate::config::TenantConfig::default();
        let (mine, theirs) = (Uuid::new_v4(), Uuid::new_v4());
        let my_key = server_with_credential(&mut cfg, mine);
        let their_key = server_with_credential(&mut cfg, theirs);

        assert_eq!(server_credential(&cfg, &mine), Some(Ok(my_key.as_str())));
        assert_eq!(server_credential(&cfg, &theirs), Some(Ok(their_key.as_str())));
        assert_eq!(server_credential(&cfg, &Uuid::new_v4()), None, "and none for a stranger");
    }

    #[test]
    fn each_endpoint_is_asked_with_its_own_servers_credential() {
        // The pairing, not just the lookup: an endpoint belongs to one server,
        // and the credential that goes to it must be that server's. Getting
        // this pair wrong sends one operator's key to another's engine, and
        // both reads would still succeed often enough to look fine.
        let mut cfg = crate::config::TenantConfig::default();
        let (mine, theirs) = (Uuid::new_v4(), Uuid::new_v4());
        let my_key = server_with_credential(&mut cfg, mine);
        let their_key = server_with_credential(&mut cfg, theirs);

        let gated = |id: Uuid| crate::config::endpoints::EndpointConfig {
            id,
            url: format!("http://engine-{id}"),
            weight: 1,
            max_in_flight: None,
            // Only an endpoint whose engine the gateway reads is polled.
            waiting_threshold: Some(0),
            engine_metrics: false,
            adaptive_concurrency: false,
            adaptive_itl_target: Default::default(),
        };
        let (my_ep, their_ep, ungated) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        cfg.endpoints.servers.insert(mine, vec![gated(my_ep)]);
        cfg.endpoints.servers.insert(theirs, vec![gated(their_ep)]);
        // A replica with no engine-queue bound is not read at all.
        cfg.endpoints.servers.insert(
            Uuid::new_v4(),
            vec![crate::config::endpoints::EndpointConfig {
                waiting_threshold: None,
                ..gated(ungated)
            }],
        );

        let registry = Registry::new(std::collections::HashMap::from([(
            crate::config::TenantId::SYSTEM,
            std::sync::Arc::new(cfg),
        )]));
        let targets = read_endpoints(&registry);

        let key_for = |id: Uuid| {
            targets
                .iter()
                .find(|t| t.id == id)
                .map(|t| t.credential)
        };
        assert_eq!(key_for(my_ep), Some(Some(Ok(my_key.as_str()))));
        assert_eq!(key_for(their_ep), Some(Some(Ok(their_key.as_str()))));
        assert_eq!(key_for(ungated), None, "an unread replica is not asked at all");
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn a_server_that_asks_for_engine_metrics_is_read_and_reported_without_any_bound() {
        use super::super::dispatch_gate::GateSettings;
        let endpoint = |id: Uuid, engine_metrics: bool| crate::config::endpoints::EndpointConfig {
            id,
            url: format!("http://engine-{id}/v1"),
            weight: 1,
            max_in_flight: None,
            waiting_threshold: None,
            engine_metrics,
            adaptive_concurrency: false,
            adaptive_itl_target: Default::default(),
        };
        let (watched, unwatched) = (Uuid::new_v4(), Uuid::new_v4());
        let server = Uuid::new_v4();
        let mut cfg = crate::config::TenantConfig::default();
        cfg.endpoints.servers.insert(server, vec![endpoint(watched, true), endpoint(unwatched, false)]);
        let registry = Registry::new(std::collections::HashMap::from([(
            crate::config::TenantId(Uuid::new_v4()),
            Arc::new(cfg),
        )]));

        let targets = read_endpoints(&registry);
        assert_eq!(targets.iter().map(|t| t.id).collect::<Vec<_>>(), vec![watched], "the switch alone makes it read");

        let gate = Arc::new(DispatchGate::new(GateSettings::default()));
        let counters = EngineCounters { generation_tokens: Some(42.0), ..Default::default() };
        gate.record_load(
            watched,
            EndpointLoad { ranks: 1, waiting: 0, running: Some(3), kv_usage: Some(0.2), read_at: Instant::now(), mark: 0, counters },
        );
        let report = load_report(&gate, &registry);
        assert_eq!(report.len(), 1, "an endpoint neither gated nor read is not reported: {report:?}");
        let r = &report[0];
        assert!(r.engine_read && r.endpoint_id == watched);
        assert!(!r.gated, "its in-flight 0 is not a count, and says so");
        let engine = r.engine.expect("a fresh reading");
        assert_eq!((engine.running, engine.counters.generation_tokens), (Some(3), Some(42.0)));
        // And reading it bounds nothing: no request is ever held for it.
        assert!(!endpoint_bounds(&registry).values().any(|b| b.gated));
    }

    #[test]
    fn a_keyless_server_lends_nothing_to_the_poll() {
        let mut cfg = crate::config::TenantConfig::default();
        let server = Uuid::new_v4();
        let mut model = crate::config::model_map::test_upstream_model(
            crate::config::model_map::Provider::Ollama,
            "llama3",
        );
        model.upstream_server_id = Some(server.to_string());
        cfg.model_map.mappings.insert("local".to_string(), vec![model]);
        assert_eq!(server_credential(&cfg, &server), None);
    }

    #[test]
    fn a_cloud_transports_credential_is_never_replayed_onto_a_metrics_read() {
        // Azure, Bedrock and Vertex sign or mint per request from a stored
        // document; a static header built out of one is not that credential,
        // and none of them publishes these gauges anyway.
        let mut cfg = crate::config::TenantConfig::default();
        let server = Uuid::new_v4();
        server_with_credential(&mut cfg, server);
        for transport in [
            crate::config::upstream_transport::UpstreamTransport::AzureOpenAi,
            crate::config::upstream_transport::UpstreamTransport::AzureOpenAiEntra,
            crate::config::upstream_transport::UpstreamTransport::AwsBedrock,
            crate::config::upstream_transport::UpstreamTransport::GoogleVertex,
        ] {
            for c in cfg.endpoints.read_credentials.values_mut() {
                c.transport = transport;
            }
            assert_eq!(server_credential(&cfg, &server), None, "{transport:?}");
        }
    }
}
