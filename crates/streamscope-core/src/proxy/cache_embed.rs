//! Turning a prompt into a vector, for the response cache's semantic mode.
//!
//! The gateway holds no embedding credential of its own. The tenant names an
//! ordinary embeddings alias from its own catalog and the call is resolved
//! through the same routing table a client request uses — same provider, same
//! stored credential, same allowlist. An alias the tenant cannot reach is
//! simply an alias the cache cannot embed with.
//!
//! ## Failure is always a miss
//!
//! A cache exists to make requests cheaper and faster. So every failure here —
//! unresolvable alias, upstream error, malformed body, timeout — returns a
//! reason string and the caller takes an ordinary cache miss. The request goes
//! upstream and is answered normally; only the *optimization* is lost, and the
//! reason lands on the audit row so a misconfigured alias is visible rather
//! than merely ineffective.
//!
//! ## Wire shape
//!
//! The OpenAI embeddings shape (`POST /v1/embeddings` with `{model, input}`,
//! answering `{data: [{embedding: [...]}]}`) is what is sent. It is what every
//! embeddings provider the gateway routes to accepts, and an upstream that
//! answers something else fails the parse and takes the miss.

use std::time::Instant;

use bytes::Bytes;

use super::response_cache::MAX_EMBED_INPUT_BYTES;
use crate::api::sse::ApiVersion;
use crate::auth::UserContext;

/// Bound on an embeddings response body. The largest honest reply is one
/// float-per-dimension vector plus usage — a few hundred kilobytes even at
/// 4096 dimensions in verbose JSON — so 4 MiB is generous.
const MAX_EMBEDDING_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// One embedding, priced.
///
/// The cost is computed **here**, against the embed target's own rates, because
/// by the time the triggering request reaches the audit stage its pricing may
/// have been deliberately zeroed (a cache hit bills nothing for the completion
/// it replaced). A figure derived later would therefore read `$0` on exactly the
/// rows that prove the cache is working.
pub struct Embedding {
    pub vector: Vec<f32>,
    pub cost: f64,
    /// Whether [`Self::cost`] is a real figure. False when the embedding model
    /// carries no rate, or one that cannot be stated in the tenant's accounting
    /// currency — the call still happened and will still be invoiced, so the
    /// triggering request badges itself rather than reporting the spend as zero.
    pub priced: bool,
    pub tokens: u32,
    /// Which embedding model actually produced `vector`.
    ///
    /// Load-bearing for correctness, not telemetry: vectors from two different
    /// models are not comparable, so this rides back to the caller and becomes
    /// part of the semantic bucket. Resolving the alias can legitimately yield
    /// different models on different calls — an alias load-balanced across two
    /// embedding models round-robins per call — and an alias can be re-pointed
    /// at another model entirely. Both would otherwise mix incomparable vectors
    /// in one bucket, where equal dimensions produce a meaningless cosine that
    /// can still clear the threshold and serve an unrelated answer.
    pub model_key: String,
}

/// Embed one prompt, or say why not.
///
/// The `Err` payload is a stable reason string for the
/// `cache_semantic_skipped` badge, not a message for a client — nothing here
/// ever reaches the caller's response.
pub async fn embed(
    state: &super::AppState,
    user: &UserContext,
    config: &crate::config::TenantConfig,
    alias: &str,
    text: &str,
) -> Result<Embedding, &'static str> {
    let started = Instant::now();
    let result = tokio::time::timeout(
        config.cache.embedding_timeout(),
        embed_inner(state, user, config, alias, text),
    )
    .await;

    match result {
        Err(_elapsed) => {
            tracing::warn!(
                alias,
                timeout_ms = config.cache.embedding_timeout_ms,
                "response-cache embedding timed out; taking the miss"
            );
            Err("embedding_timeout")
        }
        Ok(Err(reason)) => {
            tracing::warn!(
                alias,
                reason,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "response-cache embedding failed; taking the miss"
            );
            Err(reason)
        }
        Ok(Ok(v)) => Ok(v),
    }
}

async fn embed_inner(
    state: &super::AppState,
    user: &UserContext,
    config: &crate::config::TenantConfig,
    alias: &str,
    text: &str,
) -> Result<Embedding, &'static str> {
    // Resolved exactly like a client's model reference: the alias must be in
    // this key's own routes, so an embedding call can never reach a provider
    // the workspace is not allowed to use.
    let targets = super::routing::resolve_all_upstreams_by_model(
        alias,
        user,
        &config.credentials,
        &state.lb_counters,
        None,
        ApiVersion::ChatCompletions,
        None,
        &config.endpoints,
        // The embedding call presents the gateway's own credentials, never the
        // client's, so no target is withheld for whose credential it carries.
        false,
    )
    .map_err(|_| "embedding_alias_unresolved")?;
    // One call, no failover: take the first target whose breaker is closed, so
    // a dead replica of the embedding model does not turn every other lookup
    // into a miss while a live one is there.
    let keys: Vec<String> = targets.iter().map(super::routing::UpstreamTarget::breaker_key).collect();
    let target = state
        .circuit_breaker
        .healthy_first(&keys)
        .first()
        .and_then(|&i| targets.get(i))
        .ok_or("embedding_alias_unresolved")?;

    // Refuse rather than truncate. A vector built from part of a question
    // cannot tell it apart from another that shares that part — `semantic_request`
    // already declines over-long text, so reaching here means a caller bypassed
    // that gate, and failing loudly is the only safe answer.
    if text.len() > MAX_EMBED_INPUT_BYTES {
        return Err("embedding_input_too_large");
    }
    let body = serde_json::json!({ "model": target.model, "input": text });
    let bytes = Bytes::from(serde_json::to_vec(&body).map_err(|_| "embedding_failed")?);

    let resp = state
        .http_client
        .forward_media_with_retry(
            target.endpoint(),
            bytes,
            &axum::http::HeaderMap::new(),
            "/v1/embeddings",
            "application/json",
            // No retry: the whole call is already inside a hard timeout, and a
            // second attempt would spend the budget that a plain miss serves
            // better.
            0,
            None,
        )
        .await;
    // The breaker hears about this call like any other forward to the replica:
    // a dead embedding replica is taken out of rotation for chat and media too.
    // A call the hard timeout cancels reports nothing, so a slow replica is
    // never counted as a dead one.
    super::note_forward_outcome(state, user.tenant_id, target, resp.as_ref().map(|_| ()));
    let resp = resp.map_err(|_| "embedding_failed")?;

    // An embedding response is a fixed-width vector plus usage — kilobytes, not
    // megabytes. Bounding it keeps a misconfigured or hostile embeddings URL
    // from OOMing the edge on a path every cached request can reach.
    let raw = crate::http_body::read_body_capped(resp, MAX_EMBEDDING_RESPONSE_BYTES)
        .await
        .map_err(|_| "embedding_failed")?;
    let parsed: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| "embedding_failed")?;
    let vector = parse_embedding(&parsed).ok_or("embedding_failed")?;
    let tokens = parse_prompt_tokens(&parsed).unwrap_or_else(|| estimate_tokens(text));
    // Priced at the embed target's own rates, at call time. The charge rides the
    // triggering request's audit row, so it is converted into the same ledger
    // currency that row's total is stated in.
    let billed = target.pricing.bill(
        &crate::pricing::Units::new().with(crate::pricing::Unit::InputToken, u64::from(tokens)),
        config.pricing.accounting_currency,
        &config.pricing.fx,
    );
    let cost = billed.amount();
    // The embedding model may carry no price, or one the ledger cannot state.
    // Either way the call was made and the provider will invoice it, so the zero
    // recorded above is a floor rather than a figure — the triggering request
    // carries that fact onto its own row. Dropping it here would let real spend
    // disappear with none of the markers that make a zero diagnosable, which is
    // exactly what the completion path badges for.
    let priced = billed.is_known();
    // The `upstream_models` row is the exact identity; the URL+name pair is the
    // fallback for a target that carries no id. Never the alias — the whole
    // point is to tell apart two models the same alias can resolve to.
    let model_key = match &target.upstream_model_id {
        Some(id) => id.clone(),
        None => format!("{}|{}", target.url, target.model),
    };
    Ok(Embedding {
        vector,
        cost,
        priced,
        tokens,
        model_key,
    })
}

/// Prompt tokens the provider says it billed, when it says so.
///
/// An embeddings response carries only input tokens, under either name
/// providers use. Absent or unusable ⇒ `None`, and the caller estimates rather
/// than recording a free call that was not free.
/// A figure above `i32::MAX` is refused rather than clamped: the audit column is
/// an `INT`, so a clamped `u32::MAX` would fail the insert, abort the whole
/// per-tenant batch, and leave the edge redelivering the same record forever.
/// Refusing falls through to the estimate, which the input cap keeps small — and
/// an absurd usage report deserves an estimate anyway.
fn parse_prompt_tokens(body: &serde_json::Value) -> Option<u32> {
    let usage = body.get("usage")?;
    let n = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("total_tokens"))?
        .as_u64()?;
    if n == 0 || n > i32::MAX as u64 {
        return None;
    }
    u32::try_from(n).ok()
}

/// Fallback when the provider reports no usage.
///
/// Four bytes per token is the usual English approximation. It is deliberately
/// an over- rather than under-estimate on the byte side: a slightly high figure
/// costs the caller a fraction of a cent, while a zero would make a real call
/// look free and quietly break the cache's own savings arithmetic.
fn estimate_tokens(text: &str) -> u32 {
    u32::try_from(text.len().div_ceil(4)).unwrap_or(u32::MAX).max(1)
}

/// Pull the first vector out of an OpenAI-shaped embeddings response.
fn parse_embedding(body: &serde_json::Value) -> Option<Vec<f32>> {
    let raw = body
        .get("data")?
        .as_array()?
        .first()?
        .get("embedding")?
        .as_array()?;
    if raw.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len());
    for v in raw {
        let f = v.as_f64()? as f32;
        // A non-finite component would poison every cosine it takes part in.
        if !f.is_finite() {
            return None;
        }
        out.push(f);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_openai_embeddings_response() {
        let body = serde_json::json!({
            "data": [{"embedding": [0.5, -0.25, 0.0]}],
        });
        assert_eq!(parse_embedding(&body), Some(vec![0.5, -0.25, 0.0]));
    }

    #[test]
    fn rejects_bodies_that_cannot_produce_a_usable_vector() {
        // Anything unparseable must take the miss rather than yield a vector
        // that would make cosine similarity meaningless.
        for body in [
            serde_json::json!({}),
            serde_json::json!({"data": []}),
            serde_json::json!({"data": [{}]}),
            serde_json::json!({"data": [{"embedding": []}]}),
            serde_json::json!({"data": [{"embedding": ["not-a-number"]}]}),
            serde_json::json!({"error": {"message": "no such model"}}),
        ] {
            assert_eq!(parse_embedding(&body), None, "body: {body}");
        }
    }

    #[test]
    fn rejects_non_finite_components() {
        // serde_json cannot hold a literal NaN, so this arrives as a string the
        // upstream serialized; either way it must not become a vector.
        let body = serde_json::json!({"data": [{"embedding": [1.0, "NaN"]}]});
        assert_eq!(parse_embedding(&body), None);
    }

}
