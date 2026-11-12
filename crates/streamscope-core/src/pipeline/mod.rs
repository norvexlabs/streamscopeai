//! Request and response transform pipeline.
//!
//! Orchestrates all modifications to LLM requests and responses. Request-phase
//! transforms run after routing in fixed order: tool policy enforcement, Rhai
//! script chain (by scope and priority), stream options injection, and tool name
//! sanitization. Response-phase transforms run during SSE streaming via the
//! [`response_blocks::BlockAccumulator`].
//!
//! Protocol translation between API formats lives in [`translate`]. JSON
//! response healing for malformed output lives in [`healing`].

pub mod capabilities;
pub mod healing;
pub mod mixed_pending_splice;
pub mod request;
pub mod response;
pub mod response_blocks;
pub mod response_pipeline;
pub mod sanitize;
pub mod translate;

use crate::api::ApiRequest;
use crate::audit::badge::BadgeBuilder;
use crate::auth::UserContext;
use crate::error::AppError;
use crate::guardrail::GuardrailSettings;
use crate::scripting::{ScriptEngine, TransformProgram};

pub use request::{
    scan_inbound_request, InboundGuardrailOutcome, TransformFlags, TransformResult,
};

/// Everything the request phase produced: the transform chain's result and the
/// inbound guardrail's outcome, still separate so callers can drain each side's
/// detail (diffs, steps) into their own audit shapes.
pub struct RequestPhaseOutcome {
    pub transform: TransformResult,
    pub guardrail: InboundGuardrailOutcome,
}

impl RequestPhaseOutcome {
    /// The combined badge set for the audit row: the transform chain's badges
    /// with the guardrail's merged in, and the unified `Modified` chip stamped
    /// when guardrail enforce mutated a message. Drains both badge sources;
    /// call once.
    pub fn merged_badges(&mut self) -> BadgeBuilder {
        let mut badges = std::mem::take(&mut self.transform.badges);
        for badge in std::mem::take(&mut self.guardrail.badges) {
            badges.add(badge);
        }
        if self.guardrail.messages_modified {
            badges.add_modified();
        }
        badges
    }
}

/// Run the full request phase on `request` in place: the transform chain
/// (gateway-owned field strip → tool policy → Rhai script chain →
/// stream-options injection → tool-name sanitization → the history's tool
/// references pointed at the final declarations, see
/// [`request::transform_request`]) followed by the
/// inbound-prompt guardrail ([`scan_inbound_request`]). This is the one entry
/// point shared by the forwarding proxy path and the out-of-band `/v1/analyze`
/// RPC, so both apply identical policy in identical order.
#[allow(clippy::too_many_arguments)]
pub async fn run_request_phase(
    request: &mut ApiRequest,
    user: &UserContext,
    script_engine: &ScriptEngine,
    active_programs: &[TransformProgram],
    guardrail: &GuardrailSettings,
    app_id: Option<&str>,
    context_window: Option<i32>,
    upstream_provider: Option<&str>,
    needs_translation: bool,
    capture_diffs: bool,
    tool_rules: &[crate::config::tool_rules::Rule],
    field_profiles: Option<&crate::config::tool_rules::FieldProfileSet>,
    mcp_config: Option<&crate::config::mcp::McpConfig>,
    sanitize_tool_names: bool,
    rhai_fail_mode: crate::scripting::ScriptFailMode,
    request_content: Option<&crate::proxy::content::RequestContent>,
    conversation: Option<uuid::Uuid>,
) -> Result<RequestPhaseOutcome, AppError> {
    let transform = request::transform_request(
        request,
        user,
        script_engine,
        active_programs,
        app_id,
        context_window,
        upstream_provider,
        needs_translation,
        capture_diffs,
        tool_rules,
        field_profiles,
        mcp_config,
        sanitize_tool_names,
        rhai_fail_mode,
    )
    .await?;

    // The inbound guardrail's keys, built only for a request it screens. Those
    // of `request_content` name the client's items; once the request was
    // rewritten before this phase (`None`), or the transform chain rewrote a
    // message or added or removed an item (a tool policy's notice as a new
    // system message), they no longer name what is forwarded, so they are
    // taken from the request as it now stands.
    let screen_keys = guardrail.screens_inbound().then(|| {
        let items = crate::api::domain_request::DomainRequest::conversation_len(request);
        match request_content {
            Some(content) if !transform.flags.messages_modified && content.link_hashes.len() == items => {
                content.screen_keys()
            }
            _ => crate::proxy::content::screen_keys_of(request),
        }
    });
    let guardrail = request::scan_inbound_request(request, guardrail, user.tenant_id, conversation, screen_keys.as_deref()).await?;

    Ok(RequestPhaseOutcome {
        transform,
        guardrail,
    })
}
