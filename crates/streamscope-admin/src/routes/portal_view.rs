//! What a portal member sees of a row the console sees whole.
//!
//! The rows a member may read are decided by `PortalDataScope` alone; this
//! module decides which FIELDS of those rows reach them. Two rules:
//!
//! - [`MemberView`], for every member: the experts' findings on a session (its
//!   alert level, the experts that raised it and their note, and the
//!   `session_alert` badge an audit row folds them into) are withheld. Session
//!   linkage is not a finding and stays.
//! - [`WithoutContent`], for a member whose conversation content is hidden
//!   (`HiddenPages::content_hidden`): a request-list row keeps its metadata —
//!   when, who, which model, server, tool or agent, how much, how long, what
//!   status — and loses everything that carries what was said: text the
//!   caller, the model, an upstream or a web page wrote. Each row type's
//!   fields are classified one by one in its `without_content`, by a pattern
//!   that names every field, so a field added to a row does not compile until
//!   it is classified. The routes that serve content itself are refused by
//!   `portal_pages`' Content fence; this covers the one list that stays.
//!
//! Every portal handler returning a [`SessionSummary`], a
//! [`ConversationResponse`], a [`LinkedSessions`], an [`AuditLogRow`], a
//! [`WebAuditLogEntry`] or a [`TraceResponse`] passes it through
//! [`MemberView::for_member`] before it is serialised: clearing the
//! fields in the UI alone would still ship them in the JSON. A filter, a text
//! search or an order on a withheld field is ignored by the handler, never
//! applied, so the rows returned cannot reveal it either.

use streamscope_core::audit::AuditBadge;

use super::audit::{
    A2aAuditLogEntry, AuditLogEntry, AuditLogRow, ConversationResponse, LinkedSessions, McpAuditLogEntry,
    SessionSummary, TraceResponse, WebAuditLogEntry,
};

/// A response body as a portal member receives it.
pub(crate) trait MemberView: Sized {
    /// Withhold what members do not see.
    fn for_member(self) -> Self;
}

impl MemberView for SessionSummary {
    fn for_member(mut self) -> Self {
        self.alert_level = None;
        self.alert_expert_axis = None;
        self.alert_note = None;
        self
    }
}

impl MemberView for ConversationResponse {
    fn for_member(mut self) -> Self {
        self.alert_level = None;
        self.alert_expert_axis = None;
        self.alert_note = None;
        self
    }
}

impl MemberView for LinkedSessions {
    fn for_member(mut self) -> Self {
        self.parent = self.parent.map(MemberView::for_member);
        self.children = self.children.into_iter().map(MemberView::for_member).collect();
        self
    }
}

fn drop_session_alert(badges: &mut Vec<AuditBadge>) {
    badges.retain(|b| !matches!(b, AuditBadge::SessionAlert { .. }));
}

impl MemberView for AuditLogRow {
    fn for_member(mut self) -> Self {
        match &mut self {
            AuditLogRow::Llm { entry } => {
                entry.session_alert_level = None;
                entry.session_alert_axis = None;
                drop_session_alert(&mut entry.badges.0);
            }
            AuditLogRow::Mcp { entry } => drop_session_alert(&mut entry.badges.0),
            AuditLogRow::Web { entry } => drop_session_alert(&mut entry.badges.0),
            AuditLogRow::A2a { entry } => drop_session_alert(&mut entry.badges.0),
        }
        self
    }
}

impl MemberView for WebAuditLogEntry {
    fn for_member(mut self) -> Self {
        drop_session_alert(&mut self.badges.0);
        self
    }
}

impl MemberView for TraceResponse {
    /// A trace carries no expert finding today: it reaches a member whole.
    /// Kept as the step every portal trace passes through, so what members
    /// may not see of one is decided here, with the rest.
    fn for_member(self) -> Self {
        self
    }
}

impl<T: MemberView> MemberView for Vec<T> {
    fn for_member(self) -> Self {
        self.into_iter().map(MemberView::for_member).collect()
    }
}

// ---------------------------------------------------------------------------
// The request list without conversation content
// ---------------------------------------------------------------------------

/// A response body as a member receives it while conversation content is
/// hidden for them.
pub(crate) trait WithoutContent: Sized {
    /// Withhold everything that carries what was said; keep the metadata.
    fn without_content(self) -> Self;
}

/// A badge says THAT something happened and how often; the three tool-block
/// badges also name the tools, and a tool's name is text the client's request
/// defined (its tool definitions are content), so the names go and the count
/// stays. Every other payload is the gateway's own vocabulary: a phase, a
/// count, a reason it wrote, a rule or program an administrator named, a
/// model, a category.
fn badges_without_content(badges: &mut [AuditBadge]) {
    for badge in badges {
        match badge {
            AuditBadge::ToolBlocked { names, .. }
            | AuditBadge::ToolBlockedOverflow { names, .. }
            | AuditBadge::ToolBlockNotApplied { names, .. } => names.clear(),
            AuditBadge::Modified
            | AuditBadge::ModifiedNotApplied
            | AuditBadge::Compressed
            | AuditBadge::JsonHealed
            | AuditBadge::BlockOverflow { .. }
            | AuditBadge::ScriptError { .. }
            | AuditBadge::ProtocolTranslated { .. }
            | AuditBadge::CapabilityRerouted { .. }
            | AuditBadge::Catchall
            | AuditBadge::SanitizedToolNames { .. }
            | AuditBadge::ResponseSanitizedToolNames { .. }
            | AuditBadge::AgentAlert { .. }
            | AuditBadge::McpRpcError { .. }
            | AuditBadge::McpLegacySse
            | AuditBadge::McpSamplingIntercepted
            | AuditBadge::LlmSyntheticSampling
            | AuditBadge::WebBlocked
            | AuditBadge::WebUrlFiltered { .. }
            | AuditBadge::WebAllResultsFiltered
            | AuditBadge::WebRateLimited
            | AuditBadge::WebContentStripped { .. }
            | AuditBadge::RecordStripped { .. }
            | AuditBadge::ContentUnavailable
            | AuditBadge::WebSsrfRefused
            | AuditBadge::WebSchemeRefused
            | AuditBadge::WebSubstitutedServer { .. }
            | AuditBadge::WebSubstitutedClient { .. }
            | AuditBadge::WebSubstitutionMaxIter
            | AuditBadge::WebSubstitutionToolError
            | AuditBadge::WebSubstitutionTruncatedStream
            | AuditBadge::WebSubstitutionMixedPending
            | AuditBadge::WebSubstitutionForwardFailed
            | AuditBadge::WebSubstitutionSerializeFailed
            | AuditBadge::WebSubstitutionNonStreaming
            | AuditBadge::WebSubstitutionHistoryCap
            | AuditBadge::WebSubstitutionCancelled
            | AuditBadge::WebSubstitutionMixedPendingSpliced { .. }
            | AuditBadge::WebSubstitutionMixedPendingSpliceFailed { .. }
            | AuditBadge::Guardrail { .. }
            | AuditBadge::GuardrailError { .. }
            | AuditBadge::CacheHit { .. }
            | AuditBadge::CacheObserveHit { .. }
            | AuditBadge::CacheStoreSkipped { .. }
            | AuditBadge::CacheSemanticSkipped { .. }
            | AuditBadge::Queued { .. }
            | AuditBadge::Spilled
            | AuditBadge::Unpriced
            | AuditBadge::UpstreamAdapted { .. }
            | AuditBadge::SessionAlert { .. } => {}
        }
    }
}

impl WithoutContent for AuditLogEntry {
    fn without_content(mut self) -> Self {
        let AuditLogEntry {
            // CONTENT — withheld.
            // Prose about the failure; it can quote the request or the
            // upstream's answer. `error_category` and `status_code` stay.
            error_detail,
            // A media call's prompt, transcript and generated media.
            media_call,
            // The media a chat request carried: what the content was made of,
            // and the hashes its media are fetched by.
            chat_media_summary,
            // What a transform, a tool rule or the guardrail changed: the text
            // before and after.
            transform_diff,
            // Kept, without the tool names (`badges_without_content`).
            badges,
            // METADATA — kept. Ids (a session id stays an id), when, who and
            // from which client, which model and provider on which protocol,
            // the tokens, the cost and what it is made of, the timings, how it
            // ended, the limit that refused it, where it was routed. The
            // catch-all path is the gateway endpoint called, not what was sent
            // to it.
            request_id: _,
            timestamp: _,
            user_id: _,
            tenant_id: _,
            app_id: _,
            session_id: _,
            conversation_session_id: _,
            user_agent: _,
            detection_method: _,
            client_ip: _,
            end_user: _,
            end_user_groups: _,
            model_requested: _,
            model_used: _,
            provider: _,
            api_version: _,
            stream: _,
            prompt_tokens: _,
            completion_tokens: _,
            reasoning_tokens: _,
            cache_creation_tokens: _,
            cache_read_tokens: _,
            finish_reason: _,
            native_finish_reason: _,
            finish_reason_display: _,
            cost: _,
            cost_currency: _,
            source_cost: _,
            source_currency: _,
            fx_rate: _,
            billed_units: _,
            embedding_cost: _,
            embedding_tokens: _,
            zero_completion: _,
            latency_ttft_ms: _,
            latency_total_ms: _,
            session_alert_level: _,
            session_alert_axis: _,
            pipeline_path: _,
            catchall_path: _,
            catchall_method: _,
            status_code: _,
            error_category: _,
            limit_bucket: _,
            user_email: _,
            upstream_server_name: _,
            endpoint_url: _,
            queue_wait_ms: _,
            qos_class_id: _,
            workspace_name: _,
            key_name: _,
            key_prefix: _,
        } = &mut self;
        *error_detail = None;
        *media_call = None;
        *chat_media_summary = None;
        *transform_diff = None;
        badges_without_content(&mut badges.0);
        self
    }
}

impl WithoutContent for McpAuditLogEntry {
    fn without_content(mut self) -> Self {
        let McpAuditLogEntry {
            // CONTENT — withheld.
            // The resource asked for: a path, a URL or a query the caller
            // wrote.
            resource_uri,
            // The upstream's own words about the failure. `error_code` and
            // `status_code` stay.
            error_message,
            // What a rule or the stream pump recorded about the call's body.
            transform_diff,
            // The call's arguments and the upstream's answer.
            params,
            result,
            badges,
            // METADATA — kept. Ids, when, who, which server and upstream, the
            // JSON-RPC method, the status and code, the timings and sizes, the
            // protocol version. The tool and the prompt are kept by id: each
            // names an entry of the server's own catalogue — which tool was
            // called, as the model names which model — not text the caller
            // wrote; what was passed to it is in `params`, withheld.
            request_id: _,
            timestamp: _,
            user_id: _,
            user_email: _,
            app_id: _,
            session_id: _,
            mcp_session_id: _,
            virtual_server_id: _,
            virtual_server_slug: _,
            upstream_server_id: _,
            upstream_server_name: _,
            method: _,
            tool_id: _,
            prompt_id: _,
            status_code: _,
            error_code: _,
            latency_total_ms: _,
            upstream_latency_ms: _,
            request_bytes: _,
            response_bytes: _,
            protocol_version: _,
        } = &mut self;
        *resource_uri = None;
        *error_message = None;
        *transform_diff = None;
        *params = None;
        *result = None;
        badges_without_content(&mut badges.0);
        self
    }
}

impl WithoutContent for WebAuditLogEntry {
    fn without_content(mut self) -> Self {
        let WebAuditLogEntry {
            // CONTENT — withheld.
            // The search query or the URL fetched.
            query,
            // Prose about the failure; it can quote the URL or the page.
            error_detail,
            // The URLs found or fetched, with their verdicts.
            url_results,
            // The arguments, the answer and its media, as sent and received.
            request_args,
            response_summary,
            provider_request,
            provider_response,
            fetch_content_summary,
            transform_diff,
            badges,
            // METADATA — kept. Ids (the parent request's included), when, who,
            // search or fetch, on which backend and surface, how many results,
            // the sizes, statuses and timings, the error category, and the ids
            // of the filters that ran (configuration).
            request_id: _,
            timestamp: _,
            user_id: _,
            user_email: _,
            app_id: _,
            session_id: _,
            upstream_server_id: _,
            upstream_server_name: _,
            operation: _,
            backend: _,
            result_count: _,
            bytes_in: _,
            bytes_out: _,
            upstream_latency_ms: _,
            upstream_status: _,
            status_code: _,
            error_category: _,
            latency_total_ms: _,
            surface: _,
            parent_request_id: _,
            filter_chain: _,
        } = &mut self;
        *query = None;
        *error_detail = None;
        *url_results = None;
        *request_args = None;
        *response_summary = None;
        *provider_request = None;
        *provider_response = None;
        *fetch_content_summary = None;
        *transform_diff = None;
        badges_without_content(&mut badges.0);
        self
    }
}

impl WithoutContent for A2aAuditLogEntry {
    fn without_content(mut self) -> Self {
        let A2aAuditLogEntry {
            // CONTENT — withheld.
            // Prose about the failure, the gateway's and the agent's.
            // `error_category`, `error_code` and `status_code` stay.
            error_detail,
            error_message,
            // What a rule or the guardrail found in the message or the reply.
            transform_diff,
            // The message sent, the agent's reply and its stream.
            params,
            result,
            stream_events,
            badges,
            // METADATA — kept. Ids (the wire's context and task ids are
            // correlators, not text), when, who, which agent, the operation,
            // the task state, the status and codes, the timings and sizes, the
            // protocol version.
            request_id: _,
            timestamp: _,
            user_id: _,
            user_email: _,
            app_id: _,
            session_id: _,
            agent_id: _,
            agent_slug: _,
            agent_name: _,
            method: _,
            a2a_context_id: _,
            a2a_task_id: _,
            task_state: _,
            status_code: _,
            error_category: _,
            error_code: _,
            latency_total_ms: _,
            upstream_latency_ms: _,
            request_bytes: _,
            response_bytes: _,
            protocol_version: _,
        } = &mut self;
        *error_detail = None;
        *error_message = None;
        *transform_diff = None;
        *params = None;
        *result = None;
        *stream_events = None;
        badges_without_content(&mut badges.0);
        self
    }
}

impl WithoutContent for AuditLogRow {
    fn without_content(self) -> Self {
        match self {
            AuditLogRow::Llm { entry } => AuditLogRow::Llm { entry: Box::new(entry.without_content()) },
            AuditLogRow::Mcp { entry } => AuditLogRow::Mcp { entry: Box::new(entry.without_content()) },
            AuditLogRow::Web { entry } => AuditLogRow::Web { entry: Box::new(entry.without_content()) },
            AuditLogRow::A2a { entry } => AuditLogRow::A2a { entry: Box::new(entry.without_content()) },
        }
    }
}

impl<T: WithoutContent> WithoutContent for Vec<T> {
    fn without_content(self) -> Self {
        self.into_iter().map(WithoutContent::without_content).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamscope_core::audit::AlertLevel;

    #[test]
    fn a_member_never_receives_a_session_alert_badge_and_keeps_every_other_badge() {
        let mut badges = vec![
            AuditBadge::SessionAlert { experts: vec!["anomaly".into()], level: AlertLevel::Major },
            AuditBadge::Catchall,
        ];
        drop_session_alert(&mut badges);
        assert_eq!(badges, vec![AuditBadge::Catchall]);
    }

    /// A row that records whether it was viewed as a member.
    #[derive(PartialEq, Eq)]
    struct Seen(bool);

    impl MemberView for Seen {
        fn for_member(self) -> Self {
            Seen(true)
        }
    }

    /// Text no row may carry once its content is withheld.
    const SECRET: &str = "what-was-said";

    fn secret_json() -> Option<sqlx::types::Json<serde_json::Value>> {
        Some(sqlx::types::Json(serde_json::json!({ "text": SECRET })))
    }

    fn blocked_badges() -> sqlx::types::Json<Vec<AuditBadge>> {
        sqlx::types::Json(vec![
            AuditBadge::ToolBlocked {
                phase: streamscope_core::audit::Phase::Response,
                count: 2,
                names: vec![SECRET.into(), "Bash".into()],
            },
            AuditBadge::Catchall,
        ])
    }

    /// The row as the API sends it, and that nothing of it carries the secret.
    fn sent(row: AuditLogRow) -> serde_json::Value {
        let json = serde_json::to_value(row.without_content()).expect("a row serialises");
        assert!(!json.to_string().contains(SECRET), "content left in the row: {json}");
        json
    }

    /// The tool-block badge keeps its count and loses its names; the others
    /// are as they were.
    fn assert_badges(json: &serde_json::Value) {
        assert_eq!(
            json["badges"],
            serde_json::json!([
                { "code": "tool_blocked", "phase": "response", "count": 2, "names": [] },
                { "code": "catchall" },
            ])
        );
    }

    fn absent_or_null(json: &serde_json::Value, keys: &[&str]) {
        for key in keys {
            assert!(json.get(key).is_none_or(serde_json::Value::is_null), "{key} is sent: {}", json[key]);
        }
    }

    #[test]
    fn an_llm_row_without_content_keeps_its_metadata_and_carries_none_of_what_was_said() {
        let transform_diff: streamscope_core::proxy::content::TransformDiff =
            serde_json::from_value(serde_json::json!({ "injected_system_prompt": SECRET })).unwrap();
        let media_call: streamscope_core::api::domain_request::DomainMediaCall = serde_json::from_value(
            serde_json::json!({ "endpoint": "image_generation", "model": "m", "input": [], "output": [],
                                "output_structured": { "text": SECRET } }),
        )
        .unwrap();
        let entry = AuditLogEntry {
            request_id: uuid::Uuid::from_u128(1),
            timestamp: chrono::DateTime::UNIX_EPOCH,
            user_id: uuid::Uuid::from_u128(2),
            tenant_id: uuid::Uuid::from_u128(3),
            app_id: Some("app".into()),
            session_id: Some(uuid::Uuid::from_u128(4)),
            conversation_session_id: Some(uuid::Uuid::from_u128(5)),
            user_agent: Some("agent/1".into()),
            detection_method: Some("header".into()),
            client_ip: None,
            end_user: None,
            end_user_groups: Vec::new(),
            model_requested: "alias".into(),
            model_used: "model".into(),
            provider: "provider".into(),
            api_version: "chat_completions".into(),
            stream: true,
            prompt_tokens: 10,
            completion_tokens: 20,
            reasoning_tokens: Some(3),
            cache_creation_tokens: None,
            cache_read_tokens: None,
            finish_reason: "stop".into(),
            native_finish_reason: None,
            finish_reason_display: "completed".into(),
            cost: 0.5,
            cost_currency: Default::default(),
            source_cost: 0.5,
            source_currency: Default::default(),
            fx_rate: 1.0,
            billed_units: Default::default(),
            embedding_cost: 0.0,
            embedding_tokens: 0,
            zero_completion: false,
            latency_ttft_ms: 7,
            latency_total_ms: 9,
            badges: blocked_badges(),
            session_alert_level: None,
            session_alert_axis: None,
            pipeline_path: None,
            catchall_path: None,
            catchall_method: None,
            status_code: Some(502),
            error_category: Some("upstream".into()),
            error_detail: Some(SECRET.into()),
            limit_bucket: None,
            media_call: Some(sqlx::types::Json(media_call)),
            chat_media_summary: Some(sqlx::types::Json(vec![streamscope_core::audit::ChatMediaSummaryEntry {
                content_hash: SECRET.into(),
                blob_type: streamscope_core::audit::BlobType::ChatImage,
                media_type: "image/png".into(),
                size_bytes: 1,
            }])),
            transform_diff: Some(sqlx::types::Json(transform_diff)),
            user_email: Some("member@example.test".into()),
            upstream_server_name: Some("server".into()),
            endpoint_url: None,
            queue_wait_ms: None,
            qos_class_id: None,
            workspace_name: Some("Team".into()),
            key_name: Some("key".into()),
            key_prefix: Some("sk-abc".into()),
        };
        let json = sent(AuditLogRow::Llm { entry: Box::new(entry) });
        absent_or_null(&json, &["error_detail", "media_call", "chat_media_summary", "transform_diff"]);
        assert_badges(&json);
        // The metadata is as it was.
        assert_eq!(json["kind"], "llm");
        assert_eq!(json["model_used"], "model");
        assert_eq!(json["provider"], "provider");
        assert_eq!(json["prompt_tokens"], 10);
        assert_eq!(json["completion_tokens"], 20);
        assert_eq!(json["cost"], 0.5);
        assert_eq!(json["latency_total_ms"], 9);
        assert_eq!(json["status_code"], 502);
        assert_eq!(json["error_category"], "upstream");
        assert_eq!(json["finish_reason"], "stop");
        assert_eq!(json["workspace_name"], "Team");
        assert_eq!(json["key_prefix"], "sk-abc");
        assert_eq!(json["app_id"], "app");
        assert_eq!(json["user_email"], "member@example.test");
        assert_eq!(json["conversation_session_id"], uuid::Uuid::from_u128(5).to_string());
    }

    #[test]
    fn an_mcp_row_without_content_keeps_the_tool_called_and_carries_none_of_its_arguments() {
        let entry = McpAuditLogEntry {
            request_id: uuid::Uuid::from_u128(1),
            timestamp: chrono::DateTime::UNIX_EPOCH,
            user_id: None,
            user_email: None,
            app_id: None,
            session_id: None,
            mcp_session_id: Some("mcp-session".into()),
            virtual_server_id: uuid::Uuid::from_u128(6),
            virtual_server_slug: Some("tools".into()),
            upstream_server_id: None,
            upstream_server_name: Some("upstream".into()),
            method: "tools/call".into(),
            tool_id: Some("upstream:search".into()),
            prompt_id: Some("summarise".into()),
            resource_uri: Some(format!("file:///{SECRET}")),
            status_code: Some(200),
            error_code: Some(-32000),
            error_message: Some(SECRET.into()),
            latency_total_ms: Some(12),
            upstream_latency_ms: 11,
            request_bytes: Some(100),
            response_bytes: Some(200),
            protocol_version: Some("2025-06-18".into()),
            badges: blocked_badges(),
            transform_diff: Some(sqlx::types::Json(super::super::audit::McpTransformDiff {
                transport: Some(SECRET.into()),
                ..Default::default()
            })),
            params: secret_json(),
            result: secret_json(),
        };
        let json = sent(AuditLogRow::Mcp { entry: Box::new(entry) });
        absent_or_null(&json, &["resource_uri", "error_message", "transform_diff", "params", "result"]);
        assert_badges(&json);
        assert_eq!(json["kind"], "mcp");
        assert_eq!(json["method"], "tools/call");
        assert_eq!(json["tool_id"], "upstream:search");
        assert_eq!(json["prompt_id"], "summarise");
        assert_eq!(json["virtual_server_slug"], "tools");
        assert_eq!(json["error_code"], -32000);
        assert_eq!(json["status_code"], 200);
        assert_eq!(json["upstream_latency_ms"], 11);
        assert_eq!(json["response_bytes"], 200);
    }

    #[test]
    fn a_web_row_without_content_keeps_the_operation_and_carries_no_query_url_or_page() {
        let transform_diff: streamscope_core::proxy::content::TransformDiff =
            serde_json::from_value(serde_json::json!({ "injected_system_prompt": SECRET })).unwrap();
        let entry = WebAuditLogEntry {
            request_id: uuid::Uuid::from_u128(1),
            timestamp: chrono::DateTime::UNIX_EPOCH,
            user_id: None,
            user_email: None,
            app_id: None,
            session_id: None,
            upstream_server_id: uuid::Uuid::from_u128(7),
            upstream_server_name: Some("builtin-web".into()),
            operation: "search".into(),
            backend: "searxng".into(),
            query: Some(SECRET.into()),
            result_count: Some(4),
            bytes_in: Some(10),
            bytes_out: Some(20),
            upstream_latency_ms: 30,
            upstream_status: Some(200),
            status_code: Some(200),
            error_category: Some("upstream".into()),
            error_detail: Some(SECRET.into()),
            latency_total_ms: Some(31),
            surface: "substitution".into(),
            parent_request_id: Some(uuid::Uuid::from_u128(8)),
            badges: blocked_badges(),
            url_results: secret_json(),
            filter_chain: Some(sqlx::types::Json(serde_json::json!(["domain-allowlist"]))),
            request_args: secret_json(),
            response_summary: secret_json(),
            provider_request: secret_json(),
            provider_response: Some(sqlx::types::Json(streamscope_core::web::audit::WebProviderResponse::Captured(
                serde_json::json!({ "text": SECRET }),
            ))),
            fetch_content_summary: secret_json(),
            transform_diff: Some(sqlx::types::Json(transform_diff)),
        };
        let json = sent(AuditLogRow::Web { entry: Box::new(entry) });
        absent_or_null(
            &json,
            &[
                "query", "error_detail", "url_results", "request_args", "response_summary", "provider_request",
                "provider_response", "fetch_content_summary", "transform_diff",
            ],
        );
        assert_badges(&json);
        assert_eq!(json["kind"], "web");
        assert_eq!(json["operation"], "search");
        assert_eq!(json["backend"], "searxng");
        assert_eq!(json["result_count"], 4);
        assert_eq!(json["surface"], "substitution");
        assert_eq!(json["error_category"], "upstream");
        assert_eq!(json["filter_chain"], serde_json::json!(["domain-allowlist"]));
        assert_eq!(json["parent_request_id"], uuid::Uuid::from_u128(8).to_string());
    }

    #[test]
    fn an_a2a_row_without_content_keeps_the_agent_and_carries_no_message_or_reply() {
        let entry = A2aAuditLogEntry {
            request_id: uuid::Uuid::from_u128(1),
            timestamp: chrono::DateTime::UNIX_EPOCH,
            user_id: None,
            user_email: None,
            app_id: None,
            session_id: None,
            agent_id: uuid::Uuid::from_u128(9),
            agent_slug: Some("planner".into()),
            agent_name: Some("Planner".into()),
            method: "SendMessage".into(),
            a2a_context_id: Some("ctx-1".into()),
            a2a_task_id: Some("task-1".into()),
            task_state: Some("TASK_STATE_COMPLETED".into()),
            status_code: Some(200),
            error_category: Some("rpc_error".into()),
            error_detail: Some(SECRET.into()),
            error_code: Some(-32001),
            error_message: Some(SECRET.into()),
            latency_total_ms: Some(40),
            upstream_latency_ms: 39,
            request_bytes: Some(1),
            response_bytes: Some(2),
            protocol_version: Some("1.0".into()),
            badges: blocked_badges(),
            transform_diff: Some(sqlx::types::Json(super::super::audit::A2aTransformDiff {
                policy_findings: vec![super::super::audit::A2aPolicyFinding {
                    phase: "request".into(),
                    rule_id: None,
                    risk: "high".into(),
                    title: Some(SECRET.into()),
                    description: None,
                    action: "block".into(),
                }],
                guardrail_steps: Vec::new(),
            })),
            params: secret_json(),
            result: secret_json(),
            stream_events: secret_json(),
        };
        let json = sent(AuditLogRow::A2a { entry: Box::new(entry) });
        absent_or_null(
            &json,
            &["error_detail", "error_message", "transform_diff", "params", "result", "stream_events"],
        );
        assert_badges(&json);
        assert_eq!(json["kind"], "a2a");
        assert_eq!(json["agent_slug"], "planner");
        assert_eq!(json["method"], "SendMessage");
        assert_eq!(json["task_state"], "TASK_STATE_COMPLETED");
        assert_eq!(json["a2a_context_id"], "ctx-1");
        assert_eq!(json["error_code"], -32001);
        assert_eq!(json["error_category"], "rpc_error");
        assert_eq!(json["upstream_latency_ms"], 39);
    }

    #[test]
    fn a_list_keeps_every_row_and_views_each_as_a_member() {
        let rows = vec![Seen(false), Seen(false), Seen(false)].for_member();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| *r == Seen(true)));
    }
}
