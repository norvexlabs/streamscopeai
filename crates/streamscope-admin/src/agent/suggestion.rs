//! Store and manage program suggestions from agent analysis.

use crate::db::tenant::Scoped;

/// Validate a proposed Rhai source compiles, plus semantic checks that catch
/// the failure modes weak-model output produces but the Rhai compiler accepts
/// as syntactically valid.
///
/// `is_span` selects the contract: span sources use `fn transform(m)` over a
/// single matched span (no `ctx.messages`/`ctx.tools`), so the `ctx`-shaped
/// lints below are full-mode only — running them on span sources would
/// false-reject legitimate per-match rewrites.
///
/// Full-mode lints:
/// * `ctx.messages.<field>` — `ctx.messages` is a Vec; per-item fields
///   live on each element. Catches the `task completion detector` /
///   `rust task context enhancer` class.
/// * `ctx.tools = []` / `ctx.messages = []` — wholesale array wipe is
///   never a filter. Catches the `tool call filter` class that silently
///   removes every tool.
///
/// Both modes:
/// * ≥2 long string literals with no matcher referencing them —
///   session-specific text leaked into a rule. Catches
///   `conversation continuity`-class proposals with hardcoded prompt
///   excerpts.
fn validate_proposed_source(source: &str, is_span: bool) -> Result<(), String> {
    let engine = streamscope_core::scripting::ScriptEngine::new();
    engine.validate(source).map_err(|e| e.to_string())?;

    if !is_span {
        if let Some(field) = detect_messages_field_access(source) {
            return Err(format!(
                "`ctx.messages.{field}` — `ctx.messages` is an array; access per-item via `ctx.messages[i].{field}`"
            ));
        }

        if let Some(target) = detect_array_wipe(source) {
            return Err(format!(
                "`ctx.{target} = []` wipes the whole collection — iterate and retain matching entries instead"
            ));
        }
    }

    if detect_session_specific_literals(source) {
        return Err(
            "source contains multiple hardcoded long string literals not referenced by any matcher — likely a session-specific excerpt that won't generalise"
                .into(),
        );
    }

    Ok(())
}

/// Catches `ctx.messages.<field>` where `<field>` is one of the
/// per-element fields. False positives bounded by the field allow-list.
fn detect_messages_field_access(source: &str) -> Option<&'static str> {
    const FIELDS: &[&str] = &["content", "role", "tool_calls", "tool_results", "name"];
    for field in FIELDS {
        let needle = format!("ctx.messages.{field}");
        if source.contains(&needle) {
            return Some(field);
        }
    }
    None
}

/// Catches `ctx.tools = []` and `ctx.messages = []` (any whitespace).
fn detect_array_wipe(source: &str) -> Option<&'static str> {
    for target in &["tools", "messages"] {
        let prefix = format!("ctx.{target}");
        for (idx, _) in source.match_indices(&prefix) {
            let rest = &source[idx + prefix.len()..];
            let trimmed = rest.trim_start();
            let Some(after_eq) = trimmed.strip_prefix('=') else {
                continue;
            };
            // Reject only when the assignment is a literal `[]` — `ctx.tools = filtered`
            // and `ctx.tools += [...]` are fine.
            if after_eq.trim_start().starts_with('[') {
                let after_bracket = after_eq.trim_start()[1..].trim_start();
                if after_bracket.starts_with(']') {
                    return Some(target);
                }
            }
        }
    }
    None
}

/// Catches scripts that contain ≥2 long quoted literals (≥40 chars) but
/// no matcher op (`contains`, `starts_with`, `ends_with`, regex) that
/// could reference them. Signals session-specific text leakage.
fn detect_session_specific_literals(source: &str) -> bool {
    let mut long_literal_count = 0usize;
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'"' {
                if bytes[end] == b'\\' && end + 1 < bytes.len() {
                    end += 2;
                } else {
                    end += 1;
                }
            }
            if end - start >= 40 {
                long_literal_count += 1;
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }
    if long_literal_count < 2 {
        return false;
    }
    const MATCHER_FNS: &[&str] = &[
        "contains", "starts_with", "ends_with", "regex", "matches",
    ];
    !MATCHER_FNS.iter().any(|fn_| source.contains(fn_))
}

/// A proposed program from the agent analysis.
pub struct ProposedProgram {
    pub name: String,
    pub description: String,
    pub source: String,
    pub phase: String,
    pub scope: String,
    pub rationale: String,
    pub model_filter: Option<String>,
    pub app_filter: Option<String>,
    /// Optional fast-find / span-finder regex. Blank/None ⇒ no trigger (full
    /// mode runs unconditionally). Required when `match_mode` is `span`.
    pub trigger_regex: Option<String>,
    /// `span` runs the script per `trigger_regex` match (`fn transform(m)`);
    /// anything else (including None/`full`) is full mode (`fn transform(ctx)`).
    pub match_mode: Option<String>,
}

/// A finding from the agent analysis.
pub struct Finding {
    pub severity: String,
    pub category: String,
    pub description: String,
}

/// A session label proposed by a cluster expert.
pub struct SessionLabel {
    pub session_id: String,
    pub label_type: String,
    pub label_value: String,
    pub confidence: String,
    pub note: String,
    /// Parent turn the child was spawned from — the code-detected turn when the
    /// judge confirmed a spawn point, else the judge's estimate.
    pub spawn_turn: Option<i32>,
    /// Tool-call id of the confirmed spawn call in the parent (None when no
    /// detected spawn point matched). Anchors the child card precisely.
    pub spawn_tool_call_id: Option<String>,
}

/// A tool risk rule proposed by expert analysis. Carries the unified rule
/// shape directly — the agent emits a fully-formed Rule (minus is_builtin
/// which the server stamps on approval).
///
/// Implements `Deserialize` so callers can drop the agent's raw JSON object
/// straight into this struct via `serde_json::from_value` without per-field
/// destructuring. Fields mirror `tool_rules::Rule` plus the proposal-only
/// `rationale` text.
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProposedToolRule {
    /// Stable rule identifier the agent assigned (e.g. `ASI06-01`,
    /// `CUSTOM-SLACK`). Required: a proposal without one does not parse.
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub risk: String,
    /// Phase × scope: `request` × `tool_definitions|tool_results` or
    /// `response` × `tool_calls`.
    pub phase: streamscope_core::config::tool_rules::Phase,
    pub scope: streamscope_core::config::tool_rules::Scope,
    /// AND-of-conditions. Empty = catch-all (rare for proposals).
    #[serde(default, rename = "match")]
    pub conditions: Vec<streamscope_core::config::tool_rules::MatchCondition>,
    /// Tagged action enum: `classify` | `block` | `replace { regex?, with?,
    /// drop }` | `substitute { with, intercept }` | `intercept_only { handler }`.
    /// The scope/phase governs which kinds `validate` accepts.
    pub action: streamscope_core::config::tool_rules::RuleAction,
    #[serde(default = "default_proposal_priority")]
    pub priority: i32,
    #[serde(default)]
    pub model_filter: Option<String>,
    #[serde(default)]
    pub app_filter: Option<String>,
    #[serde(default)]
    pub mcp_server_filter: Option<String>,
    pub rationale: String,
    /// Optional framework citations — list of ids from the security-framework
    /// knowledge pack (e.g. `["OWASP-LLM01", "CWE-78"]`). Populated only when
    /// the expert consumed the framework input type. Empty for pure
    /// traffic-driven proposals. Stamped onto the approved rule.
    #[serde(default)]
    pub framework_refs: Vec<String>,
}

/// A tool field profile proposed by expert analysis. Mirrors
/// `tool_rules::FieldProfile` (minus server-managed `is_builtin`) plus the
/// proposal-only `rationale`. Deserialized straight from the agent's JSON.
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProposedFieldProfile {
    /// Optional stable id; auto-generated on approval when absent.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    /// Canonical concept id (`shell_exec`, `read_file`, …).
    pub tool_id: String,
    /// Pipe-separated case-insensitive glob over the wire tool name.
    pub tool_pattern: String,
    #[serde(default)]
    pub app_filter: Option<String>,
    #[serde(default)]
    pub mcp_server: Option<String>,
    #[serde(default)]
    pub server_type: Option<String>,
    /// Canonical arg name (`command`, `path`, …) referenced by `arg.<field>` rules.
    pub field: String,
    /// Actual wire arg key when it differs from the canonical `field`.
    #[serde(default)]
    pub wire_field: Option<String>,
    pub normalizer: streamscope_core::config::tool_rules_normalize::Normalizer,
    #[serde(default = "default_proposal_priority")]
    pub priority: i32,
    pub rationale: String,
}

fn default_proposal_priority() -> i32 {
    100
}

/// Apply session labels (e.g. parent_session_id links) from expert analysis.
/// Returns the count of labels successfully applied.
pub async fn store_session_labels(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    labels: &[SessionLabel],
) -> usize {
    let mut applied = 0;
    for label in labels {
        let Ok(child_id) = uuid::Uuid::parse_str(&label.session_id) else {
            tracing::warn!(session_id = %label.session_id, "invalid session UUID in label");
            continue;
        };
        if label.label_type.as_str() != "parent_session_id" {
            tracing::warn!(label_type = %label.label_type, "unsupported session label type");
            continue;
        }
        let Ok(parent_id) = uuid::Uuid::parse_str(&label.label_value) else {
            tracing::warn!(label_value = %label.label_value, "invalid parent session UUID");
            continue;
        };
        match write_linkage_relation(
            conn, tenant_id, child_id, parent_id, "agent", &label.confidence, label.spawn_turn,
            label.spawn_tool_call_id.as_deref(),
        )
        .await
        {
            Ok(true) => {
                tracing::info!(
                    child = %child_id, parent = %parent_id,
                    confidence = %label.confidence, note = %label.note,
                    "linked child to parent session"
                );
                applied += 1;
            }
            Ok(false) => tracing::debug!(child = %child_id, "session already linked, skipping"),
            Err(e) => tracing::error!(child = %child_id, parent = %parent_id, "failed to apply session label: {e}"),
        }
    }
    applied
}

/// Insert a `kind='linkage'` cross-session relation (parent→child) with
/// FIRST-WRITE-WINS semantics: the one-parent-per-child partial unique index
/// (`role='child'`) turns a second link on an already-linked child into a no-op
/// via `ON CONFLICT DO NOTHING`, preserving the old "don't override an existing
/// (e.g. header-derived) link" guarantee across concurrent writers. Returns
/// `Ok(true)` when a new link landed, `Ok(false)` when the child was already
/// linked. The agent's (`origin='agent'`) writer; edge ingestion's header
/// linkage (`origin='header'`) runs the same statements — the `LINKAGE_*_SQL`
/// constants — on its own connection, so both produce the identical relation.
#[allow(clippy::too_many_arguments)] // one relation row's columns, kept flat over the two call sites
pub async fn write_linkage_relation(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    child_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    origin: &str,
    confidence: &str,
    spawn_turn: Option<i32>,
    spawn_tool_call_id: Option<&str>,
) -> Result<bool, sqlx::Error> {
    // A session is never its own parent — reject a self-link (a duplicated index
    // from the agent, or an `X-Parent-Session-Id` equal to the session's own id)
    // so it can't inflate the session's child_count.
    if child_id == parent_id {
        return Ok(false);
    }
    let mut tx = conn.begin().await?;
    let relation_id: uuid::Uuid = sqlx::query_scalar(LINKAGE_RELATION_SQL)
        .bind(tenant_id)
        .bind(confidence)
        .bind(spawn_turn)
        .bind(spawn_tool_call_id)
        .bind(origin)
        .fetch_one(&mut *tx)
        .await?;
    // Child member carries the one-parent guard; a conflict (child already has a
    // parent) returns no row → the whole relation is rolled back.
    let landed: Option<uuid::Uuid> = sqlx::query_scalar(LINKAGE_CHILD_SQL)
        .bind(relation_id)
        .bind(tenant_id)
        .bind(child_id)
        .fetch_optional(&mut *tx)
        .await?;
    if landed.is_none() {
        tx.rollback().await?;
        return Ok(false);
    }
    sqlx::query(LINKAGE_PARENT_SQL)
        .bind(relation_id)
        .bind(tenant_id)
        .bind(parent_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// The linkage relation row: `$1` tenant, `$2` confidence, `$3` spawn turn,
/// `$4` spawn tool-call id, `$5` origin. Shared with the edge ingest writer's
/// header linkage, so both produce the identical relation shape.
pub(crate) const LINKAGE_RELATION_SQL: &str =
    "INSERT INTO cross_session_relations (tenant_id, kind, confidence, spawn_turn, spawn_tool_call_id, origin) \
     VALUES ($1, 'linkage', $2, $3, $4, $5) RETURNING id";

/// The child member (`$1` relation, `$2` tenant, `$3` session): no row when the
/// child already has a parent (the one-parent-per-child guard).
pub(crate) const LINKAGE_CHILD_SQL: &str =
    "INSERT INTO cross_session_relation_members (relation_id, tenant_id, session_id, role, seq) \
     VALUES ($1, $2, $3, 'child', 0) ON CONFLICT DO NOTHING RETURNING relation_id";

/// The parent member (`$1` relation, `$2` tenant, `$3` session).
pub(crate) const LINKAGE_PARENT_SQL: &str =
    "INSERT INTO cross_session_relation_members (relation_id, tenant_id, session_id, role, seq) \
     VALUES ($1, $2, $3, 'parent', 0)";

/// Store suggestions from an analysis cycle into the database.
/// Uses a tenant-scoped connection; `tenant_id` is used for INSERT column values.
pub async fn store_suggestions(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    expert_axis: &str,
    findings: &[Finding],
    programs: &[ProposedProgram],
    source_session_ids: &[String],
) -> Result<usize, sqlx::Error> {
    let mut stored = 0;

    let cap = crate::settings::admin_settings().agent_suggestions_per_cycle_cap;
    let programs = if programs.len() > cap {
        tracing::warn!(
            axis = %expert_axis,
            received = programs.len(),
            cap,
            "agent proposed more program suggestions than per-cycle cap; truncating"
        );
        &programs[..cap]
    } else {
        programs
    };

    for program in programs {
        // Comma-separated filters are a schema mismatch — the runtime splits
        // on `|`. Drop the proposal rather than store one that will silently
        // fail to match anything at apply time.
        let bad_filter = [
            ("model_filter", program.model_filter.as_deref()),
            ("app_filter", program.app_filter.as_deref()),
        ]
        .into_iter()
        .find(|(_, val)| {
            val.is_some_and(|s| s.contains(',') && !s.contains('|'))
        });
        if let Some((name, val)) = bad_filter {
            tracing::warn!(
                axis = %expert_axis,
                program = %program.name,
                filter = name,
                value = ?val,
                "rejecting program suggestion: filter uses comma separators (schema is pipe-separated)"
            );
            continue;
        }

        // Build a title from findings context.
        let title = format!(
            "[{}] {}",
            expert_axis,
            program.name.replace('_', " ")
        );

        let source_sessions = if source_session_ids.is_empty() {
            None
        } else {
            Some(serde_json::json!(source_session_ids))
        };

        // Build rationale including relevant findings.
        let mut full_rationale = program.rationale.clone();
        let relevant: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                program.description.contains(&f.category)
                    || program.rationale.contains(&f.category)
            })
            .collect();

        if !relevant.is_empty() {
            full_rationale.push_str("\n\nRelated findings:\n");
            for f in relevant {
                full_rationale.push_str(&format!(
                    "- [{}] {}: {}\n",
                    f.severity, f.category, f.description
                ));
            }
        }

        // Normalise the span/trigger fields the same way the admin CRUD does:
        // a blank/`full`/unknown match_mode ⇒ full mode (column `NULL`); `span`
        // requires a non-blank, compiling trigger_regex (it is the span finder).
        // A bad trigger or span-without-trigger drops the proposal rather than
        // storing one that fails at apply time.
        let trigger_regex = match crate::routes::transforms::validate_trigger_regex(
            program.trigger_regex.as_deref(),
        ) {
            Ok(t) => t,
            Err(_) => {
                tracing::warn!(
                    name = %program.name,
                    axis = %expert_axis,
                    "rejecting proposed program: trigger_regex does not compile"
                );
                continue;
            }
        };
        let match_mode = match crate::routes::transforms::validate_match_mode(
            program.match_mode.as_deref(),
            trigger_regex.as_deref(),
        ) {
            Ok(m) => m,
            Err(_) => {
                tracing::warn!(
                    name = %program.name,
                    axis = %expert_axis,
                    "rejecting proposed program: span match_mode without a trigger_regex"
                );
                continue;
            }
        };
        let is_span = match_mode.as_deref() == Some("span");

        // Validate the Rhai source compiles before storing (span-aware: span
        // sources use `fn transform(m)`, not `fn transform(ctx)`).
        if let Err(reason) = validate_proposed_source(&program.source, is_span) {
            tracing::warn!(
                name = %program.name,
                axis = %expert_axis,
                reason = %reason,
                "rejecting proposed program: invalid Rhai source"
            );
            continue;
        }

        // INSERT … ON CONFLICT increments seen_count when this proposal
        // matches an existing pending entry under
        // `uniq_pending_program_suggestion`. The rationale + span/trigger fields
        // are refreshed so the latest cycle's reasoning wins; everything else stays.
        sqlx::query(
            "INSERT INTO program_suggestions \
                (tenant_id, expert_axis, title, rationale, proposed_source, \
                 proposed_phase, proposed_scope, proposed_model_filter, \
                 proposed_app_filter, proposed_trigger_regex, proposed_match_mode, \
                 source_sessions) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (tenant_id, expert_axis, title) \
                 WHERE status = 'pending' \
             DO UPDATE SET \
                 seen_count = program_suggestions.seen_count + 1, \
                 last_seen_at = NOW(), \
                 rationale = EXCLUDED.rationale, \
                 proposed_trigger_regex = EXCLUDED.proposed_trigger_regex, \
                 proposed_match_mode = EXCLUDED.proposed_match_mode, \
                 source_sessions = EXCLUDED.source_sessions"
        )
        .bind(tenant_id)
        .bind(expert_axis)
        .bind(&title)
        .bind(&full_rationale)
        .bind(&program.source)
        .bind(&program.phase)
        .bind(&program.scope)
        .bind(&program.model_filter)
        .bind(&program.app_filter)
        .bind(&trigger_regex)
        .bind(&match_mode)
        .bind(&source_sessions)
        .execute(&mut *conn)
        .await?;

        stored += 1;
    }

    Ok(stored)
}

/// The rule an approval of `proposal` would store, run through the checks a
/// rule created through the API passes: an id of the shape the API requires
/// (approval stores it as the rule's own) and the same shape validator — a
/// malformed suggestion is dropped rather than poisoning the list.
fn candidate_rule(proposal: &ProposedToolRule) -> Result<streamscope_core::config::tool_rules::Rule, String> {
    use streamscope_core::config::tool_rules::{validate, Rule};
    let rule = Rule {
        id: proposal.id.trim().to_string(),
        title: Some(proposal.title.clone()),
        description: proposal.description.clone(),
        risk: proposal.risk.clone(),
        phase: proposal.phase,
        scope: proposal.scope,
        conditions: proposal.conditions.clone(),
        action: proposal.action.clone(),
        priority: proposal.priority,
        model_filter: proposal.model_filter.clone(),
        app_filter: proposal.app_filter.clone(),
        mcp_server_filter: proposal.mcp_server_filter.clone(),
        // Experts do not propose agent-scoped rules — the analysis prompt has
        // no A2A axis; an operator adds the filter when adopting a rule.
        a2a_agent_filter: None,
        enabled: true,
        framework_refs: proposal.framework_refs.clone(),
        is_builtin: false,
        profile_id: None,
        forked_from: None,
    };
    if !crate::routes::tool_rules::is_valid_rule_id(&rule.id) {
        return Err("invalid rule id".to_string());
    }
    validate(&rule).map_err(|e| format!("invalid shape: {e:?}"))?;
    Ok(rule)
}

/// Store tool rule suggestions from an analysis cycle: each checked by
/// [`candidate_rule`] and the semantic check, and deduplicated against pending
/// suggestions by id and title.
pub async fn store_tool_rule_suggestions(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    expert_axis: &str,
    rules: &[ProposedToolRule],
    findings: &[Finding],
    source_session_ids: &[String],
) -> Result<usize, sqlx::Error> {
    let mut stored = 0;

    let cap = crate::settings::admin_settings().agent_suggestions_per_cycle_cap;
    let rules = if rules.len() > cap {
        tracing::warn!(
            axis = %expert_axis,
            received = rules.len(),
            cap,
            "agent proposed more tool-rule suggestions than per-cycle cap; truncating"
        );
        &rules[..cap]
    } else {
        rules
    };

    for proposal in rules {
        let candidate = match candidate_rule(proposal) {
            Ok(rule) => rule,
            Err(reason) => {
                tracing::warn!(
                    axis = %expert_axis,
                    proposal_id = ?proposal.id,
                    reason = %reason,
                    "rejecting tool rule suggestion"
                );
                continue;
            }
        };
        let builtin_ids = crate::seed_loader::builtin_tool_rule_ids();
        if let Err(reason) = streamscope_core::config::tool_rules_semantic::semantic_check(
            &candidate,
            builtin_ids,
        ) {
            tracing::warn!(
                axis = %expert_axis,
                proposal_id = ?proposal.id,
                reason = %reason,
                "rejecting tool rule suggestion: semantic check failed"
            );
            continue;
        }

        let title = format!("[{}] {}", expert_axis, proposal.title);
        let phase_str = serde_json::to_value(proposal.phase)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "response".to_string());
        let scope_str = serde_json::to_value(proposal.scope)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "tool_calls".to_string());
        let action_json = serde_json::to_value(&proposal.action).unwrap_or_else(|_| {
            serde_json::json!({"kind": "classify"})
        });
        let match_json = serde_json::to_value(&proposal.conditions).unwrap_or_else(|_| {
            serde_json::Value::Array(vec![])
        });

        // Build rationale with any related findings.
        let mut full_rationale = proposal.rationale.clone();
        let relevant: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                proposal.rationale.contains(&f.category) || proposal.title.contains(&f.category)
            })
            .collect();
        if !relevant.is_empty() {
            full_rationale.push_str("\n\nRelated findings:\n");
            for f in relevant {
                full_rationale.push_str(&format!(
                    "- [{}] {}: {}\n",
                    f.severity, f.category, f.description
                ));
            }
        }

        let source_sessions = if source_session_ids.is_empty() {
            None
        } else {
            Some(serde_json::json!(source_session_ids))
        };

        let framework_refs = if proposal.framework_refs.is_empty() {
            None
        } else {
            Some(serde_json::json!(proposal.framework_refs))
        };

        // INSERT … ON CONFLICT increments seen_count when this proposal
        // matches an existing pending entry under
        // `uniq_pending_tool_rule_suggestion`. The mutable fields (rationale,
        // match_conditions, action, source_sessions) are refreshed so the
        // latest cycle's content wins; identity (id, title) stays. The id is
        // the trimmed one `semantic_check` passed (never empty).
        let proposed_rule_id = candidate.id.as_str();
        sqlx::query(
            "INSERT INTO tool_rule_suggestions \
                (tenant_id, expert_axis, proposed_rule_id, title, description, risk, \
                 phase, scope, match_conditions, action, priority, model_filter, \
                 app_filter, mcp_server_filter, rationale, source_sessions, framework_refs) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) \
             ON CONFLICT (tenant_id, expert_axis, proposed_rule_id, title) \
                 WHERE status = 'pending' \
             DO UPDATE SET \
                 seen_count = tool_rule_suggestions.seen_count + 1, \
                 last_seen_at = NOW(), \
                 rationale = EXCLUDED.rationale, \
                 match_conditions = EXCLUDED.match_conditions, \
                 action = EXCLUDED.action, \
                 source_sessions = EXCLUDED.source_sessions",
        )
        .bind(tenant_id)
        .bind(expert_axis)
        .bind(proposed_rule_id)
        .bind(&title)
        .bind(&proposal.description)
        .bind(&proposal.risk)
        .bind(&phase_str)
        .bind(&scope_str)
        .bind(&match_json)
        .bind(&action_json)
        .bind(proposal.priority)
        .bind(&proposal.model_filter)
        .bind(&proposal.app_filter)
        .bind(&proposal.mcp_server_filter)
        .bind(&full_rationale)
        .bind(&source_sessions)
        .bind(&framework_refs)
        .execute(&mut *conn)
        .await?;

        stored += 1;
    }

    Ok(stored)
}

/// Store field-profile suggestions from an analysis cycle. Validates each
/// candidate through the same `validate_field_profile` the admin CRUD uses
/// (dropping a malformed one with a warn) and deduplicates against pending
/// suggestions by `(tool_pattern, field)`.
pub async fn store_field_profile_suggestions(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    expert_axis: &str,
    profiles: &[ProposedFieldProfile],
    findings: &[Finding],
    source_session_ids: &[String],
) -> Result<usize, sqlx::Error> {
    use streamscope_core::config::tool_rules::{validate_field_profile, FieldProfile};
    let mut stored = 0;

    let cap = crate::settings::admin_settings().agent_suggestions_per_cycle_cap;
    let profiles = if profiles.len() > cap {
        tracing::warn!(
            axis = %expert_axis,
            received = profiles.len(),
            cap,
            "agent proposed more field-profile suggestions than per-cycle cap; truncating"
        );
        &profiles[..cap]
    } else {
        profiles
    };

    for proposal in profiles {
        // Run through the same validator the admin CRUD uses — a malformed
        // proposal (empty tool_pattern/field, mutually-exclusive scopes, bad
        // chars) is dropped with a warn rather than poisoning the queue.
        let candidate = FieldProfile {
            id: proposal.id.clone(),
            description: proposal.description.clone(),
            source: proposal.source.clone(),
            tool_id: proposal.tool_id.clone(),
            tool_pattern: proposal.tool_pattern.clone(),
            app_filter: proposal.app_filter.clone(),
            mcp_server: proposal.mcp_server.clone(),
            server_type: proposal.server_type.clone(),
            field: proposal.field.clone(),
            wire_field: proposal.wire_field.clone(),
            normalizer: proposal.normalizer,
            priority: proposal.priority,
            is_builtin: false,
        };
        if let Err(e) = validate_field_profile(&candidate) {
            tracing::warn!(
                axis = %expert_axis,
                tool_pattern = %proposal.tool_pattern,
                field = %proposal.field,
                error = ?e,
                "rejecting field-profile suggestion: invalid shape"
            );
            continue;
        }

        let normalizer_str = serde_json::to_value(proposal.normalizer)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "raw".to_string());

        // Append related findings to the rationale (same pattern as the other stores).
        let mut full_rationale = proposal.rationale.clone();
        let relevant: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                proposal.rationale.contains(&f.category)
                    || proposal.tool_id.contains(&f.category)
            })
            .collect();
        if !relevant.is_empty() {
            full_rationale.push_str("\n\nRelated findings:\n");
            for f in relevant {
                full_rationale.push_str(&format!(
                    "- [{}] {}: {}\n",
                    f.severity, f.category, f.description
                ));
            }
        }

        let source_sessions = if source_session_ids.is_empty() {
            None
        } else {
            Some(serde_json::json!(source_session_ids))
        };

        sqlx::query(
            "INSERT INTO field_profile_suggestions \
                (tenant_id, expert_axis, proposed_profile_id, description, source, \
                 tool_id, tool_pattern, app_filter, mcp_server, server_type, field, \
                 wire_field, normalizer, priority, rationale, source_sessions) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
             ON CONFLICT (tenant_id, expert_axis, tool_pattern, field) \
                 WHERE status = 'pending' \
             DO UPDATE SET \
                 seen_count = field_profile_suggestions.seen_count + 1, \
                 last_seen_at = NOW(), \
                 tool_id = EXCLUDED.tool_id, \
                 wire_field = EXCLUDED.wire_field, \
                 normalizer = EXCLUDED.normalizer, \
                 rationale = EXCLUDED.rationale, \
                 source_sessions = EXCLUDED.source_sessions",
        )
        .bind(tenant_id)
        .bind(expert_axis)
        .bind(&proposal.id)
        .bind(&proposal.description)
        .bind(&proposal.source)
        .bind(&proposal.tool_id)
        .bind(&proposal.tool_pattern)
        .bind(&proposal.app_filter)
        .bind(&proposal.mcp_server)
        .bind(&proposal.server_type)
        .bind(&proposal.field)
        .bind(&proposal.wire_field)
        .bind(&normalizer_str)
        .bind(proposal.priority)
        .bind(&full_rationale)
        .bind(&source_sessions)
        .execute(&mut *conn)
        .await?;

        stored += 1;
    }

    Ok(stored)
}

#[cfg(test)]
mod rhai_validator_tests {
    use super::validate_proposed_source;

    const PASSTHROUGH: &str = "fn transform(ctx) { ctx }";

    #[test]
    fn accepts_minimal_passthrough() {
        assert!(validate_proposed_source(PASSTHROUGH, false).is_ok());
    }

    #[test]
    fn rejects_messages_dot_content() {
        let src = "fn transform(ctx) { let m = ctx.messages.content; ctx }";
        let err = validate_proposed_source(src, false).unwrap_err();
        assert!(err.contains("ctx.messages"), "got: {err}");
        assert!(err.contains("array"), "got: {err}");
    }

    #[test]
    fn rejects_messages_dot_role() {
        let src = "fn transform(ctx) { let r = ctx.messages.role; ctx }";
        let err = validate_proposed_source(src, false).unwrap_err();
        assert!(err.contains("ctx.messages.role"), "got: {err}");
    }

    #[test]
    fn accepts_indexed_messages_access() {
        let src = "fn transform(ctx) { if ctx.messages.len() > 0 { let m = ctx.messages[0].content; } ctx }";
        assert!(validate_proposed_source(src, false).is_ok());
    }

    #[test]
    fn rejects_tools_wholesale_wipe() {
        let src = "fn transform(ctx) { ctx.tools = []; ctx }";
        let err = validate_proposed_source(src, false).unwrap_err();
        assert!(err.contains("wipes"), "got: {err}");
    }

    #[test]
    fn rejects_messages_wholesale_wipe() {
        let src = "fn transform(ctx) { ctx.messages = [ ]; ctx }";
        let err = validate_proposed_source(src, false).unwrap_err();
        assert!(err.contains("wipes"), "got: {err}");
    }

    #[test]
    fn accepts_tools_assignment_from_variable() {
        let src = "fn transform(ctx) { let filtered = []; ctx.tools = filtered; ctx }";
        assert!(validate_proposed_source(src, false).is_ok());
    }

    #[test]
    fn rejects_session_specific_literals_without_matchers() {
        let src = r#"fn transform(ctx) {
            let template = "Draft a quarterly business review email for ARR: $4.2M";
            let context = "Customer is enterprise tier with multi-region deployment notes";
            ctx
        }"#;
        let err = validate_proposed_source(src, false).unwrap_err();
        assert!(err.contains("hardcoded"), "got: {err}");
    }

    #[test]
    fn accepts_long_literals_when_matchers_referenced() {
        let src = r#"fn transform(ctx) {
            let needle = "this is a fairly long string literal we will search for";
            let other  = "this is another fairly long string literal in the script";
            if ctx.system_prompt.contains(needle) { ctx.system_prompt = other; }
            ctx
        }"#;
        assert!(validate_proposed_source(src, false).is_ok());
    }

    #[test]
    fn accepts_short_literals() {
        let src = r#"fn transform(ctx) { let a = "short"; let b = "another"; ctx }"#;
        assert!(validate_proposed_source(src, false).is_ok());
    }

    #[test]
    fn span_source_accepts_transform_m_returning_string() {
        // Span sources use `fn transform(m)` — the ctx-shaped lints must NOT
        // run, and a per-match string return is the canonical span shape.
        let src = "fn transform(m) { m.matched.to_upper() }";
        assert!(validate_proposed_source(src, true).is_ok());
    }

    #[test]
    fn span_source_skips_ctx_lints() {
        // A span script may legitimately reference `messages`-like identifiers
        // in its own logic; the full-mode `ctx.messages = []` wipe lint would
        // false-reject it, so span mode must skip those lints.
        let src = "fn transform(m) { let messages = []; m.matched }";
        assert!(validate_proposed_source(src, true).is_ok());
    }

    #[test]
    fn span_source_still_rejects_uncompilable() {
        let src = "fn transform(m) { this is not valid rhai ";
        assert!(validate_proposed_source(src, true).is_err());
    }
}

#[cfg(test)]
mod candidate_rule_tests {
    use super::{candidate_rule, ProposedToolRule};

    fn proposal(id: &str) -> ProposedToolRule {
        serde_json::from_value(serde_json::json!({
            "id": id, "title": "t", "risk": "danger", "phase": "response", "scope": "tool_calls",
            "match": [], "action": {"kind": "block"}, "rationale": "r"
        }))
        .expect("a proposal")
    }

    #[test]
    fn a_suggested_rule_needs_the_id_shape_a_created_rule_has() {
        // Each refused class beside the accepted one, and the length limit on
        // both sides.
        for id in ["", "   ", "CUSTOM SLACK", "a/b", "é", &"x".repeat(65)] {
            assert!(candidate_rule(&proposal(id)).is_err(), "{id:?} was accepted");
        }
        for id in ["CUSTOM-SLACK_1.2", &"x".repeat(64)] {
            assert_eq!(candidate_rule(&proposal(id)).expect(id).id, id);
        }
        // The id is stored trimmed.
        assert_eq!(candidate_rule(&proposal(" C-1 ")).expect("trimmed").id, "C-1");
    }
}
