//! Agent analysis cycle — per-session expert analysis with context budgeting.
//!
//! Fetches sessions via direct DB queries (calling `list_sessions_impl` and
//! `get_conversation_impl` internally, not HTTP). Each session is analyzed
//! individually with a context budget scaled to 60% of the upstream model's
//! context window. Produces [`Finding`]s containing program proposals, alerts,
//! and memory updates. Uses LLM tool calling (`submit_analysis`) for structured output.

use std::sync::Arc;

use crate::AdminState;

use crate::db::tenant::{TenantConn, TenantId};
use crate::routes::WorkspaceIds;

use super::experts::Expert;
use super::suggestion::{Finding, ProposedProgram};
use super::AgentConfig;

/// Max chars for expert memory in context.
const MEMORY_BUDGET: usize = 4_000;
/// Max chars for active programs in context.
const PROGRAMS_BUDGET: usize = 4_000;
/// Max chars for rejected suggestions in context.
const REJECTED_BUDGET: usize = 4_000;
/// Fixed overhead for system prompt + Rhai reference + memory reference + framing text.
const FIXED_OVERHEAD: usize = 10_000;
/// Max chars for memory stored in DB.
const MEMORY_CAP: usize = 4_000;
/// Default context window (tokens) when upstream has no context_window set.
/// Conservative default — minimum for quality LLMs (GPT-4o class).
const DEFAULT_CONTEXT_WINDOW: i32 = 32_000;
/// Safe fraction of context window to use (leave room for response + system prompt tokens).
const CONTEXT_USAGE_RATIO: f64 = 0.6;
/// Approximate characters per token.
const CHARS_PER_TOKEN: usize = 4;
/// Max rejected suggestions to fetch per expert for dedup context.
const REJECTED_SUGGESTIONS_LIMIT: i64 = 50;

/// Bound on a failed proxy call's body. It only ever lands in a log line and an
/// error message, so a small cap loses nothing.
const AGENT_ERROR_BODY_CAP: u64 = 64 * 1024;

/// Expert with its DB id and memory (per-profile watermarks load separately).
struct ExpertWithProgress {
    id: uuid::Uuid,
    expert: Expert,
    memory: String,
    input_types: Vec<String>,
    output_types: Vec<String>,
    model_override: Option<String>,
    /// Whether this expert pools into merged analysis calls. `false` = always
    /// a solo call (its own group), regardless of shape compatibility.
    merge_enabled: bool,
}


/// Which traffic path a pooled-call group runs over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupPath {
    Session,
    Cluster,
}

/// Pure grouping key for one (expert, profile, path) participation. An expert
/// with both `session` and `session_cluster` inputs contributes one entry per
/// path, per expert profile it is an effective member of.
#[derive(Debug)]
struct GroupingInput {
    expert_idx: usize,
    path: GroupPath,
    /// Resolved model alias the expert's calls route through (the profile's
    /// judge model unless the expert carries a `model_override`).
    routing_alias: String,
    /// Index into the cycle's expert-profile partition — the profile IS the
    /// workspace scope, so pooling never crosses profiles.
    profile_idx: usize,
    merge_enabled: bool,
}

/// Group (expert, profile, path) participations into pooled-call groups.
///
/// Merge-enabled members sharing (path, routing alias, profile) pool into one
/// group — one LLM call per session/cluster answers every member axis. A
/// merge-disabled member is always its own solo group. Group order is
/// first-occurrence input order, so the round-robin turn order is stable.
fn group_experts(inputs: &[GroupingInput]) -> Vec<(GroupPath, usize, Vec<usize>)> {
    let mut keys: Vec<Option<(GroupPath, &str, usize)>> = Vec::new();
    let mut groups: Vec<(GroupPath, usize, Vec<usize>)> = Vec::new();

    for input in inputs {
        if input.merge_enabled {
            let key = (input.path, input.routing_alias.as_str(), input.profile_idx);
            if let Some(pos) = keys.iter().position(|k| *k == Some(key)) {
                groups[pos].2.push(input.expert_idx);
                continue;
            }
            keys.push(Some(key));
        } else {
            // Solo group — a sentinel keeps positions aligned between
            // `keys` and `groups` without ever matching a shared key.
            keys.push(None);
        }
        groups.push((input.path, input.profile_idx, vec![input.expert_idx]));
    }

    groups
}

/// Whether a cluster-path member applies to a cluster of the given size.
/// Linkage-style members (outputs limited to `session_label` + `memory`) need
/// at least two sessions — there is nothing to link in a singleton; members
/// with any other output (alerts, transforms, …) analyze singletons too.
fn member_applies_to_cluster(output_types: &[String], cluster_len: usize) -> bool {
    cluster_len >= 2
        || output_types
            .iter()
            .any(|t| t != "session_label" && t != "memory")
}

/// Per-member outcome of one pooled analysis call (`T` is the per-path result
/// type: [`SessionAnalysisResult`] or [`ClusterAnalysisResult`]).
enum AxisOutcome<T> {
    /// The axis answered — payload parsed into the member's result.
    Answered(Box<T>),
    /// The response omitted this mandatory axis. Partial accept: the other
    /// axes' results stand; only this member's watermark holds so the input
    /// re-analyzes for just this axis next cycle.
    Missing,
}

/// Accumulated per-member results across a group's round-robin turns.
/// Suggestions are stored once per cycle at group end (insert-or-bump keyed by
/// content — one store per cycle keeps the seen-counters honest); alerts and
/// session labels are written immediately per call instead.
#[derive(Default)]
struct MemberAcc {
    programs: Vec<ProposedProgram>,
    tool_rules: Vec<super::suggestion::ProposedToolRule>,
    findings: Vec<Finding>,
    session_ids: Vec<String>,
    last_memory_update: String,
    total_findings: usize,
    total_programs: usize,
    total_alerts: usize,
}

/// Live state of one pooled-call group across the cycle's round-robin turns.
/// Per-member vectors are aligned with `member_idx`.
struct GroupRun {
    path: GroupPath,
    /// Indices into the cycle's expert list.
    member_idx: Vec<usize>,
    routing: AgentRouting,
    /// The expert profile this group runs under — the watermark dimension
    /// (`expert_profile_watermarks` keys on it) and the workspace scope.
    profile_id: uuid::Uuid,
    /// Profile name, for log lines (one axis can run in several profiles).
    profile_name: String,
    /// The profile's workspace set. `None` = every
    /// workspace (the Default profile while no other assignment exists).
    ws_filter: Option<WorkspaceIds>,
    /// Also fetch sessions with no issuing key (orphan sessions follow the
    /// Default profile).
    include_keyless: bool,
    /// Merged panel system prompt — `None` for a solo group, which uses the
    /// member's own assembled prompt.
    system_prompt: Option<String>,
    rejected: Vec<Vec<String>>,
    /// Per-member scan cursor, seeded from `last_processed_at`.
    cursors: Vec<Option<chrono::DateTime<chrono::Utc>>>,
    /// Sticky per-member hold: a transient failure or an omitted axis keeps
    /// the member's watermark below the failure and skips its end-of-cycle
    /// jump to effective-now.
    held: Vec<bool>,
    acc: Vec<MemberAcc>,
    total_sessions: i64,
    done: bool,
    /// True once a turn observed the end of the backlog (empty fetch or a
    /// short batch). The end-of-cycle jump to effective-now is gated on it: a
    /// group retired early (transient hold, no-progress guard) has NOT scanned
    /// past its window, and jumping un-held members would silently skip every
    /// later session forever.
    drained: bool,
    /// Sessions/clusters skipped this cycle on a deterministic failure. A
    /// handful is a poison payload; a pile is systematic (bad model config,
    /// schema rejection) — the cycle end notifies the operator past a
    /// threshold instead of letting warn-level skips silently eat the backlog.
    deterministic_skips: usize,
    /// One representative deterministic-failure message for the notification.
    deterministic_sample: Option<String>,
}

impl GroupRun {
    /// Group scan cursor: the oldest member cursor (`None` = a member has
    /// never processed anything, so the scan starts from the beginning).
    fn scan_cursor(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.cursors.iter().copied().min().flatten()
    }
}

/// One round-robin turn of a session-path group: fetch one batch from the
/// group scan cursor, analyze each session with one pooled call over the
/// members it still applies to, fold the per-member watermarks (advance over
/// successes + deterministic skips, hold below the oldest transient failure
/// or omitted axis), and retire the group when the backlog is drained, a
/// transient failure holds it, or no watermark moved.
#[allow(clippy::too_many_arguments)]
async fn run_session_group_turn(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    client: &reqwest::Client,
    config: &AgentConfig,
    cooldown: i64,
    experts: &[ExpertWithProgress],
    run: &mut GroupRun,
    active_programs: &[String],
) -> anyhow::Result<()> {
    let sessions = fetch_sessions_via_db(
        pool,
        tenant_id,
        run.scan_cursor(),
        cooldown,
        run.ws_filter.as_ref(),
        run.include_keyless,
    )
    .await?;

    if sessions.is_empty() {
        run.drained = true;
        run.done = true;
        return Ok(());
    }

    let batch_size = sessions.len() as i64;
    run.total_sessions += batch_size;
    let concurrency = crate::settings::admin_settings()
        .agent_session_concurrency
        .max(1);

    {
        let axes: Vec<&str> = run
            .member_idx
            .iter()
            .map(|&i| experts[i].expert.axis.as_str())
            .collect();
        tracing::info!(
            axes = ?axes,
            batch_size,
            total_so_far = run.total_sessions,
            concurrency,
            "analyzing session batch"
        );
    }

    // Member positions each session still applies to (cursor < session ts) —
    // after a partial hold, re-fetched sessions re-run only for the lagging
    // members.
    let applicable_per_session: Vec<Vec<usize>> = sessions
        .iter()
        .map(|s| {
            (0..run.member_idx.len())
                .filter(|&p| match (run.cursors[p], s.last_timestamp) {
                    (None, _) => true,
                    (Some(c), Some(ts)) => ts > c,
                    (Some(_), None) => false,
                })
                .collect()
        })
        .collect();

    // Run the batch with bounded parallelism; outcomes stay aligned with
    // `sessions` so they zip back cleanly.
    let mut outcomes: Vec<anyhow::Result<Vec<AxisOutcome<SessionAnalysisResult>>>> =
        Vec::with_capacity(sessions.len());
    for chunk_start in (0..sessions.len()).step_by(concurrency) {
        let chunk_end = (chunk_start + concurrency).min(sessions.len());
        let futs = (chunk_start..chunk_end).map(|si| {
            let session = &sessions[si];
            let applicable = &applicable_per_session[si];
            let run = &*run;
            async move {
                if applicable.is_empty() {
                    return Ok(Vec::new());
                }
                let members: Vec<&ExpertWithProgress> = applicable
                    .iter()
                    .map(|&p| &experts[run.member_idx[p]])
                    .collect();
                let rejected: Vec<&[String]> = applicable
                    .iter()
                    .map(|&p| run.rejected[p].as_slice())
                    .collect();
                if members.len() == 1 {
                    analyze_single_session(
                        pool,
                        tenant_id,
                        client,
                        config,
                        &run.routing,
                        members[0],
                        session,
                        active_programs,
                        rejected[0],
                    )
                    .await
                    .map(|r| vec![AxisOutcome::Answered(Box::new(r))])
                } else {
                    analyze_session_merged(
                        pool,
                        tenant_id,
                        client,
                        config,
                        &run.routing,
                        run.system_prompt.as_deref().unwrap_or_default(),
                        &members,
                        &rejected,
                        session,
                        active_programs,
                    )
                    .await
                }
            }
        });
        outcomes.extend(futures::future::join_all(futs).await);
    }

    // Fold per member.
    let n = run.member_idx.len();
    let mut advanceable: Vec<Vec<chrono::DateTime<chrono::Utc>>> = vec![Vec::new(); n];
    let mut successes: Vec<Vec<chrono::DateTime<chrono::Utc>>> = vec![Vec::new(); n];
    let mut min_hold: Vec<Option<chrono::DateTime<chrono::Utc>>> = vec![None; n];
    let mut any_transient = false;

    for ((session, applicable), res) in sessions
        .iter()
        .zip(&applicable_per_session)
        .zip(outcomes)
    {
        let Some(ts) = session.last_timestamp else {
            continue;
        };
        match res {
            Ok(axis_outcomes) => {
                for (&p, outcome) in applicable.iter().zip(axis_outcomes) {
                    match outcome {
                        AxisOutcome::Answered(result) => {
                            advanceable[p].push(ts);
                            successes[p].push(ts);
                            let result = *result;

                            // Store session labels immediately (don't batch)
                            if !result.session_labels.is_empty()
                                && let Ok(mut tdb) =
                                    TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await
                            {
                                let stored = super::suggestion::store_session_labels(
                                    tdb.conn(),
                                    tenant_id,
                                    &result.session_labels,
                                )
                                .await;
                                if stored > 0 {
                                    tracing::info!(
                                        axis = %experts[run.member_idx[p]].expert.axis,
                                        session_id = %session.session_id,
                                        stored,
                                        "applied session labels from per-session analysis"
                                    );
                                }
                            }

                            let acc = &mut run.acc[p];
                            acc.total_findings += result.findings.len();
                            acc.total_programs += result.programs.len();
                            if result.alert.is_some() {
                                acc.total_alerts += 1;
                            }
                            if !result.programs.is_empty() || !result.tool_rules.is_empty() {
                                let sid = session.session_id.to_string();
                                if !acc.session_ids.contains(&sid) {
                                    acc.session_ids.push(sid);
                                }
                            }
                            acc.programs.extend(result.programs);
                            acc.tool_rules.extend(result.tool_rules);
                            acc.findings.extend(result.findings);
                            if !result.memory_update.is_empty() {
                                acc.last_memory_update = result.memory_update;
                            }
                        }
                        AxisOutcome::Missing => {
                            min_hold[p] = Some(min_hold[p].map_or(ts, |m| m.min(ts)));
                            run.held[p] = true;
                        }
                    }
                }
            }
            Err(e) => {
                if is_deterministic_failure(&e) {
                    // Skip-and-advance: this session fails the same way every
                    // cycle; don't let it wedge the backlog.
                    for &p in applicable {
                        advanceable[p].push(ts);
                    }
                    run.deterministic_skips += 1;
                    run.deterministic_sample.get_or_insert_with(|| e.to_string());
                    tracing::warn!(
                        session_id = %session.session_id,
                        "session analysis skipped (deterministic failure), advancing past it: {e}"
                    );
                } else {
                    // Transient: hold the watermark below it and retry.
                    for &p in applicable {
                        min_hold[p] = Some(min_hold[p].map_or(ts, |m| m.min(ts)));
                        run.held[p] = true;
                    }
                    any_transient = true;
                    tracing::error!(
                        session_id = %session.session_id,
                        "session analysis failed (transient), will retry next cycle: {e}"
                    );
                }
            }
        }
    }

    // Advance each member's watermark across its contiguous run of successes
    // and deterministic skips, never past its oldest hold.
    let mut cursor_moved = false;
    for p in 0..n {
        let (new_wm, covered) = contiguous_watermark(&advanceable[p], &successes[p], min_hold[p]);
        if let Some(nw) = new_wm
            && run.cursors[p].is_none_or(|c| nw > c)
        {
            run.cursors[p] = Some(nw);
            cursor_moved = true;
            update_expert_profile_watermark(
                pool,
                tenant_id,
                run.profile_id,
                experts[run.member_idx[p]].id,
                covered,
                nw,
            )
            .await;
        }
    }

    // A short batch means the scan reached the end of the backlog — safe to
    // jump un-held members to effective-now at finalize even if this turn also
    // held someone.
    if batch_size < crate::settings::admin_settings().agent_session_batch_limit {
        run.drained = true;
    }

    if any_transient {
        tracing::warn!(
            batch_size,
            "transient failure in batch — holding watermarks at last contiguous success, will retry next cycle"
        );
        run.done = true;
    } else if run.drained {
        run.done = true;
    } else if !cursor_moved {
        // A response persistently omitting the same axis would respin this
        // batch forever — stop the group for this cycle instead.
        tracing::warn!(batch_size, "no watermark progress in group turn — stopping group this cycle");
        run.done = true;
    }

    Ok(())
}

/// One round-robin turn of a cluster-path group: fetch one batch, cluster it
/// by (key_id, app_id) — singleton clusters included — and run one pooled call
/// per cluster over the members it applies to. Whole-call failures stay lossy
/// (the watermark still advances past the failed cluster — holding would wedge
/// the whole group on one bad cluster); an
/// omitted axis holds only that member.
#[allow(clippy::too_many_arguments)]
async fn run_cluster_group_turn(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    client: &reqwest::Client,
    config: &AgentConfig,
    cooldown: i64,
    experts: &[ExpertWithProgress],
    run: &mut GroupRun,
    active_programs: &[String],
) -> anyhow::Result<()> {
    let sessions = fetch_sessions_via_db(
        pool,
        tenant_id,
        run.scan_cursor(),
        cooldown,
        run.ws_filter.as_ref(),
        run.include_keyless,
    )
    .await?;

    if sessions.is_empty() {
        run.drained = true;
        run.done = true;
        return Ok(());
    }

    let batch_size = sessions.len() as i64;
    run.total_sessions += batch_size;
    let batch_max_ts = sessions.iter().filter_map(|s| s.last_timestamp).max();

    // Group by (key_id, app_id) — same key can be used in multiple clients.
    let mut clusters: std::collections::HashMap<(uuid::Uuid, String), Vec<&SessionMeta>> =
        std::collections::HashMap::new();
    for session in &sessions {
        if let Some(key_id) = session.key_id {
            let key = (key_id, session.app_id.clone().unwrap_or_default());
            clusters.entry(key).or_default().push(session);
        }
        // key_id is always set by auth — skip the None branch.
    }

    {
        let axes: Vec<&str> = run
            .member_idx
            .iter()
            .map(|&i| experts[i].expert.axis.as_str())
            .collect();
        tracing::info!(
            axes = ?axes,
            batch_size,
            clusters = clusters.len(),
            "analyzing session clusters"
        );
    }

    // Per-member contiguous fold over clusters (the cluster-grained analog of
    // the per-session fold): an analyzed/skipped cluster advances at its MAX
    // session timestamp; a held cluster (transient failure / omitted axis)
    // holds at its MIN session timestamp so the WHOLE cluster re-forms from
    // the next fetch — holding at the max would refetch only the tail
    // sessions and analyze a truncated cluster.
    let n_members = run.member_idx.len();
    let mut advanceable: Vec<Vec<chrono::DateTime<chrono::Utc>>> = vec![Vec::new(); n_members];
    // (cluster ts, session count) per ANSWERED cluster — the display counter
    // covers only what the member actually analyzed.
    let mut analyzed: Vec<Vec<(chrono::DateTime<chrono::Utc>, i64)>> = vec![Vec::new(); n_members];
    let mut min_hold: Vec<Option<chrono::DateTime<chrono::Utc>>> = vec![None; n_members];
    let hold = |min_hold: &mut Vec<Option<chrono::DateTime<chrono::Utc>>>,
                p: usize,
                ts: Option<chrono::DateTime<chrono::Utc>>| {
        if let Some(ts) = ts {
            min_hold[p] = Some(min_hold[p].map_or(ts, |m| m.min(ts)));
        }
    };

    for ((key_id, app_id), cluster_sessions) in &clusters {
        let cluster_max_ts = cluster_sessions.iter().filter_map(|s| s.last_timestamp).max();
        let cluster_min_ts = cluster_sessions.iter().filter_map(|s| s.last_timestamp).min();
        let applicable: Vec<usize> = (0..run.member_idx.len())
            .filter(|&p| {
                let ewp = &experts[run.member_idx[p]];
                member_applies_to_cluster(&ewp.output_types, cluster_sessions.len())
                    && match (run.cursors[p], cluster_max_ts) {
                        (None, _) => true,
                        (Some(c), Some(ts)) => ts > c,
                        (Some(_), None) => false,
                    }
            })
            .collect();
        // An inapplicable cluster is advanceable for the members it skipped.
        if let Some(ts) = cluster_max_ts {
            for (p, adv) in advanceable.iter_mut().enumerate() {
                if !applicable.contains(&p) {
                    adv.push(ts);
                }
            }
        }
        if applicable.is_empty() {
            continue;
        }

        let members: Vec<&ExpertWithProgress> = applicable
            .iter()
            .map(|&p| &experts[run.member_idx[p]])
            .collect();
        let rejected: Vec<&[String]> = applicable
            .iter()
            .map(|&p| run.rejected[p].as_slice())
            .collect();

        let result = if members.len() == 1 {
            analyze_session_cluster(
                pool,
                tenant_id,
                client,
                config,
                &run.routing,
                members[0],
                cluster_sessions,
                active_programs,
                rejected[0],
                key_id,
                app_id,
            )
            .await
            .map(|r| vec![AxisOutcome::Answered(Box::new(r))])
        } else {
            analyze_cluster_merged(
                pool,
                tenant_id,
                client,
                config,
                &run.routing,
                run.system_prompt.as_deref().unwrap_or_default(),
                &members,
                &rejected,
                cluster_sessions,
                active_programs,
                key_id,
                app_id,
            )
            .await
        };

        match result {
            Ok(axis_outcomes) => {
                for (&p, outcome) in applicable.iter().zip(axis_outcomes) {
                    match outcome {
                        AxisOutcome::Answered(res) => {
                            if let Some(ts) = cluster_max_ts {
                                advanceable[p].push(ts);
                                analyzed[p].push((ts, cluster_sessions.len() as i64));
                            }
                            let res = *res;
                            let axis = experts[run.member_idx[p]].expert.axis.clone();

                            // Store session labels immediately
                            if !res.session_labels.is_empty()
                                && let Ok(mut tdb) =
                                    TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await
                            {
                                let stored = super::suggestion::store_session_labels(
                                    tdb.conn(),
                                    tenant_id,
                                    &res.session_labels,
                                )
                                .await;
                                tracing::info!(axis = %axis, stored, "applied session labels");
                            }

                            // Write single-session outlier alerts immediately.
                            for (sid, level, note) in &res.alerts {
                                write_session_alert(pool, tenant_id, sid, &axis, level, note)
                                    .await;
                            }

                            // Persist cross-session issues as first-class relations
                            // linking the sessions they span — instead of pinning a
                            // multi-session finding onto one arbitrary session's alert.
                            if !res.cross_session_issues.is_empty() {
                                store_cross_session_relations(
                                    pool,
                                    tenant_id,
                                    Some(*key_id),
                                    run.profile_id,
                                    &axis,
                                    &res.cross_session_issues,
                                )
                                .await;
                            }

                            let acc = &mut run.acc[p];
                            acc.total_findings += res.findings.len();
                            acc.total_programs += res.programs.len();
                            acc.total_alerts += res.alerts.len() + res.cross_session_issues.len();
                            if !res.programs.is_empty() || !res.tool_rules.is_empty() {
                                for s in cluster_sessions {
                                    let sid = s.session_id.to_string();
                                    if !acc.session_ids.contains(&sid) {
                                        acc.session_ids.push(sid);
                                    }
                                }
                            }
                            acc.programs.extend(res.programs);
                            acc.tool_rules.extend(res.tool_rules);
                            acc.findings.extend(res.findings);
                            if !res.memory_update.is_empty() {
                                acc.last_memory_update = res.memory_update;
                            }
                        }
                        AxisOutcome::Missing => {
                            hold(&mut min_hold, p, cluster_min_ts);
                        }
                    }
                }
            }
            // A deterministic failure (e.g. an unprocessable payload) recurs
            // every cycle — skip the cluster with a loud warning and advance
            // past it. Anything else is transient: hold every applicable
            // member at the cluster so it retries whole next cycle.
            Err(e) if is_deterministic_failure(&e) => {
                tracing::warn!(
                    key_id = %key_id,
                    app_id,
                    sessions = cluster_sessions.len(),
                    "cluster analysis skipped (deterministic failure), advancing past it: {e}"
                );
                run.deterministic_skips += cluster_sessions.len();
                run.deterministic_sample.get_or_insert_with(|| e.to_string());
                for &p in &applicable {
                    if let Some(ts) = cluster_max_ts {
                        advanceable[p].push(ts);
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    key_id = %key_id,
                    app_id,
                    sessions = cluster_sessions.len(),
                    "cluster analysis failed (transient), will retry next cycle: {e}"
                );
                for &p in &applicable {
                    hold(&mut min_hold, p, cluster_min_ts);
                }
            }
        }
    }

    // Advance each member to its contiguous frontier: the whole window when
    // nothing held, else the max advanceable cluster strictly below its
    // earliest held cluster. Held members block the finalize effective-now
    // jump (run.held) so their pending clusters aren't skipped.
    let mut cursor_moved = false;
    for p in 0..n_members {
        let target = match min_hold[p] {
            None => batch_max_ts,
            Some(mh) => {
                run.held[p] = true;
                advanceable[p].iter().copied().filter(|ts| *ts < mh).max()
            }
        };
        if let Some(target) = target
            && run.cursors[p].is_none_or(|c| target > c)
        {
            run.cursors[p] = Some(target);
            cursor_moved = true;
            let covered: i64 = analyzed[p]
                .iter()
                .filter(|(ts, _)| *ts <= target)
                .map(|(_, n)| n)
                .sum();
            update_expert_profile_watermark(
                pool,
                tenant_id,
                run.profile_id,
                experts[run.member_idx[p]].id,
                covered,
                target,
            )
            .await;
        }
    }

    // A short batch means the scan reached the end of the backlog — safe to
    // jump un-held members to effective-now at finalize.
    if batch_size < crate::settings::admin_settings().agent_session_batch_limit {
        run.drained = true;
    }
    if run.drained || !cursor_moved {
        run.done = true;
    }

    Ok(())
}

/// End-of-cycle bookkeeping for one group: per-member watermark jump to
/// effective-now (skipped for held members — that would jump past their
/// pending sessions), suggestion stores (once per cycle, insert-or-bump), and
/// memory merges.
async fn finalize_group_run(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    cooldown: i64,
    experts: &[ExpertWithProgress],
    run: &GroupRun,
) {
    let effective_now = if cooldown > 0 {
        chrono::Utc::now() - chrono::Duration::minutes(cooldown)
    } else {
        chrono::Utc::now()
    };

    for (p, &ei) in run.member_idx.iter().enumerate() {
        let ewp = &experts[ei];
        let acc = &run.acc[p];

        // Advance to effective_now so alert writes (which bump
        // sessions.updated_at) don't cause re-analysis next cycle. Gated on
        // BOTH: the member wasn't held, AND the group actually drained its
        // backlog — a group retired early (transient hold, no-progress guard)
        // never scanned past its window, so jumping an un-held member here
        // would silently skip every later session forever.
        if run.drained && !run.held[p] && run.cursors[p].is_none_or(|c| effective_now > c) {
            update_expert_profile_watermark(
                pool, tenant_id, run.profile_id, ewp.id, 0, effective_now,
            )
            .await;
        }

        tracing::info!(
            axis = %ewp.expert.axis,
            profile = %run.profile_name,
            findings = acc.total_findings,
            programs = acc.total_programs,
            alerts = acc.total_alerts,
            sessions = run.total_sessions,
            held = run.held[p],
            "expert cycle complete"
        );

        // Update expert memory with the last non-empty memory_update
        if !acc.last_memory_update.is_empty() && !ewp.id.is_nil() {
            let merged = merge_memory(&ewp.memory, &acc.last_memory_update);
            update_expert_memory(pool, tenant_id, ewp.id, &merged).await;
        }

        // Store program suggestions (attributed to all sessions that produced them)
        if !acc.programs.is_empty() {
            match TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await {
                Ok(mut tdb) => match super::suggestion::store_suggestions(
                    tdb.conn(),
                    tenant_id,
                    &ewp.expert.axis,
                    &acc.findings,
                    &acc.programs,
                    &acc.session_ids,
                )
                .await
                {
                    Ok(stored) => tracing::info!(
                        axis = %ewp.expert.axis,
                        processed = stored,
                        "processed program suggestions (insert-or-bump)"
                    ),
                    Err(e) => tracing::error!(
                        axis = %ewp.expert.axis,
                        "failed to store program suggestions: {e}"
                    ),
                },
                Err(e) => tracing::error!(
                    axis = %ewp.expert.axis,
                    "failed to acquire tenant db for program suggestions: {e}"
                ),
            }
        }

        if !acc.tool_rules.is_empty() {
            match TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await {
                Ok(mut tdb) => match super::suggestion::store_tool_rule_suggestions(
                    tdb.conn(),
                    tenant_id,
                    &ewp.expert.axis,
                    &acc.tool_rules,
                    &acc.findings,
                    &acc.session_ids,
                )
                .await
                {
                    Ok(stored) => tracing::info!(
                        axis = %ewp.expert.axis,
                        processed = stored,
                        "processed tool rule suggestions (insert-or-bump)"
                    ),
                    Err(e) => tracing::error!(
                        axis = %ewp.expert.axis,
                        "failed to store tool rule suggestions: {e}"
                    ),
                },
                Err(e) => tracing::error!(
                    axis = %ewp.expert.axis,
                    "failed to acquire tenant db for tool rule suggestions: {e}"
                ),
            }
        }
    }
}

/// Session metadata from the sessions list API.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct SessionMeta {
    session_id: uuid::Uuid,
    #[serde(default)]
    user_id: Option<uuid::Uuid>,
    #[serde(default)]
    key_id: Option<uuid::Uuid>,
    turn_count: i64,
    total_tokens: Option<i64>,
    /// The session's spend in the currency it was booked in; `None` when no
    /// single figure states it.
    spend: Option<crate::routes::SpendTotal>,
    first_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    last_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    last_latency_ms: Option<i64>,
    model_requested: Option<String>,
    model_used: Option<String>,
    user_email: Option<String>,
    #[serde(default)]
    app_id: Option<String>,
    #[serde(default)]
    first_user_prompt: Option<String>,
}

/// Run a single analysis cycle for a specific tenant.
///
/// Experts are pooled into merged-call groups (`group_experts`) and the groups
/// are scheduled ROUND-ROBIN — each live group processes one batch per turn —
/// so a large backlog on one axis can no longer starve the others. Each expert
/// keeps its own `last_processed_at` watermark; a pooled call advances every
/// member it answered and holds the ones it omitted (partial accept).
pub async fn run_analysis_cycle(
    state: &Arc<AdminState>,
    client: &reqwest::Client,
    config: &AgentConfig,
    tenant_id: uuid::Uuid,
) -> anyhow::Result<()> {
    let pool = &state.db;
    let cooldown = config.session_cooldown_mins;

    // Fetch existing active programs for context.
    let active_programs = fetch_active_programs(pool, tenant_id).await?;

    // Resolve judge-model routing: profile model → alias (for proxy) + context
    // budget. The agent runs as a normal Agent-workspace key, so the alias must
    // resolve to a route the Agent workspace is granted (else the proxy 403s —
    // `resolve_agent_routing` warns when it isn't).
    // Load experts (+ the snippet map for merged-prompt assembly).
    let (experts, snippet_map) = load_experts_with_progress(pool, tenant_id).await?;

    if experts.is_empty() {
        tracing::debug!("no enabled experts");
        return Ok(());
    }

    // ---- Expert-profile partition ----
    // The `kind='expert'` profiles partition the tenant: each workspace
    // follows its assigned profile (no row = inherit the Default, NULL
    // profile_id = explicit Off), orphan/keyless sessions follow the Default,
    // and each profile carries its own judge model (NULL = inherit the
    // Default's). Every (expert, profile) pair holds its own watermark.
    let profiles = load_expert_profile_partition(pool, tenant_id, &experts).await?;
    let Some(default_profile) = profiles.iter().find(|p| p.is_default) else {
        tracing::warn!("no default expert profile — skipping analysis cycle");
        return Ok(());
    };
    let default_model = default_profile
        .model
        .clone()
        .unwrap_or_else(|| super::DEFAULT_AGENT_MODEL.to_string());

    // Resolve routing once per distinct model string (profile models + the
    // per-expert overrides all funnel through here).
    let mut routing_cache: std::collections::HashMap<String, AgentRouting> =
        std::collections::HashMap::new();

    // Tool-inventory legs: one tenant-wide call per declaring expert (the tool
    // catalog has no workspace dimension), on the expert's override model else
    // the Default profile's, before the session/cluster round-robin.
    for ewp in &experts {
        if !ewp.input_types.iter().any(|t| t == "tool_inventory") {
            continue;
        }
        let model = ewp.model_override.clone().unwrap_or_else(|| default_model.clone());
        if !routing_cache.contains_key(&model) {
            let r = resolve_agent_routing(pool, tenant_id, &model).await;
            routing_cache.insert(model.clone(), r);
        }
        let routing = &routing_cache[&model];
        if let Err(e) = run_tool_inventory_expert_cycle(
            state, client, config, routing, ewp, &active_programs, cooldown, tenant_id,
        )
        .await
        {
            tracing::error!(axis = %ewp.expert.axis, "tool inventory expert cycle failed: {e}");
        }
    }

    // Build grouping inputs: one entry per (profile, effective member, path).
    // An expert reachable through no profile (or a profile with no workspace)
    // simply forms no group — its (expert, profile) watermark seeds lazily
    // when the pair first becomes live, from "now" (no historical rescan).
    let mut inputs: Vec<GroupingInput> = Vec::new();
    for (pidx, profile) in profiles.iter().enumerate() {
        if !profile.active {
            continue;
        }
        for &ei in &profile.member_idx {
            let ewp = &experts[ei];
            let has_session = ewp.input_types.iter().any(|t| t == "session");
            let has_cluster = ewp.input_types.iter().any(|t| t == "session_cluster");
            if !has_session && !has_cluster {
                continue;
            }
            let model = ewp
                .model_override
                .clone()
                .unwrap_or_else(|| profile.model.clone().unwrap_or_else(|| default_model.clone()));
            if !routing_cache.contains_key(&model) {
                let r = resolve_agent_routing(pool, tenant_id, &model).await;
                routing_cache.insert(model.clone(), r);
            }
            let alias = routing_cache[&model].alias.clone();
            if has_session {
                inputs.push(GroupingInput {
                    expert_idx: ei,
                    path: GroupPath::Session,
                    routing_alias: alias.clone(),
                    profile_idx: pidx,
                    merge_enabled: ewp.merge_enabled,
                });
            }
            if has_cluster {
                inputs.push(GroupingInput {
                    expert_idx: ei,
                    path: GroupPath::Cluster,
                    routing_alias: alias,
                    profile_idx: pidx,
                    merge_enabled: ewp.merge_enabled,
                });
            }
        }
    }

    // Watermark map for every live (profile, expert) pair; a missing row seeds
    // at effective-now — a newly-created/assigned profile starts analyzing
    // from now instead of re-scanning history its workspaces already had
    // analyzed under their previous profile.
    let mut cursors_map = load_profile_watermarks(pool, tenant_id).await?;
    let effective_now = if cooldown > 0 {
        chrono::Utc::now() - chrono::Duration::minutes(cooldown)
    } else {
        chrono::Utc::now()
    };
    for input in &inputs {
        let key = (profiles[input.profile_idx].id, experts[input.expert_idx].id);
        if let std::collections::hash_map::Entry::Vacant(entry) = cursors_map.entry(key) {
            entry.insert(Some(effective_now));
            seed_profile_watermark(pool, tenant_id, key.0, key.1, effective_now).await;
        }
    }

    // Build the group run states.
    let mut runs: Vec<GroupRun> = Vec::new();
    for (path, pidx, member_idx) in group_experts(&inputs) {
        let first = member_idx[0];
        let profile = &profiles[pidx];
        let system_prompt = if member_idx.len() > 1 {
            let members: Vec<&Expert> =
                member_idx.iter().map(|&i| &experts[i].expert).collect();
            Some(super::experts::assemble_group_prompt(&members, &snippet_map))
        } else {
            None
        };
        let mut rejected = Vec::with_capacity(member_idx.len());
        for &i in &member_idx {
            rejected
                .push(fetch_rejected_suggestions(pool, tenant_id, &experts[i].expert.axis).await);
        }
        let cursors = member_idx
            .iter()
            .map(|&i| cursors_map.get(&(profile.id, experts[i].id)).copied().flatten())
            .collect();
        let first_model = experts[first]
            .model_override
            .clone()
            .unwrap_or_else(|| profile.model.clone().unwrap_or_else(|| default_model.clone()));
        let n = member_idx.len();
        runs.push(GroupRun {
            path,
            routing: routing_cache[&first_model].clone(),
            profile_id: profile.id,
            profile_name: profile.name.clone(),
            ws_filter: profile.ws_filter.clone(),
            include_keyless: profile.include_keyless,
            system_prompt,
            rejected,
            cursors,
            held: vec![false; n],
            acc: (0..n).map(|_| MemberAcc::default()).collect(),
            total_sessions: 0,
            done: false,
            drained: false,
            deterministic_skips: 0,
            deterministic_sample: None,
            member_idx,
        });
    }

    if runs.is_empty() {
        return Ok(());
    }

    tracing::info!(
        groups = runs.len(),
        experts = experts.len(),
        "starting round-robin analysis over expert groups"
    );

    // Round-robin: one batch per live group per turn, until every group is
    // exhausted or held. A turn error retires the group for this cycle (its
    // members' watermarks hold wherever they stopped).
    loop {
        let mut any_live = false;
        for run in &mut runs {
            if run.done {
                continue;
            }
            any_live = true;
            let turn = match run.path {
                GroupPath::Session => {
                    run_session_group_turn(
                        pool, tenant_id, client, config, cooldown, &experts, run, &active_programs,
                    )
                    .await
                }
                GroupPath::Cluster => {
                    run_cluster_group_turn(
                        pool, tenant_id, client, config, cooldown, &experts, run, &active_programs,
                    )
                    .await
                }
            };
            if let Err(e) = turn {
                let axes: Vec<&str> = run
                    .member_idx
                    .iter()
                    .map(|&i| experts[i].expert.axis.as_str())
                    .collect();
                tracing::error!(axes = ?axes, "group turn failed: {e}");
                run.held.fill(true);
                run.done = true;
            }
        }
        if !any_live {
            break;
        }
    }

    // Per-group end-of-cycle bookkeeping: watermark jumps, suggestion stores,
    // memory merges.
    for run in &runs {
        finalize_group_run(pool, tenant_id, cooldown, &experts, run).await;
    }

    // A handful of deterministic skips is a poison payload; a pile in one
    // cycle is systematic (model/config/schema rejection) — the warn-level
    // skips silently eat the analysis backlog, so tell the operator. Deduped
    // per day; best-effort.
    let skipped: usize = runs.iter().map(|r| r.deterministic_skips).sum();
    if skipped >= AGENT_SKIP_NOTIFY_THRESHOLD
        && let Ok(mut db) = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await
    {
        let sample = runs
            .iter()
            .find_map(|r| r.deterministic_sample.clone())
            .unwrap_or_default();
        let _ = crate::notifications::notify(
            db.conn(),
            tenant_id,
            crate::notifications::NewNotification {
                workspace_id: None,
                kind: crate::notifications::NotificationKind::AgentAnalysisFailing,
                dedup_key: format!(
                    "agent_analysis_failing:{}",
                    chrono::Utc::now().format("%Y-%m-%d")
                ),
                title: "Expert analysis is failing systematically".to_string(),
                summary: format!(
                    "{skipped} session(s) were skipped this cycle on repeated upstream \
                     rejections. Sample: {sample}"
                ),
                target_kind: Some("agent_experts"),
                target_id: None,
                payload: serde_json::json!({ "skipped": skipped, "sample": sample }),
            },
        )
        .await;
    }

    Ok(())
}

/// Deterministic skips in one cycle at or past this count notify the operator
/// (below it they stay warn-level logs — poison payloads happen).
const AGENT_SKIP_NOTIFY_THRESHOLD: usize = 5;



/// Run analysis for a tool_inventory expert.
/// Fetches tool inventory via direct DB query and analyzes it in a single LLM call.
#[allow(clippy::too_many_arguments)]
async fn run_tool_inventory_expert_cycle(
    state: &Arc<AdminState>,
    client: &reqwest::Client,
    config: &AgentConfig,
    routing: &AgentRouting,
    ewp: &ExpertWithProgress,
    active_programs: &[String],
    _cooldown_mins: i64,
    tenant_id: uuid::Uuid,
) -> anyhow::Result<()> {
    let pool = &state.db;
    let expert = &ewp.expert;
    let rejected = fetch_rejected_suggestions(pool, tenant_id, &expert.axis).await;

    // Fetch tool inventory via direct DB query — fixed 30-day rolling window.
    let inventory = {
        let mut db = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;
        let end_ts = chrono::Utc::now();
        let start_ts = end_ts - chrono::Duration::days(30);
        crate::audit_store::analytics::tools::tool_inventory_impl(
            db.conn(),
            tenant_id,
            (start_ts, end_ts),
            None,
            None,
            None,
            None,
            None,
        )
        .await?
    };
    let inventory: serde_json::Value = serde_json::to_value(&inventory)?;

    // Count unique tools — skip if empty (fresh DB) or unchanged since last cycle.
    let tool_count = inventory
        .get("tools")
        .and_then(|t| t.as_array())
        .map_or(0, |t| t.len());

    if tool_count == 0 {
        tracing::debug!(axis = %expert.axis, "tool inventory empty — skipping cycle");
        return Ok(());
    }

    // Track previous tool count via expert memory to detect changes.
    // Avoids conflicting with sessions_analyzed which is used by the session dispatch path.
    let prev_count: usize = ewp
        .memory
        .lines()
        .find_map(|l| l.strip_prefix("tool_count:").and_then(|v| v.trim().parse().ok()))
        .unwrap_or(0);

    if tool_count == prev_count {
        tracing::debug!(axis = %expert.axis, tool_count, "tool inventory unchanged — skipping cycle");
        return Ok(());
    }

    tracing::info!(axis = %expert.axis, tool_count, prev_count, "tool inventory changed — running analysis");

    // Render tool inventory as context
    let mut context = String::from("Analyze this tool inventory:\n\n");

    if let Some(tools) = inventory.get("tools").and_then(|t| t.as_array()) {
        context.push_str(&format!("## Tool Summary ({} unique tools)\n\n", tools.len()));
        for tool in tools.iter().take(100) {
            let name = tool.get("tool_name").and_then(|n| n.as_str()).unwrap_or("?");
            let calls = tool.get("call_count").and_then(|c| c.as_i64()).unwrap_or(0);
            let risk = tool.get("risk_level").and_then(|r| r.as_str()).unwrap_or("unknown");
            context.push_str(&format!("- **{}**: {} calls, risk={}\n", name, calls, risk));
        }
    }

    // Existing risk rules — pulled fresh from system_settings. The agent
    // doesn't need per-rule activity counts here — it needs the rule shape
    // so it doesn't propose duplicates.
    let existing_rules = {
        let mut db = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;
        crate::routes::analytics::load_risk_rules(db.conn()).await
    };
    if !existing_rules.is_empty() {
        context.push_str("\n## Existing Rules\n\n");
        for rule in &existing_rules {
            if !rule.enabled {
                continue;
            }
            let title = rule.title.as_deref().unwrap_or("(untitled)");
            let pattern = rule
                .conditions
                .iter()
                .map(|c| format!("{}={}", c.target, c.value))
                .collect::<Vec<_>>()
                .join(" AND ");
            context.push_str(&format!(
                "- {} [{}]: scope={:?}, match=`{}`\n",
                title, rule.risk, rule.scope, pattern
            ));
        }
    }

    // Field-profile coverage — only injected when this expert can propose
    // field profiles. Lists which (tool, field) pairs are already canonicalised
    // and, crucially, the high-occurrence UNCOVERED ones the agent should
    // propose profiles for (so `arg.<field>` rules can target them).
    let has_field_profile_output = ewp
        .output_types
        .iter()
        .any(|t| t == "field_profile_suggestion");
    if has_field_profile_output {
        let coverage = {
            let mut db = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;
            crate::routes::tool_field_profiles::aggregate_field_coverage(
                db.conn(),
                tenant_id,
                1000,
            )
            .await
            .unwrap_or_default()
        };
        let uncovered: Vec<_> = coverage.iter().filter(|f| !f.already_covered).collect();
        let covered_count = coverage.len() - uncovered.len();
        if !coverage.is_empty() {
            context.push_str("\n## Field-Profile Coverage\n\n");
            context.push_str(&format!(
                "{} of {} observed (tool, field) pairs are already canonicalised by a field profile.\n",
                covered_count,
                coverage.len()
            ));
            if uncovered.is_empty() {
                context.push_str("All observed tool fields are covered — no field-profile proposals needed.\n");
            } else {
                context.push_str(
                    "\nUNCOVERED (tool, field) pairs (propose `field_profile_suggestion`s for the high-occurrence ones so policy rules can target them by canonical `arg.<field>`):\n",
                );
                for f in uncovered.iter().take(30) {
                    let hint = f
                        .suggested_tool_id
                        .as_deref()
                        .map(|t| format!(", registry suggests tool_id=`{t}`"))
                        .unwrap_or_default();
                    context.push_str(&format!(
                        "- tool=`{}` field=`{}` ({} occurrences{})\n",
                        f.tool_name, f.field, f.occurrences, hint
                    ));
                }
            }
        }
    }

    // Calculate budget
    let programs_text = active_programs.join("\n");
    let rejected_text: String = rejected.iter().map(|t| format!("- {t}\n")).collect();

    if !active_programs.is_empty() {
        context.push_str("\n## Currently Active Transform Programs\n\n");
        let capped = if programs_text.len() > PROGRAMS_BUDGET {
            format!("{}...[truncated]", safe_truncate(&programs_text, PROGRAMS_BUDGET))
        } else {
            programs_text
        };
        context.push_str(&capped);
        context.push('\n');
    }

    if !rejected.is_empty() {
        context.push_str("\n## Previously Rejected Suggestions (avoid re-proposing)\n\n");
        let capped = if rejected_text.len() > REJECTED_BUDGET {
            format!("{}...[truncated]", safe_truncate(&rejected_text, REJECTED_BUDGET))
        } else {
            rejected_text
        };
        context.push_str(&capped);
    }

    // Include expert memory if memory is an input type
    let has_memory_input = ewp.input_types.iter().any(|t| t == "memory");
    if has_memory_input && !ewp.memory.is_empty() {
        context.push_str("\n## Your Memory\n\n");
        let capped = if ewp.memory.len() > MEMORY_BUDGET {
            format!("{}...[truncated]", safe_truncate(&ewp.memory, MEMORY_BUDGET))
        } else {
            ewp.memory.clone()
        };
        context.push_str(&capped);
        context.push_str("\n\n");
    }

    inject_security_frameworks(&mut context, &ewp.input_types);

    tracing::debug!(
        axis = %expert.axis,
        context_len = context.len(),
        "analyzing tool inventory"
    );

    let body = serde_json::json!({
        "model": routing.alias,
        "messages": [
            {"role": "system", "content": expert.prompt},
            {"role": "user", "content": context}
        ],
        "max_tokens": routing.max_tokens(1),
        "tools": [analysis_tool_definition(&ewp.output_types, false)],
        "tool_choice": super::AGENT_TOOL_CHOICE
    });

    let response = agent_analysis_call(client, config, body, routing.call_timeout()).await?;
    let parsed = parse_analysis_response(&response, &expert.axis)?;

    // Parse tool rules — agent emits the unified Rule shape directly so we
    // delegate to ProposedToolRule's Deserialize impl. Malformed entries are
    // dropped with a warn log rather than failing the whole batch.
    let tool_rules: Vec<super::suggestion::ProposedToolRule> = parsed
        .get("proposed_tool_rules")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    serde_json::from_value::<super::suggestion::ProposedToolRule>(r.clone())
                        .map_err(|e| {
                            tracing::warn!(error = %e, raw = %r, "skipping malformed proposed_tool_rule");
                        })
                        .ok()
                })
                .collect()
        })
        .unwrap_or_default();

    if !tool_rules.is_empty() {
        let findings: Vec<super::suggestion::Finding> = parsed
            .get("findings")
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| {
                        Some(super::suggestion::Finding {
                            severity: f.get("severity")?.as_str()?.to_string(),
                            category: f.get("category")?.as_str()?.to_string(),
                            description: f.get("description")?.as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut tdb = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;
        let stored = super::suggestion::store_tool_rule_suggestions(
            tdb.conn(),
            tenant_id,
            &expert.axis,
            &tool_rules,
            &findings,
            &[],  // no specific sessions for inventory analysis
        )
        .await?;
        tracing::info!(axis = %expert.axis, processed = stored, "processed tool rule suggestions from inventory (insert-or-bump)");
    }

    // Parse programs (if expert also has transform_suggestion output)
    let programs: Vec<super::suggestion::ProposedProgram> = parsed
        .get("proposed_programs")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    Some(super::suggestion::ProposedProgram {
                        name: p.get("name")?.as_str()?.to_string(),
                        description: p.get("description")?.as_str()?.to_string(),
                        source: p.get("source")?.as_str()?.to_string(),
                        phase: p.get("phase")?.as_str().unwrap_or("request").to_string(),
                        scope: p.get("scope")?.as_str().unwrap_or("global").to_string(),
                        rationale: p.get("rationale")?.as_str()?.to_string(),
                        model_filter: p.get("model_filter").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        app_filter: p.get("app_filter").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        trigger_regex: p.get("trigger_regex").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        match_mode: p.get("match_mode").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    if !programs.is_empty() {
        let findings: Vec<super::suggestion::Finding> = parsed
            .get("findings")
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| {
                        Some(super::suggestion::Finding {
                            severity: f.get("severity")?.as_str()?.to_string(),
                            category: f.get("category")?.as_str()?.to_string(),
                            description: f.get("description")?.as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut tdb = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;
        let stored = super::suggestion::store_suggestions(
            tdb.conn(),
            tenant_id,
            &expert.axis,
            &findings,
            &programs,
            &[],
        )
        .await?;
        tracing::info!(axis = %expert.axis, processed = stored, "processed program suggestions from inventory (insert-or-bump)");
    }

    // Parse field profiles (if expert has field_profile_suggestion output) —
    // agent emits the FieldProfile shape directly; malformed entries are
    // dropped with a warn rather than failing the batch.
    let field_profiles: Vec<super::suggestion::ProposedFieldProfile> = parsed
        .get("proposed_field_profiles")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    serde_json::from_value::<super::suggestion::ProposedFieldProfile>(p.clone())
                        .map_err(|e| {
                            tracing::warn!(error = %e, raw = %p, "skipping malformed proposed_field_profile");
                        })
                        .ok()
                })
                .collect()
        })
        .unwrap_or_default();

    if !field_profiles.is_empty() {
        let findings: Vec<super::suggestion::Finding> = parsed
            .get("findings")
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| {
                        Some(super::suggestion::Finding {
                            severity: f.get("severity")?.as_str()?.to_string(),
                            category: f.get("category")?.as_str()?.to_string(),
                            description: f.get("description")?.as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut tdb = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;
        let stored = super::suggestion::store_field_profile_suggestions(
            tdb.conn(),
            tenant_id,
            &expert.axis,
            &field_profiles,
            &findings,
            &[],
        )
        .await?;
        tracing::info!(axis = %expert.axis, processed = stored, "processed field-profile suggestions from inventory (insert-or-bump)");
    }

    // Handle alert
    let has_alert = ewp.output_types.iter().any(|t| t == "alert");
    if has_alert {
        let alert_level = parsed.get("alert_level").and_then(|l| l.as_str()).unwrap_or("");
        let alert_note = parsed.get("alert_note").and_then(|n| n.as_str()).unwrap_or("");
        if alert_level == "info" || alert_level == "minor" || alert_level == "major" {
            tracing::info!(axis = %expert.axis, level = %alert_level, note = %alert_note, "tool inventory alert (no session target)");
        }
    }

    // Handle memory
    let has_memory = ewp.output_types.iter().any(|t| t == "memory");
    if has_memory {
        let memory_update = parsed.get("memory_update").and_then(|m| m.as_str()).unwrap_or("");
        if !memory_update.is_empty() && !ewp.id.is_nil() {
            let merged = merge_memory(&ewp.memory, memory_update);
            update_expert_memory(pool, tenant_id, ewp.id, &merged).await;
        }
    }

    // Store tool count in memory for change detection on next cycle.
    // Prepend to existing memory (merge_memory will handle truncation).
    let tool_count_line = format!("tool_count:{tool_count}");
    let updated_memory = if ewp.memory.lines().any(|l| l.starts_with("tool_count:")) {
        ewp.memory
            .lines()
            .map(|l| {
                if l.starts_with("tool_count:") {
                    tool_count_line.as_str()
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        format!("{tool_count_line}\n{}", ewp.memory)
    };
    update_expert_memory(pool, tenant_id, ewp.id, &updated_memory).await;

    // Bump the display counter only — the session-path cursors are per
    // (expert, profile) and must not be touched by the inventory leg.
    bump_expert_sessions_analyzed(pool, tenant_id, ewp.id, 1).await;

    tracing::info!(axis = %expert.axis, tool_count, "tool inventory analysis complete");

    Ok(())
}

/// Result of analyzing a session cluster.
struct ClusterAnalysisResult {
    session_labels: Vec<super::suggestion::SessionLabel>,
    programs: Vec<ProposedProgram>,
    tool_rules: Vec<super::suggestion::ProposedToolRule>,
    findings: Vec<Finding>,
    alerts: Vec<(String, String, String)>, // single-session outlier: (session_id, level, note)
    cross_session_issues: Vec<(String, String, Vec<uuid::Uuid>)>, // (level, note, source_session_ids)
    memory_update: String,
}

/// Analyze a cluster of sessions grouped by (key_id, app_id) with one solo
/// (single-axis) LLM call.
/// Same key can be used across multiple clients, so app_id distinguishes them.
#[allow(clippy::too_many_arguments)]
async fn analyze_session_cluster(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    client: &reqwest::Client,
    config: &AgentConfig,
    routing: &AgentRouting,
    ewp: &ExpertWithProgress,
    sessions: &[&SessionMeta],
    active_programs: &[String],
    rejected_suggestions: &[String],
    key_id: &uuid::Uuid,
    app_id: &str,
) -> anyhow::Result<ClusterAnalysisResult> {
    let expert = &ewp.expert;

    // Calculate budget
    let has_memory_input = ewp.input_types.iter().any(|t| t == "memory");
    let memory_chars = if has_memory_input { ewp.memory.len().min(MEMORY_BUDGET) } else { 0 };
    let programs_text = active_programs.join("\n");
    let programs_chars = programs_text.len().min(PROGRAMS_BUDGET);
    let rejected_text: String = rejected_suggestions
        .iter()
        .map(|t| format!("- {t}\n"))
        .collect();
    let rejected_chars = rejected_text.len().min(REJECTED_BUDGET);
    let fixed_cost = FIXED_OVERHEAD + memory_chars + programs_chars + rejected_chars;
    let cluster_budget = routing.context_budget.saturating_sub(fixed_cost);

    let (cluster_text, cidx) =
        render_cluster(pool, tenant_id, sessions, cluster_budget, key_id, app_id).await?;

    // Build user message
    let mut context = format!("Analyze this session cluster:\n\n{cluster_text}");

    if has_memory_input && !ewp.memory.is_empty() {
        context.push_str("\n## Your Memory\n\n");
        let capped = if ewp.memory.len() > MEMORY_BUDGET {
            format!(
                "{}...[truncated]",
                safe_truncate(&ewp.memory, MEMORY_BUDGET)
            )
        } else {
            ewp.memory.clone()
        };
        context.push_str(&capped);
        context.push_str("\n\n");
    }

    if !rejected_suggestions.is_empty() {
        context.push_str("## Previously Rejected Suggestions\n\n");
        context.push_str(
            "The following proposals were rejected by the admin. Do NOT re-propose them:\n",
        );
        let capped = if rejected_text.len() > REJECTED_BUDGET {
            format!(
                "{}...[truncated]",
                safe_truncate(&rejected_text, REJECTED_BUDGET)
            )
        } else {
            rejected_text
        };
        context.push_str(&capped);
        context.push('\n');
    }

    inject_security_frameworks(&mut context, &ewp.input_types);

    tracing::debug!(
        axis = %expert.axis,
        key_id = %key_id,
        app_id,
        sessions = sessions.len(),
        context_len = context.len(),
        "analyzing session cluster"
    );

    // Call the proxy. Cluster alerts ride the session-targeted
    // `session_alerts[]` channel — a cluster-wide scalar has nowhere to land.
    let body = serde_json::json!({
        "model": routing.alias,
        "messages": [
            {"role": "system", "content": expert.prompt},
            {"role": "user", "content": context}
        ],
        "max_tokens": routing.max_tokens(1),
        "tools": [analysis_tool_definition(&ewp.output_types, true)],
        "tool_choice": super::AGENT_TOOL_CHOICE
    });

    let response = agent_analysis_call(client, config, body, routing.call_timeout()).await?;
    let parsed = parse_analysis_response(&response, &expert.axis)?;

    let fields = parse_axis_fields(&parsed, &ewp.output_types, &cidx.s_index, &cidx.spawn_points);

    // Alert / issue targets are named by S-index and resolved against `s_index`
    // (the cluster's ordered id map) — an out-of-range index is dropped, so a
    // hallucinated ref can't reach a session the expert never analyzed.
    let (alerts, cross_session_issues) = if ewp.output_types.iter().any(|t| t == "alert") {
        (
            extract_session_alerts(&parsed, &expert.axis, &cidx.s_index),
            extract_cross_session_issues(&parsed, &expert.axis, &cidx.s_index),
        )
    } else {
        (Vec::new(), Vec::new())
    };

    tracing::info!(
        axis = %expert.axis,
        key_id = %key_id,
        app_id,
        labels = fields.session_labels.len(),
        programs = fields.programs.len(),
        tool_rules = fields.tool_rules.len(),
        has_alert = !alerts.is_empty(),
        cross_issues = cross_session_issues.len(),
        "cluster analysis complete"
    );

    Ok(ClusterAnalysisResult {
        session_labels: fields.session_labels,
        programs: fields.programs,
        tool_rules: fields.tool_rules,
        findings: fields.findings,
        alerts,
        cross_session_issues,
        memory_update: fields.memory_update,
    })
}

/// The cluster's `S{i}` → session map plus, parallel to it, the spawn points
/// detected in each session's own stream (labelled `[P{j}]` in the prompt). Built
/// once in [`render_cluster`] — the only place the printed labels and these
/// vectors stay in lockstep — and consumed by extraction to resolve the judge's
/// `session_index` / `parent_spawn_point_index` refs back to ids and anchors.
struct ClusterIndex {
    /// `s_index[i]` is the session printed as `S{i}`.
    s_index: Vec<uuid::Uuid>,
    /// `spawn_points[i]` are the spawn points printed as `[P0]…` under `S{i}`.
    spawn_points: Vec<Vec<crate::conversation::DetectedSpawnPoint>>,
}

/// Render a cluster — the timeline overview plus each session's budget-capped
/// conversation — for the cluster-path user message.
async fn render_cluster(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    sessions: &[&SessionMeta],
    cluster_budget: usize,
    key_id: &uuid::Uuid,
    app_id: &str,
) -> anyhow::Result<(String, ClusterIndex)> {
    let per_session_budget = cluster_budget / sessions.len().max(1);
    // Derive user info from the first session in the cluster
    let cluster_user = sessions.first()
        .and_then(|s| s.user_email.as_deref())
        .unwrap_or("unknown");
    let mut cluster_text = format!(
        "## Session Cluster (user: {}, app: {}, key: {}, sessions: {})\n\n",
        cluster_user,
        if app_id.is_empty() { "unknown" } else { app_id },
        key_id,
        sessions.len()
    );

    // Sort by creation time for temporal analysis. INVARIANT: this `sorted` order
    // IS the S-index the prompt prints (`S{i}`) AND the `s_index` map returned
    // below — extraction resolves the model's S-index refs against it. Anything
    // that re-sorts the printed timeline MUST rebuild `s_index` from the same
    // order, or a finding lands on the wrong session (the bug this fixes).
    let mut sorted: Vec<&&SessionMeta> = sessions.iter().collect();
    sorted.sort_by_key(|s| s.first_timestamp);
    let s_index: Vec<uuid::Uuid> = sorted.iter().map(|s| s.session_id).collect();

    // Session timeline overview
    cluster_text.push_str("### Timeline\n");
    for (i, session) in sorted.iter().enumerate() {
        let model = session.model_used.as_deref().unwrap_or("?");
        let turns = session.turn_count;
        let cost = render_spend(session.spend, 3);
        let first = session
            .first_timestamp
            .map(|t| t.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "?".to_string());
        let last = session
            .last_timestamp
            .map(|t| t.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "?".to_string());
        let topic = session
            .first_user_prompt
            .as_deref()
            .unwrap_or("")
            .chars()
            .take(100)
            .collect::<String>();
        // Sessions are identified to the model ONLY by their S-index (`S{i}`) —
        // the raw UUID is deliberately not printed, so the model can't transcribe
        // one into an output field (it references sessions by index; our code maps
        // the index back via `s_index`).
        cluster_text.push_str(&format!(
            "  S{i}: {first}–{last} | {turns} turns | {model} | {cost} | \"{topic}\"\n"
        ));
    }
    cluster_text.push('\n');

    // Fetch key conversations (budget-aware). Alongside each, capture the spawn
    // points detected deterministically in that session's stream and print them as
    // `[P{j}]` so the judge CONFIRMS a child→spawn link by index instead of
    // hunting the raw text (kept in lockstep with `s_index` by the shared order).
    cluster_text.push_str("### Session Details\n");
    let mut spawn_points: Vec<Vec<crate::conversation::DetectedSpawnPoint>> =
        Vec::with_capacity(sorted.len());
    for (i, session) in sorted.iter().enumerate() {
        let conversation =
            fetch_conversation_via_db(pool, tenant_id, session.session_id).await?;
        let rendered = render_session(session, &conversation, per_session_budget);
        cluster_text.push_str(&format!("#### S{i}\n"));
        cluster_text.push_str(&rendered);
        let points: Vec<crate::conversation::DetectedSpawnPoint> = conversation
            .get("detected_spawn_points")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        if !points.is_empty() {
            cluster_text.push_str("##### Detected spawn points\n");
            for (j, p) in points.iter().enumerate() {
                cluster_text.push_str(&format!(
                    "  [P{j}] turn {} · {} · \"{}\"\n",
                    p.turn_number, p.tool_name, p.prompt_preview
                ));
            }
        }
        spawn_points.push(points);
        cluster_text.push('\n');
    }

    Ok((cluster_text, ClusterIndex { s_index, spawn_points }))
}

/// Bound and de-degenerate an agent-supplied alert note before it is persisted
/// or rendered. A weak or misbehaving agent model can emit a degenerate
/// `alert_note` — a runaway repetition loop or JSON-schema tokens bleeding into
/// the string value (which valid-JSON arguments parsing cannot catch). The UI
/// renders this string verbatim, so the invariant is that it is always
/// length-bounded and repetition-collapsed here: a degenerate model yields a
/// readable, capped note instead of a wall of garbage.
fn sanitize_alert_note(note: &str) -> String {
    const MAX_LINE_CHARS: usize = 400;
    const MAX_LINES: usize = 24;
    const MAX_CHARS: usize = 3000;
    // Hard char ceiling applied before the repetition scan so a pathological
    // line cannot blow up its per-position unit search.
    const WORKING_LINE_CHARS: usize = 8000;

    let mut out_lines: Vec<String> = Vec::new();
    for line in note.lines() {
        if out_lines.len() >= MAX_LINES {
            break;
        }
        let working = truncate_chars(line, WORKING_LINE_CHARS);
        let collapsed = collapse_repetition(&working);
        out_lines.push(truncate_chars(&collapsed, MAX_LINE_CHARS));
    }
    truncate_chars(&out_lines.join("\n"), MAX_CHARS)
}

/// Truncate to at most `max` chars on a char boundary, appending an ellipsis
/// when anything was dropped.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max).collect();
    format!("{kept}…")
}

/// Collapse a degenerate run where a short unit repeats consecutively many
/// times — the signature of model repetition-loop degeneration
/// ("agentic-agentic-agentic…"). Keeps a few copies, then elides the rest.
/// Operates over chars so unit boundaries are always valid UTF-8.
fn collapse_repetition(line: &str) -> String {
    const MAX_UNIT: usize = 48;
    const MIN_REPEATS: usize = 4;
    const KEEP_REPEATS: usize = 3;
    // The repeated run must also span at least this many chars to collapse, so
    // short legitimate runs (a number like `1000000`, a `------` separator) are
    // left alone — a degeneration loop always spans far more.
    const MIN_RUN_CHARS: usize = 40;

    let chars: Vec<char> = line.chars().collect();
    let n = chars.len();
    if n < MIN_RUN_CHARS {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < n {
        let mut collapsed = false;
        let max_unit = MAX_UNIT.min(n - i);
        for unit in 1..=max_unit {
            let mut reps = 1;
            let mut j = i + unit;
            while j + unit <= n && chars[j..j + unit] == chars[i..i + unit] {
                reps += 1;
                j += unit;
            }
            if reps >= MIN_REPEATS && reps * unit >= MIN_RUN_CHARS {
                out.extend(chars[i..i + KEEP_REPEATS * unit].iter());
                out.push('…');
                i = j;
                collapsed = true;
                break;
            }
        }
        if !collapsed {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Result of analyzing a single session.
struct SessionAnalysisResult {
    findings: Vec<Finding>,
    programs: Vec<ProposedProgram>,
    tool_rules: Vec<super::suggestion::ProposedToolRule>,
    session_labels: Vec<super::suggestion::SessionLabel>,
    alert: Option<(String, String)>, // (level, note)
    memory_update: String,
}

/// Analyze a single session with one dedicated LLM call.
#[allow(clippy::too_many_arguments)]
async fn analyze_single_session(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    client: &reqwest::Client,
    config: &AgentConfig,
    routing: &AgentRouting,
    ewp: &ExpertWithProgress,
    session: &SessionMeta,
    active_programs: &[String],
    rejected_suggestions: &[String],
) -> anyhow::Result<SessionAnalysisResult> {
    let expert = &ewp.expert;
    let context_budget = routing.context_budget;

    // Calculate available budget for session content
    let has_memory_input = ewp.input_types.iter().any(|t| t == "memory");
    let memory_chars = if has_memory_input { ewp.memory.len().min(MEMORY_BUDGET) } else { 0 };
    let programs_text = active_programs.join("\n");
    let programs_chars = programs_text.len().min(PROGRAMS_BUDGET);
    let rejected_text: String = rejected_suggestions
        .iter()
        .map(|t| format!("- {t}\n"))
        .collect();
    let rejected_chars = rejected_text.len().min(REJECTED_BUDGET);

    let fixed_cost = FIXED_OVERHEAD + memory_chars + programs_chars + rejected_chars;
    let session_budget = context_budget.saturating_sub(fixed_cost);

    // Fetch conversation data via API
    let conversation =
        fetch_conversation_via_db(pool, tenant_id, session.session_id).await?;

    // Render session with full available budget
    let rendered = render_session(session, &conversation, session_budget);

    // Build user message
    let mut context = format!(
        "Analyze this LLM session:\n\n{rendered}"
    );

    if !active_programs.is_empty() {
        context.push_str("## Currently Active Transform Programs\n\n");
        let capped = if programs_text.len() > PROGRAMS_BUDGET {
            format!("{}...[truncated]", safe_truncate(&programs_text, PROGRAMS_BUDGET))
        } else {
            programs_text
        };
        context.push_str(&capped);
        context.push_str("\nDo NOT propose programs that duplicate existing ones.\n");
    }

    if has_memory_input && !ewp.memory.is_empty() {
        context.push_str("\n## Your Memory\n\n");
        let capped = if ewp.memory.len() > MEMORY_BUDGET {
            format!("{}...[truncated]", safe_truncate(&ewp.memory, MEMORY_BUDGET))
        } else {
            ewp.memory.clone()
        };
        context.push_str(&capped);
        context.push_str("\n\n");
    }

    if !rejected_suggestions.is_empty() {
        context.push_str("## Previously Rejected Suggestions\n\n");
        context.push_str(
            "The following proposals were rejected by the admin. Do NOT re-propose them:\n",
        );
        let capped = if rejected_text.len() > REJECTED_BUDGET {
            format!("{}...[truncated]", safe_truncate(&rejected_text, REJECTED_BUDGET))
        } else {
            rejected_text
        };
        context.push_str(&capped);
        context.push('\n');
    }

    inject_security_frameworks(&mut context, &ewp.input_types);

    tracing::debug!(
        axis = %expert.axis,
        session_id = %session.session_id,
        context_len = context.len(),
        context_budget,
        session_budget,
        "analyzing session"
    );

    // Call the proxy (self-routing).
    let body = serde_json::json!({
        "model": routing.alias,
        "messages": [
            {"role": "system", "content": expert.prompt},
            {"role": "user", "content": context}
        ],
        "max_tokens": routing.max_tokens(1),
        "tools": [analysis_tool_definition(&ewp.output_types, false)],
        "tool_choice": super::AGENT_TOOL_CHOICE
    });

    let response = agent_analysis_call(client, config, body, routing.call_timeout()).await?;

    // A response the model emits in an unparseable shape recurs every cycle for
    // this session — tag deterministic so the batch skips it rather than holding.
    let parsed: serde_json::Value =
        parse_analysis_response(&response, &expert.axis).map_err(deterministic)?;

    let mut result = parse_axis_fields(&parsed, &ewp.output_types, &[], &[]);
    result.alert = parse_and_write_session_alert(
        pool,
        tenant_id,
        &session.session_id.to_string(),
        &expert.axis,
        &parsed,
        &ewp.output_types,
    )
    .await;

    tracing::info!(
        axis = %expert.axis,
        session_id = %session.session_id,
        findings = result.findings.len(),
        programs = result.programs.len(),
        tool_rules = result.tool_rules.len(),
        labels = result.session_labels.len(),
        has_alert = result.alert.is_some(),
        has_memory_update = !result.memory_update.is_empty(),
        "session analysis complete"
    );

    Ok(result)
}

/// Resolved routing info for the agent's model.
#[derive(Clone)]
struct AgentRouting {
    /// Alias to use in proxy requests (for model_map routing).
    alias: String,
    /// Context budget in characters.
    context_budget: usize,
    /// Resolved output cap (`resolved_max_output_sql!`: the model's own, else the
    /// catalog's, held to half the model's window when it states a smaller one
    /// than the catalog) — `None` when neither declares one. Bounds the request `max_tokens` and scales the call timeout.
    max_output_tokens: Option<i32>,
    /// Tokens of the context window the input budget leaves free
    /// (`window − CONTEXT_USAGE_RATIO·window`). The request `max_tokens` must
    /// fit in it: a server that sizes prompt + `max_tokens` against the window
    /// (vLLM) refuses the whole call otherwise.
    output_room: usize,
}

impl AgentRouting {
    /// Per-call HTTP timeout. The base (`AGENT_HTTP_TIMEOUT_SECS`) covers a
    /// standard 8k-output generation; models resolved with a bigger output
    /// budget (long thinking) get proportionally longer, capped at 3× so a
    /// wedged upstream still fails within the cycle.
    fn call_timeout(&self) -> std::time::Duration {
        let base = crate::settings::admin_settings().agent_http_timeout;
        let factor = 1 + (self.max_output_tokens.unwrap_or(0).max(0) as u64 / 32_768);
        base * factor.min(3) as u32
    }

    /// The request `max_tokens` for a call answering `n_axes` axes: the
    /// per-axis ask ([`merged_max_tokens`]), bounded by the model's output cap
    /// and by the room the input budget leaves in the context window.
    fn max_tokens(&self, n_axes: usize) -> usize {
        merged_max_tokens(n_axes, self.max_output_tokens).min(self.output_room)
    }
}

/// Resolve agent model to a routable alias and context budget.
///
/// The model can be either an upstream alias or an upstream_model name.
/// Tries alias match first, then upstream_model match. The upstream's native
/// protocol is irrelevant: the gateway translates between the agent's wire
/// protocol and whatever the upstream speaks.
async fn resolve_agent_routing(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    model: &str,
) -> AgentRouting {
    // Query through downstream_routes → upstream_models → upstream_servers.
    // Tries alias match first, then upstream_model name match. The agent is now a
    // normal keyed workspace, so the route it resolves to MUST be granted to the
    // Agent workspace (`workspace_downstream_access`) or the proxy refuses it —
    // `granted_to_agent` flags an ungranted route so we can warn the operator
    // (grants are manual, via the workspace Access UI).
    #[allow(clippy::type_complexity)]
    let row: Option<(String, Option<i32>, Option<i32>, Option<String>, bool)> = if let Ok(mut db) = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await {
        let r: Option<(String, Option<i32>, Option<i32>, Option<String>, bool)> = sqlx::query_as(
            sqlx::AssertSqlSafe(&*crate::routes::with_catalog_join(
            concat!(r#"SELECT r.alias,
                      COALESCE(m.context_window, c.context_window) as context_window,
                      "#, resolved_max_output_sql!("m", "c"), r#" as max_output_tokens,
                      COALESCE(m.upstream_api_format, s.upstream_api_format) as upstream_api_format,
                      EXISTS(
                          SELECT 1 FROM (
--{live_provider_grants}
                          ) g
                          JOIN workspaces w ON w.id = g.workspace_id
                          WHERE w.role = 'agent' AND g.downstream_provider_id = r.provider_id
                      ) AS granted_to_agent
               FROM downstream_routes r
               JOIN upstream_models m ON m.id = r.model_id
               JOIN upstream_servers s ON s.id = m.server_id
--{catalog_join}
               WHERE "#, live_route_sql!(), r#"
                 AND (r.alias = $1 OR m.upstream_model = $1)
               ORDER BY CASE WHEN r.alias = $1 THEN 0 ELSE 1 END
               LIMIT 1"#),
            "m",
            "s",
        ).replace(crate::routes::LIVE_PROVIDER_GRANTS_MARKER, crate::routes::LIVE_PROVIDER_GRANTS)))
        .bind(model)
        .fetch_optional(db.conn())
        .await
        .ok()
        .flatten();
        r
    } else {
        None
    };

    let (alias, context_window) = match &row {
        Some((a, cw, _, _, _)) => (a.clone(), cw.unwrap_or(DEFAULT_CONTEXT_WINDOW)),
        None => {
            tracing::warn!(model, "no upstream found for agent model, using as-is");
            (model.to_string(), DEFAULT_CONTEXT_WINDOW)
        }
    };

    // The agent's route exists but isn't granted to the Agent workspace — the
    // proxy will 403. Tell the operator to grant the provider in the Access tab.
    if let Some((_, _, _, _, granted)) = &row
        && !*granted
    {
        tracing::warn!(
            model,
            alias = %alias,
            "agent model resolves to a route NOT granted to the Agent workspace — \
             grant its provider in the workspace Access tab, or the agent's calls will be refused"
        );
    }

    if let Some((_, _, max_output, upstream_api_format, _)) = &row {
        tracing::info!(
            model,
            alias = %alias,
            context_window,
            max_output_tokens = ?max_output,
            upstream_api_format = ?upstream_api_format,
            "resolved agent routing with auto-config"
        );
    }

    let token_budget = (context_window as f64 * CONTEXT_USAGE_RATIO) as usize;
    let context_budget = token_budget * CHARS_PER_TOKEN;

    AgentRouting {
        alias,
        context_budget,
        max_output_tokens: row.as_ref().and_then(|(_, _, mo, _, _)| *mo),
        output_room: (context_window.max(0) as usize).saturating_sub(token_budget),
    }
}

/// Load enabled experts with their progress watermarks from DB, plus the
/// tenant's prompt-snippet map (needed again when a merged group assembles its
/// pooled system prompt).
async fn load_experts_with_progress(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
) -> anyhow::Result<(Vec<ExpertWithProgress>, std::collections::HashMap<String, String>)> {
    let mut db = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        uuid::Uuid,
        String,
        Option<String>,
        String,
        String,
        Vec<String>,
        Vec<String>,
        Option<String>,
        Option<String>,
        Vec<String>,
        bool,
    )> = sqlx::query_as(
        "SELECT id, axis, description, prompt, memory, \
         COALESCE(input_types, '{session}'), COALESCE(output_types, '{transform_suggestion}'), \
         model_override, color, COALESCE(prompt_snippets, '{}'), merge_enabled \
         FROM agent_experts WHERE enabled = true AND NOT suppressed ORDER BY axis",
    )
    .fetch_all(db.conn())
    .await?;

    // Build snippet map from DB (the `prompt_snippets` table, seeded from
    // seeds/snippets/ at startup; suppressed rows excluded).
    let mut snippet_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    if let Ok(snippet_rows) = sqlx::query_as::<_, (String, String)>(
        "SELECT snippet_key, content FROM prompt_snippets WHERE NOT suppressed",
    )
    .fetch_all(db.conn())
    .await
    {
        for (key, content) in snippet_rows {
            snippet_map.insert(key, content);
        }
    }

    if rows.is_empty() {
        tracing::warn!("no experts in DB — seeds may not have been applied yet");
        return Ok((Vec::new(), snippet_map));
    }

    let experts = rows
        .into_iter()
        .map(
            |(id, axis, description, raw_prompt, memory, input_types, output_types, model_override, color, prompt_snippets, merge_enabled)| {
                // If prompt_snippets is empty, fall back to default snippet keys
                let effective_snippets = if prompt_snippets.is_empty() {
                    super::experts::default_snippet_keys(&input_types, &output_types)
                } else {
                    prompt_snippets
                };
                // Solo prompts carry a one-line lane-confinement preamble — the
                // seed bodies hold no cross-expert deference text (merged calls
                // get the panel contract instead).
                let assembled_prompt = format!(
                    "{}{}",
                    super::experts::solo_preamble(&axis),
                    super::experts::assemble_prompt(&raw_prompt, &effective_snippets, &snippet_map)
                );

                let expert = Expert {
                    axis: axis.clone(),
                    description,
                    prompt: assembled_prompt,
                    raw_prompt,
                    input_types: input_types.clone(),
                    output_types: output_types.clone(),
                    model_override: model_override.clone(),
                    color,
                    snippet_keys: effective_snippets,
                };
                ExpertWithProgress {
                    id,
                    expert,
                    memory,
                    input_types,
                    output_types,
                    model_override,
                    merge_enabled,
                }
            },
        )
        .collect();

    Ok((experts, snippet_map))
}

/// Fetch rejected suggestion entries for an expert axis, formatted as one
/// line per entry: `program: <title>` for transform programs, `tool_rule
/// <id>: <title>` for tool-rule proposals. Pulls from both suggestion
/// tables so a previously-rejected rule id can't be re-proposed.
async fn fetch_rejected_suggestions(pool: &crate::db::Db, tenant_id: uuid::Uuid, axis: &str) -> Vec<String> {
    let Ok(mut db) = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await else {
        return Vec::new();
    };
    let rows: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT kind, id, title FROM ( \
           SELECT 'program' AS kind, NULL::text AS id, title, reviewed_at \
             FROM program_suggestions \
             WHERE expert_axis = $1 AND status = 'rejected' \
           UNION ALL \
           SELECT 'tool_rule' AS kind, proposed_rule_id AS id, title, reviewed_at \
             FROM tool_rule_suggestions \
             WHERE expert_axis = $1 AND status = 'rejected' \
         ) entries \
         ORDER BY reviewed_at DESC NULLS LAST \
         LIMIT $2",
    )
    .bind(axis)
    .bind(REJECTED_SUGGESTIONS_LIMIT)
    .fetch_all(db.conn())
    .await
    .unwrap_or_default();

    rows.into_iter()
        .map(|(kind, id, title)| match (kind.as_str(), id) {
            ("tool_rule", Some(id)) => format!("tool_rule {id}: {title}"),
            _ => format!("program: {title}"),
        })
        .collect()
}

/// Advance one (expert, profile) watermark and increment its session counter.
/// The expert's legacy display columns follow: `sessions_analyzed` accumulates
/// the total across profiles, and `last_processed_at` becomes the MIN across
/// the expert's profile watermarks (the conservative "processed through").
async fn update_expert_profile_watermark(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    profile_id: uuid::Uuid,
    expert_id: uuid::Uuid,
    sessions: i64,
    watermark_at: chrono::DateTime<chrono::Utc>,
) {
    if expert_id.is_nil() {
        return;
    }
    let Ok(mut db) = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await else {
        return;
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO expert_profile_watermarks \
            (profile_id, expert_id, tenant_id, last_processed_at, sessions_analyzed) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (tenant_id, profile_id, expert_id) DO UPDATE SET \
            last_processed_at = EXCLUDED.last_processed_at, \
            sessions_analyzed = expert_profile_watermarks.sessions_analyzed + EXCLUDED.sessions_analyzed, \
            updated_at = now()",
    )
    .bind(profile_id)
    .bind(expert_id)
    .bind(tenant_id)
    .bind(watermark_at)
    .bind(sessions)
    .execute(db.conn())
    .await
    {
        tracing::error!("agent expert profile watermark update failed: {e}");
        return;
    }
    if let Err(e) = sqlx::query(
        "UPDATE agent_experts SET \
         last_processed_at = (SELECT MIN(w.last_processed_at) \
                              FROM expert_profile_watermarks w WHERE w.expert_id = $1), \
         sessions_analyzed = sessions_analyzed + $2, \
         updated_at = now() \
         WHERE id = $1",
    )
    .bind(expert_id)
    .bind(sessions)
    .execute(db.conn())
    .await
    {
        tracing::error!("agent expert watermark refresh failed: {e}");
    }
}

/// Bump the expert's display session counter without touching any watermark —
/// the tool-inventory leg's activity marker (its real dedup is the
/// `tool_count:` line in expert memory; touching `last_processed_at` here
/// would race the session-path cursors).
async fn bump_expert_sessions_analyzed(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    expert_id: uuid::Uuid,
    by: i64,
) {
    if expert_id.is_nil() {
        return;
    }
    let Ok(mut db) = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await else {
        return;
    };
    if let Err(e) = sqlx::query(
        "UPDATE agent_experts SET sessions_analyzed = sessions_analyzed + $2, updated_at = now() \
         WHERE id = $1",
    )
    .bind(expert_id)
    .bind(by)
    .execute(db.conn())
    .await
    {
        tracing::error!("agent expert session-counter bump failed: {e}");
    }
}

/// `(model alias, tool-schema fingerprint)` pairs whose upstream rejected a
/// FORCED tool choice with a deterministic 400. Some providers compile the tool
/// schema into a constrained-decoding grammar when the call is forced (Gemini
/// `functionCallingConfig.mode=ANY`) and reject schemas past an opaque state
/// budget with `INVALID_ARGUMENT` — while accepting the very same schema under
/// `auto`. Memoized per process so, after the first fallback, later calls skip
/// the doomed forced attempt.
static FORCED_CHOICE_REJECTED: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<(String, u64)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// Stable fingerprint of a call's `tools` schema for the fallback memo.
fn tools_fingerprint(tools: &serde_json::Value) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    tools.to_string().hash(&mut h);
    h.finish()
}

/// [`agent_proxy_call`] plus the forced-tool-choice fallback: when the body
/// carries a forcing `tool_choice` (anything but `"auto"`) and the proxy
/// returns a deterministic 400, retry once with `"auto"` — every expert prompt
/// (the solo preamble and the panel contract) names the `submit_analysis` call,
/// so capable models still emit it unforced. A successful fallback memoizes the
/// (alias, schema) pair; later calls start on `"auto"` directly. Every expert
/// call path goes through here.
async fn agent_analysis_call(
    client: &reqwest::Client,
    config: &AgentConfig,
    mut body: serde_json::Value,
    timeout: std::time::Duration,
) -> anyhow::Result<serde_json::Value> {
    let alias = body["model"].as_str().unwrap_or_default().to_string();
    let key = (alias, tools_fingerprint(&body["tools"]));
    let mut forced = body["tool_choice"].as_str() != Some("auto");
    if forced
        && let Ok(memo) = FORCED_CHOICE_REJECTED.lock()
        && memo.contains(&key)
    {
        body["tool_choice"] = serde_json::json!("auto");
        forced = false;
    }
    match agent_proxy_call(client, config, &body, timeout).await {
        Err(e) if forced && is_deterministic_400(&e) => {
            tracing::info!(
                alias = %key.0,
                "forced tool_choice rejected with 400 — retrying with tool_choice=auto"
            );
            body["tool_choice"] = serde_json::json!("auto");
            let response = agent_proxy_call(client, config, &body, timeout).await?;
            if let Ok(mut memo) = FORCED_CHOICE_REJECTED.lock() {
                memo.insert(key);
            }
            Ok(response)
        }
        other => other,
    }
}

/// POST an expert analysis request to the proxy and return the raw JSON body,
/// with bounded retry on transient failures. Connect errors and proxy `429`/`5xx`
/// retry up to `AGENT_HTTP_MAX_RETRIES`; a request timeout retries **at most
/// once** (the per-call timeout — `AGENT_HTTP_TIMEOUT_SECS` scaled by the
/// model's output budget via [`AgentRouting::call_timeout`] — is already
/// generous, so a second full attempt is expensive). Other `4xx` and decode
/// failures fail fast. Shared by all three expert paths (tool-inventory,
/// cluster, per-session) so the timeout/retry/transient-classification lives
/// in one place.
async fn agent_proxy_call(
    client: &reqwest::Client,
    config: &AgentConfig,
    body: &serde_json::Value,
    timeout: std::time::Duration,
) -> anyhow::Result<serde_json::Value> {
    let url = format!("{}/v1/chat/completions", config.proxy_url);
    let max_retries = crate::settings::admin_settings().agent_http_max_retries;
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        match client
            .post(&url)
            .timeout(timeout)
            .header("Authorization", format!("Bearer {}", config.api_key))
            .header("X-App-Id", &config.app_id)
            .json(body)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    // Capped like every other egress read. The body is our own
                    // proxy's, but it relays an upstream LLM's reply, so the
                    // honest ceiling is the one the proxy itself enforces on
                    // that reply — and the buffer is this admin-api replica's.
                    let cap =
                        streamscope_core::settings::core_settings().max_upstream_body_size as u64;
                    let raw = streamscope_core::http_body::read_body_capped(resp, cap).await?;
                    return Ok(serde_json::from_slice(&raw)?);
                }
                let retryable =
                    status_is_retryable(status) && agent_retry_allowed(false, attempt, max_retries);
                let backoff = agent_retry_backoff(status, resp.headers(), attempt, timeout);
                let retryable = retryable && backoff.is_some();
                let text = streamscope_core::http_body::read_body_capped(
                    resp,
                    AGENT_ERROR_BODY_CAP,
                )
                .await
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
                if retryable {
                    tracing::warn!(attempt, %status, ?backoff, "agent proxy call transient failure, retrying");
                    tokio::time::sleep(backoff.unwrap_or_default()).await;
                    continue;
                }
                // A session-specific 4xx (e.g. 400 bad request / unsupported
                // payload) fails the same way every cycle — tag it deterministic
                // so the batch skips it instead of holding the watermark forever.
                // Auth/permission (401/403) and exhausted 429/5xx stay transient
                // (a held stall + warnings is the right signal for those).
                if proxy_status_is_deterministic(status) {
                    return Err(anyhow::Error::new(DeterministicFailure {
                        msg: format!("proxy returned {status}: {text}"),
                        status: Some(status.as_u16()),
                    }));
                }
                anyhow::bail!("proxy returned {status}: {text}");
            }
            Err(e) => {
                let transient = e.is_timeout() || e.is_connect();
                if transient && agent_retry_allowed(e.is_timeout(), attempt, max_retries) {
                    tracing::warn!(attempt, "agent proxy call transient error, retrying: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(attempt as u64)).await;
                    continue;
                }
                return Err(e.into());
            }
        }
    }
}



/// Contiguous-prefix watermark for a processed batch. Returns
/// `(new_watermark, covered_count)`:
/// - `new_watermark` = the max **advanceable** timestamp (a success or a
///   deterministically-skipped session) **strictly below** the oldest TRANSIENT
///   failure — or the overall max advanceable when nothing was held. The
///   watermark therefore stops at the first transient failure (which retries
///   next cycle) but passes over deterministic skips so one poison session can't
///   wedge the backlog.
/// - `covered_count` = how many TRUE successes the watermark covers (the
///   `sessions_analyzed` increment, so the stat isn't inflated by skips or by
///   successes beyond a held failure that will be re-analyzed).
fn contiguous_watermark(
    advanceable_ts: &[chrono::DateTime<chrono::Utc>],
    success_ts: &[chrono::DateTime<chrono::Utc>],
    min_held_ts: Option<chrono::DateTime<chrono::Utc>>,
) -> (Option<chrono::DateTime<chrono::Utc>>, i64) {
    let new_watermark = match min_held_ts {
        Some(mh) => advanceable_ts.iter().copied().filter(|ts| *ts < mh).max(),
        None => advanceable_ts.iter().copied().max(),
    };
    let covered_count = match new_watermark {
        Some(w) => success_ts.iter().filter(|ts| **ts <= w).count() as i64,
        None => 0,
    };
    (new_watermark, covered_count)
}

/// A non-retryable, session-specific failure (a session-specific `4xx` from the
/// proxy, or an unparseable analysis response). Such a session fails the same way
/// every cycle, so the batch SKIPS it (advancing past it with a loud warning)
/// rather than holding the per-expert watermark forever — only transient failures
/// are held for retry.
#[derive(Debug)]
struct DeterministicFailure {
    msg: String,
    /// Proxy HTTP status when the failure came off the wire (`None` for local
    /// parse/validation failures) — lets the tool-choice fallback target 400s.
    status: Option<u16>,
}

impl std::fmt::Display for DeterministicFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for DeterministicFailure {}

/// True when the error chain carries a [`DeterministicFailure`] — the batch skips
/// the session and advances; otherwise the failure is transient (hold + retry).
fn is_deterministic_failure(err: &anyhow::Error) -> bool {
    err.chain().any(|c| c.is::<DeterministicFailure>())
}

/// True when the error chain carries a deterministic proxy `400` — the one
/// status the forced-tool-choice fallback retries with `"auto"`.
fn is_deterministic_400(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|c| c.downcast_ref::<DeterministicFailure>())
        .any(|d| d.status == Some(400))
}

/// Tag a session-analysis error as deterministic so the batch skips the session.
fn deterministic(err: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(DeterministicFailure { msg: err.to_string(), status: None })
}

/// A proxy `4xx` that is specific to this request/session (so it recurs every
/// cycle) and is therefore skip-and-advance. Excludes the recoverable/auth 4xx
/// that must stay transient (hold + retry): auth/permission (`401`/`403`),
/// throttle (`429`), and the time-based transients (`408 Request Timeout`,
/// `425 Too Early`).
fn proxy_status_is_deterministic(status: reqwest::StatusCode) -> bool {
    use reqwest::StatusCode;
    status.is_client_error()
        && !matches!(
            status,
            StatusCode::UNAUTHORIZED
                | StatusCode::FORBIDDEN
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_EARLY
        )
}

/// A proxy response status worth retrying — `429` (throttle) or any `5xx`.
fn status_is_retryable(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// How long to wait before retrying a refused proxy call: on a 429, the
/// proxy's own `Retry-After` — a rate window or a class's hold, which a retry
/// one second later only spends the next attempt against — else one second
/// per attempt so far. `None` — do not retry — when the hint is longer than
/// one call may take: the batch is better off failing transiently and
/// retrying next cycle than sleeping inside it.
fn agent_retry_backoff(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    attempt: usize,
    timeout: std::time::Duration,
) -> Option<std::time::Duration> {
    let hinted = (status == reqwest::StatusCode::TOO_MANY_REQUESTS)
        .then(|| streamscope_core::proxy::client::parse_retry_after(headers))
        .flatten();
    match hinted {
        Some(wait) => (wait <= timeout).then_some(wait),
        None => Some(std::time::Duration::from_secs(attempt as u64)),
    }
}

/// Whether a transient failure on attempt `attempt` (1-based) may retry. A
/// request timeout retries **at most once** (the per-call timeout is already
/// generous, so a second full attempt is expensive); other transient failures
/// (connect / 429 / 5xx) retry up to `max_retries`.
fn agent_retry_allowed(is_timeout: bool, attempt: usize, max_retries: usize) -> bool {
    if is_timeout {
        attempt <= 1
    } else {
        attempt <= max_retries
    }
}

/// Fetch sessions updated since the given watermark via direct DB query.
/// When `cooldown_mins > 0`, only sessions idle for at least that many minutes are returned.
async fn fetch_sessions_via_db(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    since: Option<chrono::DateTime<chrono::Utc>>,
    cooldown_mins: i64,
    workspace_filter: Option<&WorkspaceIds>,
    include_keyless: bool,
) -> anyhow::Result<Vec<SessionMeta>> {
    let mut db = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;

    let mut query = crate::routes::audit::SessionListQuery::default();
    query.limit = Some(crate::settings::admin_settings().agent_session_batch_limit);
    query.sort = Some(crate::routes::audit::SessionSort::Oldest);
    query.exclude_user = Some(super::AGENT_EMAIL.to_string());
    query.updated_since = since;
    query.updated_before = if cooldown_mins > 0 {
        Some(chrono::Utc::now() - chrono::Duration::minutes(cooldown_mins))
    } else {
        None
    };
    // Per-profile expert scoping: restrict to sessions in one of the profile's
    // workspaces (`None` = every workspace). Sessions carrying no workspace
    // attribution follow the Default profile.
    let scope = crate::audit_store::AuditScope::tenant(None, workspace_filter.cloned())
        .including_keyless(include_keyless);

    let summaries =
        crate::audit_store::sessions::list_sessions_impl(db.conn(), query, &scope).await?.rows;

    // Convert SessionSummary to SessionMeta (the agent's internal struct)
    let sessions: Vec<SessionMeta> = summaries
        .into_iter()
        .map(|s| SessionMeta {
            session_id: s.session_id,
            user_id: s.user_id,
            key_id: s.key_id,
            turn_count: s.turn_count,
            total_tokens: s.total_tokens,
            spend: s.spend,
            first_timestamp: Some(s.first_timestamp),
            last_timestamp: Some(s.last_timestamp),
            last_latency_ms: s.last_latency_ms,
            model_requested: s.model_requested,
            model_used: s.model_used,
            user_email: s.user_email,
            app_id: s.app_id,
            first_user_prompt: s.first_user_prompt,
        })
        .collect();

    Ok(sessions)
}

/// One `kind='expert'` profile with its resolved workspace scope and effective
/// membership, for the cycle's per-profile grouping.
struct ExpertProfileScope {
    id: uuid::Uuid,
    name: String,
    is_default: bool,
    /// Judge model. `None` on a non-default profile = inherit the Default's;
    /// `None` on the Default = the built-in `DEFAULT_AGENT_MODEL`.
    model: Option<String>,
    /// Indices into the cycle's expert list — the profile's EFFECTIVE members
    /// (Default ∪ own for a Layered profile; own for Standalone/Default),
    /// restricted to enabled, unsuppressed experts.
    member_idx: Vec<usize>,
    /// Sessions filter (`workspace_ids`). `None` = every workspace
    /// (the Default profile while no other assignment exists).
    ws_filter: Option<WorkspaceIds>,
    /// Orphan/keyless sessions follow the Default profile.
    include_keyless: bool,
    /// False when the profile reaches no workspace (and isn't the keyless
    /// catch-all Default) — it forms no groups this cycle.
    active: bool,
}

/// Load the tenant's expert-profile partition: every `kind='expert'` profile
/// with its judge model, effective member set, and workspace scope. Each
/// workspace follows its assigned profile (no row = inherit the Default,
/// NULL `profile_id` = explicit Off); orphan/keyless sessions follow the
/// Default. Tenant isolation is enforced by RLS on the scoped connection.
async fn load_expert_profile_partition(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    experts: &[ExpertWithProgress],
) -> anyhow::Result<Vec<ExpertProfileScope>> {
    let mut db = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;

    let profiles: Vec<(uuid::Uuid, String, bool, bool, Option<String>)> = sqlx::query_as(
        "SELECT id, name, is_default, standalone, model FROM profiles \
         WHERE kind = 'expert' ORDER BY is_default DESC, name",
    )
    .fetch_all(db.conn())
    .await?;

    let members: Vec<(uuid::Uuid, uuid::Uuid)> =
        sqlx::query_as("SELECT profile_id, expert_id FROM expert_profile_members")
            .fetch_all(db.conn())
            .await?;

    let assignments: Vec<(uuid::Uuid, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT workspace_id, profile_id FROM workspace_profile_assignments WHERE kind = 'expert'",
    )
    .fetch_all(db.conn())
    .await?;

    let all_ws: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM workspaces")
        .fetch_all(db.conn())
        .await?;

    let expert_pos: std::collections::HashMap<uuid::Uuid, usize> =
        experts.iter().enumerate().map(|(i, e)| (e.id, i)).collect();
    let default_id = profiles.iter().find(|p| p.2).map(|p| p.0);
    let own = |pid: uuid::Uuid| -> Vec<uuid::Uuid> {
        members.iter().filter(|(p, _)| *p == pid).map(|(_, e)| *e).collect()
    };
    let default_members = default_id.map(own).unwrap_or_default();
    let assigned_ws: std::collections::HashSet<uuid::Uuid> =
        assignments.iter().map(|(w, _)| *w).collect();

    let mut out = Vec::with_capacity(profiles.len());
    for (id, name, is_default, standalone, model) in profiles {
        // Effective members: Default and Standalone own their set; a Layered
        // profile inherits the Default's and layers its own on top.
        let mut ids = own(id);
        if !is_default && !standalone {
            ids.extend(default_members.iter().copied());
        }
        ids.sort_unstable();
        ids.dedup();
        let member_idx: Vec<usize> =
            ids.iter().filter_map(|e| expert_pos.get(e).copied()).collect();

        // Workspace scope: explicit assignments, plus (for the Default) every
        // workspace with no assignment at all.
        let mut ws: Vec<uuid::Uuid> = assignments
            .iter()
            .filter(|(_, p)| *p == Some(id))
            .map(|(w, _)| *w)
            .collect();
        if is_default {
            ws.extend(all_ws.iter().filter(|w| !assigned_ws.contains(w)));
        }
        ws.sort_unstable();

        // The Default with no divergent assignment covers everything (fast
        // path, keyless trivially included). Otherwise the set is explicit —
        // for a Default left with zero workspaces, a nil-UUID placeholder
        // keeps the filter non-empty so only keyless sessions match.
        let universal = is_default && assignments.is_empty();
        let ws_filter = if universal {
            None
        } else if ws.is_empty() {
            Some(WorkspaceIds(vec![uuid::Uuid::nil()]))
        } else {
            Some(WorkspaceIds(ws.clone()))
        };
        let active = universal || !ws.is_empty() || is_default;

        out.push(ExpertProfileScope {
            id,
            name,
            is_default,
            model,
            member_idx,
            ws_filter,
            include_keyless: is_default,
            active,
        });
    }

    Ok(out)
}

/// Load every `(profile_id, expert_id) → last_processed_at` watermark row.
async fn load_profile_watermarks(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
) -> anyhow::Result<
    std::collections::HashMap<(uuid::Uuid, uuid::Uuid), Option<chrono::DateTime<chrono::Utc>>>,
> {
    let mut db = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;
    let rows: Vec<(uuid::Uuid, uuid::Uuid, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT profile_id, expert_id, last_processed_at FROM expert_profile_watermarks",
        )
        .fetch_all(db.conn())
        .await?;
    Ok(rows.into_iter().map(|(p, e, ts)| ((p, e), ts)).collect())
}

/// First sight of a live (profile, expert) pair: seed its watermark at
/// effective-now so a newly-created/assigned profile starts analyzing from now
/// instead of re-scanning history (the Default's pairs at tenant creation are
/// seeded with a NULL cursor and scan from the beginning).
async fn seed_profile_watermark(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    profile_id: uuid::Uuid,
    expert_id: uuid::Uuid,
    at: chrono::DateTime<chrono::Utc>,
) {
    let Ok(mut db) = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await else {
        return;
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO expert_profile_watermarks \
            (profile_id, expert_id, tenant_id, last_processed_at) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(profile_id)
    .bind(expert_id)
    .bind(tenant_id)
    .bind(at)
    .execute(db.conn())
    .await
    {
        tracing::error!("expert profile watermark seed failed: {e}");
    }
}

/// Fetch conversation data for a session via direct DB query.
async fn fetch_conversation_via_db(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    session_id: uuid::Uuid,
) -> anyhow::Result<serde_json::Value> {
    let mut db = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;

    match crate::routes::audit::get_session_conversation_impl(
        db.conn(),
        tenant_id,
        session_id,
        crate::routes::audit::ResponseFormat::Parsed,
        &crate::audit_store::AuditScope::tenant(None, None),
    ).await {
        Ok(resp) => Ok(serde_json::to_value(resp)?),
        Err(e) => {
            tracing::warn!(session_id = %session_id, "conversation query failed: {e}");
            Ok(serde_json::json!({}))
        }
    }
}

/// Fetch currently active transform programs for LLM context.
/// Uses name + description (not full source) to stay within context budget.
async fn fetch_active_programs(pool: &crate::db::Db, tenant_id: uuid::Uuid) -> anyhow::Result<Vec<String>> {
    let mut db = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await?;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, description FROM transform_programs WHERE enabled = true AND NOT suppressed",
    )
    .fetch_all(db.conn())
    .await?;

    Ok(rows
        .into_iter()
        .map(|(name, desc)| format!("- **{name}**: {desc}"))
        .collect())
}

/// Truncate a string at a char boundary, returning at most `max_bytes` bytes.
fn safe_truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    &s[..s.floor_char_boundary(max_bytes)]
}

/// A single conversation event for rendering to the agent.
struct ConvEvent {
    turn: i32,
    label: String,
    content: String,
    /// Optional render annotation appended to the event's label line (e.g.
    /// `finish: length` so the judge sees a truncated/filtered assistant turn
    /// without inferring it from prose). `None` for events with no annotation.
    marker: Option<String>,
}

/// A session's spend as a prompt states it: the amount and the code of the
/// currency it was booked in, or that no single figure states it (its turns
/// span a change of the accounting currency). Never a bare `$` — a tenant
/// may keep its books in any currency.
fn render_spend(spend: Option<crate::routes::SpendTotal>, decimals: usize) -> String {
    match spend {
        Some(s) => format!("{:.*} {}", decimals, s.amount, s.currency),
        None => "not stated in one currency".to_string(),
    }
}

/// Render a session's conversation data into structured text within a character budget.
/// Events are rendered chronologically (user, assistant, tool_call, tool_result)
/// so the agent sees the full interaction flow.
fn render_session(
    meta: &SessionMeta,
    conversation: &serde_json::Value,
    budget: usize,
) -> String {
    let model = meta.model_used.as_deref().unwrap_or("unknown");
    let user = meta.user_email.as_deref().unwrap_or("unknown");
    let app = meta.app_id.as_deref().unwrap_or("unknown");
    let tokens = meta.total_tokens.unwrap_or(0);
    let cost = render_spend(meta.spend, 2);

    // Extract structured data from conversation events
    let mut tool_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut media_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut system_prompt = String::new();
    let mut conv_events: Vec<ConvEvent> = Vec::new();

    if let Some(events) = conversation.get("events").and_then(|e| e.as_array()) {
        for event in events {
            let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let turn = event.get("turn").and_then(|t| t.as_i64()).unwrap_or(0) as i32;
            match event_type {
                "system_prompt" if system_prompt.is_empty() => {
                    system_prompt = event
                        .get("content")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                }
                "message" => {
                    let role = event
                        .get("role")
                        .and_then(|r| r.as_str())
                        .unwrap_or("unknown");
                    let content = event
                        .get("content")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !content.is_empty() {
                        // Surface an abnormal assistant finish reason (truncation,
                        // content filter, …). `stop`/`tool_calls`/empty are normal;
                        // `unknown` is the not-captured (NULL column) default — not a
                        // signal, so it's filtered to avoid noising the judge prompt.
                        let marker = (role == "assistant")
                            .then(|| event.get("metadata"))
                            .flatten()
                            .and_then(|m| m.get("finish_reason"))
                            .and_then(|f| f.as_str())
                            .filter(|r| !matches!(*r, "" | "stop" | "tool_calls" | "unknown"))
                            .map(|r| format!("finish: {r}"));
                        conv_events.push(ConvEvent {
                            turn,
                            label: role.to_string(),
                            content,
                            marker,
                        });
                    }
                    // Emit inline error annotation if turn has error metadata
                    if let Some(meta) = event.get("metadata")
                        && let Some(error_cat) = meta.get("error_category").and_then(|c| c.as_str())
                    {
                        let status = meta.get("status_code").and_then(|s| s.as_i64()).unwrap_or(0);
                        let detail = meta.get("error_detail").and_then(|d| d.as_str()).unwrap_or("");
                        let error_msg = if detail.is_empty() {
                            format!("[ERROR: {error_cat} {status}]")
                        } else {
                            format!("[ERROR: {error_cat} {status} — {}]", safe_truncate(detail, 200))
                        };
                        conv_events.push(ConvEvent {
                            turn,
                            label: "error".to_string(),
                            content: error_msg,
                            marker: None,
                        });
                    }
                }
                "tool_call" => {
                    let name = event
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown");
                    *tool_counts.entry(name.to_string()).or_insert(0) += 1;
                    let args = event
                        .get("arguments")
                        .map(|a| {
                            let s = serde_json::to_string(a).unwrap_or_default();
                            if s == "{}" || s == "null" {
                                String::new()
                            } else {
                                s
                            }
                        })
                        .unwrap_or_default();
                    let content = if args.is_empty() {
                        name.to_string()
                    } else {
                        // Bound to the whole session budget only; the render layer
                        // applies the window-derived per-event cap so big-window
                        // judges see full tool arguments (agentic arg checking).
                        format!("{name}: {}", safe_truncate(&args, budget))
                    };
                    conv_events.push(ConvEvent {
                        turn,
                        label: "tool_call".to_string(),
                        content,
                        marker: None,
                    });
                }
                "tool_result" => {
                    let content = event
                        .get("content")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !content.is_empty() {
                        conv_events.push(ConvEvent {
                            turn,
                            label: "tool_result".to_string(),
                            content,
                            marker: None,
                        });
                    }
                }
                "compaction" => {
                    let before = event.get("messages_before").and_then(|v| v.as_i64());
                    let after = event.get("messages_after").and_then(|v| v.as_i64());
                    let summary = event.get("summary").and_then(|s| s.as_str()).unwrap_or("");
                    let content = if let (Some(b), Some(a)) = (before, after) {
                        format!("[compaction: {b}\u{2192}{a} messages] {}", safe_truncate(summary, 200))
                    } else {
                        format!("[compaction] {}", safe_truncate(summary, 200))
                    };
                    conv_events.push(ConvEvent { turn, label: "compaction".to_string(), content, marker: None });
                }
                "time_gap" => {
                    let gap_ms = event.get("gap_ms").and_then(|v| v.as_i64()).unwrap_or(0);
                    let mins = gap_ms / 60000;
                    let secs = (gap_ms % 60000) / 1000;
                    conv_events.push(ConvEvent {
                        turn,
                        label: "time_gap".to_string(),
                        content: format!("[{mins}m{secs}s gap]"),
                        marker: None,
                    });
                }
                "media" => {
                    let content_type = event.get("content_type").and_then(|c| c.as_str()).unwrap_or("media");
                    let role = event.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                    let media_mime = event.get("media_type").and_then(|m| m.as_str()).unwrap_or("");
                    let title = event.get("title").and_then(|t| t.as_str());
                    let size = event.get("size_bytes").and_then(|s| s.as_u64());

                    *media_counts.entry(content_type.to_string()).or_insert(0) += 1;

                    let mut desc = format!("[{content_type} attachment]");
                    if let Some(t) = title { desc.push_str(&format!(" {t}")); }
                    if !media_mime.is_empty() { desc.push_str(&format!(" ({media_mime})")); }
                    if let Some(s) = size { desc.push_str(&format!(" {}KB", s / 1024)); }

                    conv_events.push(ConvEvent {
                        turn,
                        label: format!("{role}_media"),
                        content: desc,
                        marker: None,
                    });
                }
                "media_api_call" => {
                    // Canonical MediaApiCall shape: `media_call` is the nested
                    // `DomainMediaCall` JSON (endpoint / model / input / output / params).
                    let media_call = event.get("media_call");
                    let endpoint = media_call
                        .and_then(|c| c.get("endpoint"))
                        .and_then(|e| e.as_str())
                        .unwrap_or("media");
                    let model = media_call
                        .and_then(|c| c.get("model"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("");
                    let input = media_call
                        .and_then(|c| c.get("input"))
                        .and_then(|v| v.as_array())
                        .and_then(|arr| {
                            arr.iter().find_map(|b| {
                                b.get("text").and_then(|t| t.as_str()).map(String::from)
                            })
                        })
                        .unwrap_or_default();
                    let output = media_call
                        .and_then(|c| c.get("output"))
                        .and_then(|v| v.as_array())
                        .and_then(|arr| {
                            arr.iter().find_map(|b| {
                                b.get("text").and_then(|t| t.as_str()).map(String::from)
                            })
                        })
                        .unwrap_or_default();
                    let meta = event.get("metadata");
                    let spend = meta
                        .and_then(|m| m.get("spend"))
                        .and_then(|s| <crate::routes::SpendTotal as serde::Deserialize>::deserialize(s).ok());

                    *media_counts.entry(endpoint.to_string()).or_insert(0) += 1;

                    let mut desc = format!("[{endpoint}]");
                    if !model.is_empty() {
                        desc.push_str(&format!(" (model: {model})"));
                    }
                    // In the call's own currency — the session's need not be it.
                    if let Some(s) = spend.filter(|s| s.amount > 0.0) {
                        desc.push_str(&format!(" cost {}", render_spend(Some(s), 4)));
                    }
                    if !input.is_empty() {
                        desc.push_str(&format!(": {}", safe_truncate(&input, 200)));
                    }
                    if !output.is_empty() {
                        desc.push_str(&format!(" \u{2192} {}", safe_truncate(&output, 200)));
                    }

                    conv_events.push(ConvEvent {
                        turn,
                        label: "media_call".to_string(),
                        content: desc,
                        marker: None,
                    });
                }
                // Framework-injected blocks (`<system-reminder>`, etc.) are
                // intentionally skipped from agent context — re-including
                // them would teach experts to re-emit framework noise, and
                // the matching `strip_system_reminders()` already removes
                // them from the system prompt feed for the same reason.
                "framework_reminder" => {}
                _ => {}
            }
        }
    }

    // First user prompt as topic anchor
    let topic = meta
        .first_user_prompt
        .as_deref()
        .or_else(|| {
            conv_events
                .iter()
                .find(|e| e.label == "user")
                .map(|e| e.content.as_str())
        })
        .unwrap_or("")
        .chars()
        .take(200)
        .collect::<String>();

    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "## Session (model: {model}, user: {user}, app: {app}, turns: {}, tokens: {tokens}, cost: {cost})\n",
        meta.turn_count,
    ));

    // Model routing info (alias → upstream is normal proxy behavior)
    if let Some(requested) = &meta.model_requested
        && meta.model_used.as_deref() != Some(requested) {
            out.push_str(&format!("Model alias routing: {requested} → upstream: {model} (configured proxy routing, normal)\n"));
        }

    // Duration and latency
    if let (Some(first), Some(last)) = (meta.first_timestamp, meta.last_timestamp) {
        let duration = last - first;
        let mins = duration.num_minutes();
        let secs = duration.num_seconds() % 60;
        out.push_str(&format!("Duration: {mins}m{secs}s"));
        if let Some(latency) = meta.last_latency_ms {
            out.push_str(&format!(", last_latency: {latency}ms"));
        }
        out.push('\n');
    }

    if !topic.is_empty() {
        out.push_str(&format!("Topic: {topic}\n"));
    }

    // Tools summary
    if !tool_counts.is_empty() {
        let mut tools: Vec<_> = tool_counts.iter().collect();
        tools.sort_by(|a, b| b.1.cmp(a.1));
        let tools_str: Vec<String> =
            tools.iter().map(|(n, c)| format!("{n}({c})")).collect();
        out.push_str(&format!("Tools: {}\n", tools_str.join(", ")));
    }

    // Media summary
    if !media_counts.is_empty() {
        let mut media: Vec<_> = media_counts.iter().collect();
        media.sort_by(|a, b| b.1.cmp(a.1));
        let media_str: Vec<String> =
            media.iter().map(|(n, c)| format!("{n}({c})")).collect();
        out.push_str(&format!("Media: {}\n", media_str.join(", ")));
    }

    let header_len = out.len();
    let remaining = budget.saturating_sub(header_len);

    if remaining < 100 {
        return out;
    }

    // Budget: 15% system prompt, 85% conversation
    let sp_budget = (remaining * 15 / 100).min(system_prompt.len());
    let conv_budget = remaining * 85 / 100;

    // System prompt
    if !system_prompt.is_empty() && sp_budget > 20 {
        out.push_str("\n### System Prompt\n");
        let truncated = safe_truncate(&system_prompt, sp_budget);
        out.push_str(truncated);
        if truncated.len() < system_prompt.len() {
            out.push_str("...[truncated]\n");
        } else {
            out.push('\n');
        }
    }

    // Conversation events — chronological with tool calls and results
    render_conversation(&mut out, &conv_events, conv_budget);

    out.push('\n');
    out
}

/// Render conversation events chronologically within a budget, sampling if needed.
fn render_conversation(out: &mut String, events: &[ConvEvent], budget: usize) {
    if events.is_empty() || budget < 50 {
        return;
    }

    let total = events.len();
    let avg_len = events
        .iter()
        .map(|e| e.content.len().min(800) + 30)
        .sum::<usize>()
        / total;
    let max_events = (budget / avg_len.max(1)).max(2).min(total);

    // Select events: always first, sample evenly
    let indices: Vec<usize> = if max_events >= total {
        (0..total).collect()
    } else {
        let mut idx = vec![0];
        let step = (total - 1) as f64 / (max_events - 1).max(1) as f64;
        for i in 1..max_events {
            let v = (i as f64 * step) as usize;
            if v > 0 && v < total && !idx.contains(&v) {
                idx.push(v);
            }
        }
        idx
    };

    let shown = indices.len();
    out.push_str(&format!(
        "\n### Conversation ({shown} of {total} events)\n"
    ));

    let per_event_budget = budget / shown.max(1);
    // Window-derived per-event ceilings: scale with the conversation budget
    // (which tracks the judge model's context window) so large retrieved tool
    // outputs and long messages aren't clipped on big-window judges — the
    // faithfulness/agentic signal depends on the judge actually seeing the
    // retrieved context. The prior fixed values (500 / 2000) are floors, so
    // small-window judges are unchanged; tool content stays proportionally
    // smaller than messages. Each ceiling is still bounded by per_event_budget
    // (the fair per-event share) below, so the rendered total never exceeds
    // `budget`.
    let tool_ceiling = (budget / 8).max(500);
    let msg_ceiling = (budget / 4).max(2000);
    for &idx in &indices {
        let event = &events[idx];
        let content_limit = if event.label == "tool_result" || event.label == "tool_call" {
            per_event_budget.min(tool_ceiling)
        } else {
            per_event_budget.min(msg_ceiling)
        };
        let truncated = safe_truncate(&event.content, content_limit);
        let suffix = if truncated.len() < event.content.len() {
            "..."
        } else {
            ""
        };
        let marker = event
            .marker
            .as_deref()
            .map(|m| format!(" ({m})"))
            .unwrap_or_default();
        out.push_str(&format!(
            "[T{} {}{}] {}{}\n",
            event.turn, event.label, marker, truncated, suffix
        ));
    }
}

/// Write a session alert via `sessions.alert_level` / `alert_expert_axis` /
/// `alert_note` — the one place an alert is stored.
async fn write_session_alert(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    session_id: &str,
    axis: &str,
    level: &str,
    note: &str,
) {
    let Ok(sid) = uuid::Uuid::parse_str(session_id) else {
        return;
    };

    let Ok(mut db) = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await else {
        return;
    };

    // The audit list reads the alert from the session (`session_alert` on each
    // of its LLM rows): audit rows are facts and are never rewritten here.
    let prefixed_note = format!("[{axis}:{level}] {note}");
    // Severity ordering: major > minor > info. A lower-severity write must
    // never overwrite a higher-severity existing level on the same session.
    if let Err(e) = sqlx::query(
        "UPDATE sessions SET \
         alert_level = CASE \
           WHEN alert_level = 'major' THEN 'major' \
           WHEN alert_level = 'minor' AND $2 = 'info' THEN 'minor' \
           ELSE $2 END, \
         alert_expert_axis = CASE WHEN alert_expert_axis IS NULL THEN $3 \
           WHEN $3 = ANY (string_to_array(alert_expert_axis, ', ')) THEN alert_expert_axis \
           ELSE alert_expert_axis || ', ' || $3 END, \
         alert_note = CASE WHEN alert_note IS NULL THEN $4 \
           ELSE alert_note || E'\\n' || $4 END \
         WHERE session_id = $1",
    )
    .bind(sid)
    .bind(level)
    .bind(axis)
    .bind(&prefixed_note)
    .execute(db.conn())
    .await
    {
        tracing::error!(session_id, "agent session alert write failed: {e}");
    }

    // Push a notification when a session reaches `major`. Deduped per session so
    // multiple experts hitting major on the same session emit one alert.
    // Best-effort — a notification failure never undoes the session alert.
    if level == "major" {
        let _ = crate::notifications::notify(
            db.conn(),
            tenant_id,
            crate::notifications::NewNotification {
                workspace_id: None,
                kind: crate::notifications::NotificationKind::SessionMajorAlert,
                dedup_key: format!("session_alert:{session_id}:major"),
                title: format!("Major alert: {axis}"),
                summary: note.to_string(),
                target_kind: Some("session"),
                target_id: Some(sid),
                payload: serde_json::json!({ "axis": axis, "note": note }),
            },
        )
        .await;
    }

    tracing::debug!(session_id, axis, level, note, "wrote session alert");
}

/// Persist cluster-path cross-session issues as first-class `cross_session_relations`
/// rows (`kind='issue'`) plus their `role='subject'` members — the structured home
/// that replaces stamping a multi-session finding onto one arbitrary session's alert.
/// Best-effort / log-only: an insert error must never hold or double-advance the
/// per-(profile,expert) watermark (same contract as `write_session_alert`).
///
/// Issues are **append-only observations**, deliberately NOT deduped: each is one
/// cycle's finding, and the watermark only re-analyzes a cluster when new turns
/// arrive, so a static pattern is recorded once. Retention ages them out
/// reference-driven (see `retention.rs`); the dashboard shows the most recent.
async fn store_cross_session_relations(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    key_id: Option<uuid::Uuid>,
    profile_id: uuid::Uuid,
    axis: &str,
    issues: &[(String, String, Vec<uuid::Uuid>)], // (level, note, source_session_ids)
) {
    if issues.is_empty() {
        return;
    }
    let Ok(mut db) = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await else {
        return;
    };

    // Best-effort provenance: the workspace this cluster belongs to, read from
    // the subject sessions themselves and never from the cluster's key — a
    // spec-OAuth MCP session carries the access token's jti in `key_id`, so a
    // key lookup resolves nothing and would leave the issue unscoped and thus
    // absent from every workspace-filtered listing.
    //
    // NULL when the cluster's sessions carry no attribution at all, or when they
    // span more than one workspace: an ambiguous cluster is left unscoped rather
    // than attributed to one arbitrary member's workspace.
    let subject_sessions: Vec<uuid::Uuid> = issues
        .iter()
        .flat_map(|(_, _, source_ids)| source_ids.iter().copied())
        .collect();
    let distinct: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT workspace_id FROM sessions \
         WHERE session_id = ANY($1) \
           AND workspace_id <> '00000000-0000-0000-0000-000000000000'::uuid",
    )
    .bind(&subject_sessions)
    .fetch_all(db.conn())
    .await
    .unwrap_or_default();
    let workspace_id: Option<uuid::Uuid> = match distinct.as_slice() {
        [only] => Some(*only),
        _ => None,
    };

    let mut stored = 0usize;
    for (level, note, source_ids) in issues {
        // Relation + its members in one small tx so a partial member insert can't
        // leave an issue with no linked sessions.
        let mut tx = match db.conn().begin().await {
            Ok(tx) => tx,
            Err(e) => {
                tracing::error!(axis, "cross-session issue tx begin failed: {e}");
                continue;
            }
        };
        let relation_id: uuid::Uuid = match sqlx::query_scalar(
            "INSERT INTO cross_session_relations \
               (tenant_id, kind, axis, level, note, origin, key_id, workspace_id, expert_profile_id) \
             VALUES ($1, 'issue', $2, $3, $4, 'agent', $5, $6, $7) RETURNING id",
        )
        .bind(tenant_id)
        .bind(axis)
        .bind(level)
        .bind(note)
        .bind(key_id)
        .bind(workspace_id)
        .bind(profile_id)
        .fetch_one(&mut *tx)
        .await
        {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(axis, "cross-session relation insert failed: {e}");
                let _ = tx.rollback().await;
                continue;
            }
        };
        let mut members_ok = true;
        for (seq, sid) in source_ids.iter().enumerate() {
            if let Err(e) = sqlx::query(
                "INSERT INTO cross_session_relation_members (relation_id, tenant_id, session_id, role, seq) \
                 VALUES ($1, $2, $3, 'subject', $4)",
            )
            .bind(relation_id)
            .bind(tenant_id)
            .bind(sid)
            .bind(seq as i32)
            .execute(&mut *tx)
            .await
            {
                tracing::error!(axis, "cross-session member insert failed: {e}");
                members_ok = false;
                break;
            }
        }
        if members_ok {
            match tx.commit().await {
                Ok(()) => stored += 1,
                Err(e) => tracing::error!(axis, "cross-session issue commit failed: {e}"),
            }
        } else {
            let _ = tx.rollback().await;
        }
    }
    tracing::info!(axis, stored, "stored cross-session issues");
}

/// Replace memory with LLM's update. Empty update = keep existing.
fn merge_memory(existing: &str, update: &str) -> String {
    if update.is_empty() {
        return existing.to_string();
    }
    let result = update.trim().to_string();
    if result.len() > MEMORY_CAP {
        let start = result.ceil_char_boundary(result.len() - MEMORY_CAP);
        let start = result[start..]
            .find('\n')
            .map(|i| start + i + 1)
            .unwrap_or(start);
        format!("[truncated]\n{}", &result[start..])
    } else {
        result
    }
}

/// When the expert lists `security_frameworks` as an input type, append a
/// compact form of the framework knowledge pack (id + title + summary +
/// hints) to the user-message context. This is how the framework-aware
/// expert receives OWASP / MITRE ATLAS / CWE references to cite via
/// `framework_refs` on each proposed rule. Capped at 4KB to match the
/// memory-injection budget.
fn inject_security_frameworks(context: &mut String, input_types: &[String]) {
    if !input_types.iter().any(|t| t == "security_frameworks") {
        return;
    }
    let frameworks = crate::seed_loader::load_security_frameworks();
    if frameworks.is_empty() {
        return;
    }
    let mut buf = String::from("\n## Security Frameworks (cite via `framework_refs`)\n\n");
    for f in frameworks {
        let hints = if f.tool_risk_hints.is_empty() {
            String::new()
        } else {
            format!(
                "  Hints: {}\n",
                f.tool_risk_hints
                    .iter()
                    .map(|h| format!("\"{h}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        buf.push_str(&format!(
            "- [{id}] ({framework} {version}) {title}\n  {summary}\n{hints}",
            id = f.id,
            framework = f.framework,
            version = f.version,
            title = f.title,
            summary = f.summary,
            hints = hints,
        ));
    }
    const FRAMEWORK_BUDGET: usize = 4096;
    if buf.len() > FRAMEWORK_BUDGET {
        let capped = safe_truncate(&buf, FRAMEWORK_BUDGET);
        context.push_str(capped);
        context.push_str("...[truncated]\n");
    } else {
        context.push_str(&buf);
    }
    context.push('\n');
}

fn analysis_tool_definition(output_types: &[String], cluster_alerts: bool) -> serde_json::Value {
    let (properties, required) = axis_payload_schema(output_types, cluster_alerts);

    let has_transforms = output_types.iter().any(|t| t == "transform_suggestion");
    let has_labels = output_types.iter().any(|t| t == "session_label");
    let has_tool_rules = output_types.iter().any(|t| t == "tool_rules");
    let has_field_profiles = output_types.iter().any(|t| t == "field_profile_suggestion");
    let has_alert = output_types.iter().any(|t| t == "alert");
    let has_memory = output_types.iter().any(|t| t == "memory");

    // --- Build description based on capabilities ---
    let mut desc_parts = vec!["Submit analysis results"];
    if has_labels { desc_parts.push("with session labels/links"); }
    if has_transforms { desc_parts.push("with proposed transform programs"); }
    if has_tool_rules { desc_parts.push("with proposed tool risk rules"); }
    if has_field_profiles { desc_parts.push("with proposed tool field profiles"); }
    if has_alert { desc_parts.push("with alerts"); }
    if has_memory { desc_parts.push("with memory updates"); }
    let description = format!("{}.", desc_parts.join(" "));

    serde_json::json!({
        "type": "function",
        "function": {
            "name": "submit_analysis",
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }
    })
}

/// `submit_analysis` schema for a merged (multi-axis) pooled call.
///
/// The payload is one required `axes` object with one REQUIRED entry per
/// member axis — the model structurally cannot skip an axis or answer under a
/// name that isn't in the panel. Each axis entry carries a mandatory
/// `assessment` verdict plus that axis's own output fields. On the cluster
/// path (`cluster_alerts`) the scalar alert pair is replaced by a
/// `session_alerts[]` channel so an alert names the session it targets.
fn analysis_tool_definition_for_group(
    members: &[(&str, &[String])],
    cluster_alerts: bool,
) -> serde_json::Value {
    let mut axes_props = serde_json::Map::new();
    let mut axes_required: Vec<&str> = Vec::new();

    for (axis, output_types) in members {
        let (mut properties, mut required) = axis_payload_schema(output_types, cluster_alerts);

        properties.insert("assessment".to_string(), serde_json::json!({
            "type": "string",
            "enum": ["clear", "findings"],
            "description": "REQUIRED verdict: `clear` = nothing notable, `findings` = any finding/alert/proposal/label emitted"
        }));
        required.insert(0, "assessment");

        axes_props.insert((*axis).to_string(), serde_json::json!({
            "type": "object",
            "description": format!("Complete answer for the `{axis}` axis. MANDATORY — emit it even when the verdict is `clear`."),
            "properties": properties,
            "required": required
        }));
        axes_required.push(axis);
    }

    let axis_list = members.iter().map(|(a, _)| *a).collect::<Vec<_>>().join("`, `");

    serde_json::json!({
        "type": "function",
        "function": {
            "name": "submit_analysis",
            "description": format!(
                "Submit the panel's analysis. `axes` MUST contain one complete entry for EVERY axis: `{axis_list}`. An axis with nothing to report still submits its entry with assessment `clear`."
            ),
            "parameters": {
                "type": "object",
                "properties": { "axes": {
                    "type": "object",
                    "properties": axes_props,
                    "required": axes_required
                }},
                "required": ["axes"]
            }
        }
    })
}

/// Field schema for one axis's `submit_analysis` payload, driven by the
/// expert's `output_types`. Returns (properties, required). With
/// `cluster_alerts` the scalar `alert_level`/`alert_note` pair is replaced by
/// the cluster-path `session_alerts[]` channel (alerts must name a session).
fn axis_payload_schema(
    output_types: &[String],
    cluster_alerts: bool,
) -> (serde_json::Map<String, serde_json::Value>, Vec<&'static str>) {
    let mut properties = serde_json::Map::new();
    let mut required: Vec<&'static str> = Vec::new();

    let has_transforms = output_types.iter().any(|t| t == "transform_suggestion");
    let has_labels = output_types.iter().any(|t| t == "session_label");
    let has_tool_rules = output_types.iter().any(|t| t == "tool_rules");
    let has_field_profiles = output_types.iter().any(|t| t == "field_profile_suggestion");

    // --- Output-type-specific fields (only what this expert needs) ---

    if has_transforms || has_tool_rules {
        properties.insert("findings".to_string(), serde_json::json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": { "type": "string", "enum": ["high", "medium", "low"] },
                    "category": { "type": "string" },
                    "description": { "type": "string" },
                    "evidence": { "type": "string", "description": "Brief excerpt from the session" }
                },
                "required": ["severity", "category", "description"]
            }
        }));
        required.push("findings");
    }

    if has_transforms {
        // Field semantics live in the transform_suggestion prompt snippet —
        // schema descriptions stay one-line. The whole sanitized schema is
        // compiled into a constrained-decoding grammar when tool_choice is
        // forced (Gemini mode ANY); verbose descriptions ×N merged axes blow
        // the provider's grammar size limit → 400 INVALID_ARGUMENT.
        properties.insert("proposed_programs".to_string(), serde_json::json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "snake_case descriptive name" },
                    "description": { "type": "string", "description": "What the script does and why" },
                    "source": { "type": "string", "description": "Valid Rhai script (see the transform snippet for the full/span contracts)" },
                    "phase": { "type": "string", "enum": ["request", "response"] },
                    "scope": { "type": "string", "description": "request: global|system_prompt|messages|tools; response: global|text|tool|thinking" },
                    "match_mode": { "type": ["string", "null"], "enum": ["full", "span", null], "description": "null/full = whole scope; span = per trigger_regex match" },
                    "trigger_regex": { "type": ["string", "null"], "description": "Fast-find regex; gates full mode, REQUIRED span finder in span mode" },
                    "rationale": { "type": "string", "description": "Why this is safe for the target models/clients" },
                    "model_filter": { "type": ["string", "null"], "description": "Comma-separated model aliases, or null for all" },
                    "app_filter": { "type": ["string", "null"], "description": "Comma-separated app_ids, or null for all" }
                },
                "required": ["name", "description", "source", "phase", "scope", "rationale"]
            }
        }));
        required.push("proposed_programs");
    }

    if has_labels {
        properties.insert("session_labels".to_string(), serde_json::json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "session_index": { "type": "integer", "description": "S-index of the CHILD session — the integer N from `S<N>` in the cluster listing. NEVER a UUID." },
                    "label_type": { "type": "string", "enum": ["parent_session_id"] },
                    "parent_session_index": { "type": "integer", "description": "S-index of the PARENT session — the integer N from `S<N>`. NEVER a UUID." },
                    "confidence": { "type": "string", "enum": ["high", "medium"] },
                    "note": { "type": "string", "description": "Brief explanation" },
                    "spawn_turn": { "type": ["integer", "null"], "description": "Turn in parent where child was spawned, or null" },
                    "parent_spawn_point_index": { "type": ["integer", "null"], "description": "Index P from the parent's `Detected spawn points` list ([P0], [P1]…) whose prompt preview matches this child's first message. Set it ONLY to confirm a listed spawn call; null if none matches." }
                },
                "required": ["session_index", "label_type", "parent_session_index", "confidence", "note"]
            }
        }));
        required.push("session_labels");
    }

    if has_tool_rules {
        // Unified rule shape: phase × scope × match[] × action. One rule
        // = one place it fires, one set of conditions, one action.
        properties.insert("proposed_tool_rules".to_string(), serde_json::json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Stable short uppercase code, unique vs built-ins (see the tool-rules snippet)"
                    },
                    "title": { "type": "string", "description": "Short operator-facing label (≤60 chars)" },
                    "description": { "type": "string", "description": "One-sentence operator-facing explanation" },
                    "risk": {
                        "type": "string",
                        "enum": ["danger", "caution", "safe"]
                    },
                    "phase": {
                        "type": "string",
                        "enum": ["request", "response"]
                    },
                    "scope": {
                        "type": "string",
                        "enum": ["tool_definitions", "tool_results", "tool_calls", "resource_reads", "prompt_invocations"],
                        "description": "Pick a valid phase × scope × action combination from the snippet's matrix"
                    },
                    "match": {
                        "type": "array",
                        "description": "AND-of-conditions; valid targets/ops per scope are in the tool-rules snippet",
                        "items": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "tool_id | resource_id | prompt_id | any_arg | arg.<field> | content | uri (per scope)"
                                },
                                "op": {
                                    "type": "string",
                                    "enum": ["glob", "contains_any", "contains_word_any", "regex", "equals", "in", "detector"]
                                },
                                "value": {
                                    "description": format!(
                                        "String for glob/regex/equals; array of strings for contains_any/contains_word_any/in; one of {} for detector",
                                        streamscope_core::config::tool_rules_detectors::detector_names().join(" | ")
                                    )
                                }
                            },
                            "required": ["target", "op", "value"]
                        }
                    },
                    "action": {
                        "type": "object",
                        "description": "Tagged by `kind`; extra fields per kind are in the tool-rules snippet",
                        "properties": {
                            "kind": { "type": "string", "enum": ["classify", "block", "replace", "substitute", "intercept_only"] },
                            "regex": { "type": ["string", "null"], "description": "replace: per-match regex" },
                            "with": { "description": "replace: replacement string; substitute: the new tool definition" },
                            "drop": { "type": "boolean", "description": "replace: rewrite to empty" },
                            "intercept": {
                                "type": "object",
                                "description": "substitute: response-side handler binding",
                                "properties": {
                                    "type": { "type": "string", "enum": ["web_executor"] },
                                    "kind": { "type": "string", "enum": ["search", "fetch"] }
                                },
                                "required": ["type", "kind"]
                            },
                            "handler": {
                                "type": "object",
                                "description": "intercept_only: response-side handler binding",
                                "properties": {
                                    "type": { "type": "string", "enum": ["web_executor"] },
                                    "kind": { "type": "string", "enum": ["search", "fetch"] }
                                },
                                "required": ["type", "kind"]
                            }
                        },
                        "required": ["kind"]
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Sort key, lower wins, default 100"
                    },
                    "model_filter": {
                        "type": ["string", "null"],
                        "description": "Pipe-separated glob over the upstream model name, or null"
                    },
                    "app_filter": {
                        "type": ["string", "null"],
                        "description": "Pipe-separated glob over the calling app_id, or null"
                    },
                    "mcp_server_filter": {
                        "type": ["string", "null"],
                        "description": "Pipe-separated glob over the mcp_server slug, or null"
                    },
                    "rationale": { "type": "string", "description": "Why this rule should exist; cited from the analysed traffic" },
                    "framework_refs": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Ids from the supplied framework pack that this rule maps to; empty otherwise"
                    }
                },
                "required": ["id", "title", "risk", "phase", "scope", "match", "action", "rationale"]
            }
        }));
        required.push("proposed_tool_rules");
    }

    if has_field_profiles {
        // A field profile maps a wire (tool, arg) → canonical (tool_id, field)
        // + normaliser, so `arg.<field>` / `tool_id` tool-policy rules can
        // target the tool uniformly across clients. Propose these for the
        // high-occurrence UNCOVERED fields surfaced in the Field-Profile
        // Coverage section of the tool inventory.
        properties.insert("proposed_field_profiles".to_string(), serde_json::json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": { "type": ["string", "null"], "description": "Optional stable `TFP-`/`CUSTOM-` id; auto-generated if omitted" },
                    "tool_id": { "type": "string", "description": "Canonical concept id (`shell_exec`, `read_file`, …); use `_`" },
                    "tool_pattern": { "type": "string", "description": "Pipe-separated case-insensitive glob over the wire tool name" },
                    "field": { "type": "string", "description": "Canonical arg name (no `arg.` prefix)" },
                    "wire_field": { "type": ["string", "null"], "description": "Actual wire arg key when it differs from `field`" },
                    "normalizer": { "type": "string", "enum": streamscope_core::config::tool_rules_normalize::Normalizer::ALL.map(|n| n.as_str()), "description": "Canonicaliser applied before matching (see the field-profile snippet)" },
                    "app_filter": { "type": ["string", "null"], "description": "Pipe-separated glob over app_id; exclusive with mcp_server/server_type" },
                    "mcp_server": { "type": ["string", "null"], "description": "MCP server slug for `mcp__<server>__<tool>` tools; exclusive with app_filter/server_type" },
                    "server_type": { "type": ["string", "null"], "description": "Native server-tool tag; exclusive with app_filter/mcp_server" },
                    "description": { "type": ["string", "null"], "description": "Short human-readable label" },
                    "priority": { "type": ["integer", "null"], "description": "Sort key on overlapping matches, lower wins, default 100" },
                    "rationale": { "type": "string", "description": "Why this profile is needed — cite the uncovered (tool, field) pair" }
                },
                "required": ["tool_id", "tool_pattern", "field", "normalizer", "rationale"]
            }
        }));
        required.push("proposed_field_profiles");
    }

    // --- Conditionally present fields ---

    let has_alert = output_types.iter().any(|t| t == "alert");
    let has_memory = output_types.iter().any(|t| t == "memory");

    if has_alert {
        if cluster_alerts {
            // Cluster path, single-session outlier channel: an alert here targets
            // ONE session that is itself a behavioral outlier. It names the session
            // by its integer S-index — never a UUID (the model transcribes UUIDs
            // wrong). A finding that spans MULTIPLE sessions goes to
            // `cross_session_issues` instead.
            properties.insert("session_alerts".to_string(), serde_json::json!({
                "type": "array",
                "description": "Alerts for a SINGLE session that is itself a behavioral outlier. Name the session by its integer S-index (the N in `S<N>` from the cluster listing) — NEVER a UUID. For a pattern spanning multiple sessions use cross_session_issues. Empty array when nothing warrants one.",
                "items": {
                    "type": "object",
                    "properties": {
                        "session_index": { "type": "integer", "description": "S-index of the session — the integer N from `S<N>` in the cluster listing." },
                        "level": { "type": "string", "enum": ["info", "minor", "major"] },
                        "note": { "type": "string", "description": "Brief reason for the alert." }
                    },
                    "required": ["session_index", "level", "note"]
                }
            }));
            required.push("session_alerts");
            // Cross-session issue channel: a finding that spans MULTIPLE sessions
            // (a cross-session pattern, coordinated behavior, baseline drift). Names
            // every session it touches by S-index; lands as a first-class relation
            // linking those sessions, not on one session's alert.
            properties.insert("cross_session_issues".to_string(), serde_json::json!({
                "type": "array",
                "description": "Findings spanning MULTIPLE sessions. List every session the pattern touches by its integer S-index. Empty array when none.",
                "items": {
                    "type": "object",
                    "properties": {
                        "source_session_indices": { "type": "array", "items": { "type": "integer" }, "description": "S-indices of the sessions this issue spans (the N in `S<N>`)." },
                        "level": { "type": "string", "enum": ["info", "minor", "major"] },
                        "note": { "type": "string", "description": "What the cross-session pattern is." }
                    },
                    "required": ["source_session_indices", "level", "note"]
                }
            }));
            required.push("cross_session_issues");
        } else {
            properties.insert("alert_level".to_string(), serde_json::json!({
                "type": ["string", "null"],
                "enum": ["info", "minor", "major", null],
                "description": "Session alert severity (see the alert snippet); null when no annotation applies"
            }));
            properties.insert("alert_note".to_string(), serde_json::json!({
                "type": ["string", "null"],
                "description": "Brief reason for the alert, or null"
            }));
            required.push("alert_level");
            required.push("alert_note");
        }
    }

    if has_memory {
        properties.insert("memory_update".to_string(), serde_json::json!({
            "type": "string",
            "description": "Full replacement of THIS axis's own memory section (never another axis's); empty string = keep current"
        }));
    }

    (properties, required)
}

/// Parse the LLM response — extract from `tool_calls[0].function.arguments`.
/// Returns an error if the model didn't call the tool (will be retried next cycle).
fn parse_analysis_response(response: &serde_json::Value, axis: &str) -> anyhow::Result<serde_json::Value> {
    let args_str = response
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("tool_calls"))
        .and_then(|tc| tc.as_array())
        .and_then(|tc| tc.first())
        .and_then(|tc| tc.get("function"))
        .and_then(|f| f.get("arguments"))
        .and_then(|a| a.as_str());

    match args_str {
        Some(s) => {
            let mut v: serde_json::Value = serde_json::from_str(s)
                .map_err(|e| anyhow::anyhow!("failed to parse tool_calls arguments: {e}"))?;
            // Every field of the analysis is stored (suggestions, alert notes,
            // memory, notifications), and a model — steered by the content it
            // reads — can emit U+0000, which Postgres refuses; one would drop
            // the rows after it and re-run a paid inventory call every cycle.
            streamscope_core::pg_text::scrub_nul_json(&mut v);
            tracing::debug!(axis, "parsed analysis from tool_calls");
            Ok(v)
        }
        None => {
            let finish_reason = response
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|c| c.first())
                .and_then(|c| c.get("finish_reason"))
                .and_then(|f| f.as_str())
                .unwrap_or("unknown");
            anyhow::bail!("no tool_calls in response (finish_reason: {finish_reason})")
        }
    }
}


/// Parse one axis's payload fields (findings / programs / tool rules / labels
/// / memory), gated by the axis's `output_types`. The alert channel is
/// path-specific and parsed separately (`parse_and_write_session_alert` /
/// `extract_session_alerts`), so `alert` is returned as `None`.
/// Parse the fields common to session- and cluster-path axes. `s_index` is the
/// cluster's ordered id map (`render_cluster`); it resolves the S-index refs on
/// `session_labels` to real session UUIDs. `spawn_points[i]` (parallel to
/// `s_index`) is the detected spawn points printed under `S{i}` — used to resolve
/// a confirmed `parent_spawn_point_index` to an exact anchor. On the session path
/// there are no labels, so callers pass `&[]` for both.
fn parse_axis_fields(
    parsed: &serde_json::Value,
    output_types: &[String],
    s_index: &[uuid::Uuid],
    spawn_points: &[Vec<crate::conversation::DetectedSpawnPoint>],
) -> SessionAnalysisResult {
    let findings: Vec<Finding> = parsed
        .get("findings")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| {
                    Some(Finding {
                        severity: f.get("severity")?.as_str()?.to_string(),
                        category: f.get("category")?.as_str()?.to_string(),
                        description: f.get("description")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let programs: Vec<ProposedProgram> = parsed
        .get("proposed_programs")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    Some(ProposedProgram {
                        name: p.get("name")?.as_str()?.to_string(),
                        description: p.get("description")?.as_str()?.to_string(),
                        source: p.get("source")?.as_str()?.to_string(),
                        phase: p.get("phase")?.as_str().unwrap_or("request").to_string(),
                        scope: p.get("scope")?.as_str().unwrap_or("global").to_string(),
                        rationale: p.get("rationale")?.as_str()?.to_string(),
                        model_filter: p.get("model_filter").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        app_filter: p.get("app_filter").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        trigger_regex: p.get("trigger_regex").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        match_mode: p.get("match_mode").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Delegate to ProposedToolRule's Deserialize impl. Logging on failure
    // preserves single-bad-entry tolerance.
    let tool_rules: Vec<super::suggestion::ProposedToolRule> = parsed
        .get("proposed_tool_rules")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    serde_json::from_value::<super::suggestion::ProposedToolRule>(r.clone())
                        .map_err(|e| {
                            tracing::warn!(error = %e, raw = %r, "skipping malformed proposed_tool_rule");
                        })
                        .ok()
                })
                .collect()
        })
        .unwrap_or_default();

    // Session labels reference the child + parent by S-index; resolve each
    // against `s_index` to a real UUID (out-of-range → drop the label, warn).
    // The model never hand-copies a UUID here.
    let resolve = |v: &serde_json::Value, key: &str| -> Option<String> {
        let idx = v.get(key)?.as_u64()? as usize;
        match s_index.get(idx) {
            Some(id) => Some(id.to_string()),
            None => {
                tracing::warn!(key, idx, len = s_index.len(), "dropping session label with out-of-range S-index");
                None
            }
        }
    };
    let session_labels: Vec<super::suggestion::SessionLabel> = parsed
        .get("session_labels")
        .and_then(|l| l.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|l| {
                    let session_id = resolve(l, "session_index")?;
                    let label_type = l.get("label_type")?.as_str()?.to_string();
                    let label_value = resolve(l, "parent_session_index")?;
                    // Resolve an optional CONFIRMED spawn point against the PARENT
                    // session's detected list. On a match the code-detected turn
                    // OVERRIDES the model's spawn_turn estimate (the off-by-one this
                    // fixes) and the exact tool-call id anchors the child card; with
                    // no match, keep the model's estimate and no id.
                    let parent_pts = l
                        .get("parent_session_index")
                        .and_then(|v| v.as_u64())
                        .and_then(|pi| spawn_points.get(pi as usize));
                    let matched = l
                        .get("parent_spawn_point_index")
                        .and_then(|v| v.as_u64())
                        .and_then(|sp| parent_pts.and_then(|pts| pts.get(sp as usize)));
                    let (spawn_turn, spawn_tool_call_id) = match matched {
                        Some(p) => (Some(p.turn_number), Some(p.tool_call_id.clone())),
                        None => (
                            l.get("spawn_turn").and_then(|t| t.as_i64()).map(|t| t as i32),
                            None,
                        ),
                    };
                    Some(super::suggestion::SessionLabel {
                        session_id,
                        label_type,
                        label_value,
                        confidence: l.get("confidence").and_then(|c| c.as_str()).unwrap_or("medium").to_string(),
                        note: l.get("note").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                        spawn_turn,
                        spawn_tool_call_id,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let memory_update = if output_types.iter().any(|t| t == "memory") {
        parsed
            .get("memory_update")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };

    SessionAnalysisResult {
        findings,
        programs,
        tool_rules,
        session_labels,
        alert: None,
        memory_update,
    }
}

/// Parse the scalar session-path alert for one axis and write it immediately.
/// Drops content-less `info` alerts, warns on empty `minor`/`major`. Returns the
/// written `(level, note)` when one landed. (A session-path alert is about the one
/// session being judged — it names no other session, so there is no cross-session
/// reference to sanitize; genuine cross-session findings ride the cluster path's
/// `cross_session_issues[]`.)
async fn parse_and_write_session_alert(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    session_id: &str,
    axis: &str,
    parsed: &serde_json::Value,
    output_types: &[String],
) -> Option<(String, String)> {
    if !output_types.iter().any(|t| t == "alert") {
        return None;
    }

    let alert_level = parsed.get("alert_level").and_then(|l| l.as_str()).unwrap_or("");
    let alert_note_raw = parsed.get("alert_note").and_then(|n| n.as_str()).unwrap_or("");

    let alert_note_clean = sanitize_alert_note(alert_note_raw);

    if alert_level != "info" && alert_level != "minor" && alert_level != "major" {
        return None;
    }

    let trimmed_empty = alert_note_clean.trim().is_empty();
    if trimmed_empty && alert_level == "info" {
        tracing::debug!(axis, session_id, "skipping content-less info alert");
        return None;
    }
    if trimmed_empty {
        tracing::warn!(axis, session_id, level = %alert_level, "alert emitted without note — agent should describe");
    }

    write_session_alert(pool, tenant_id, session_id, axis, alert_level, &alert_note_clean).await;
    Some((alert_level.to_string(), alert_note_clean))
}

/// Extract the cluster-path `session_alerts[]` channel for one axis (a SINGLE
/// session that is itself a behavioral outlier): validate the level, sanitize
/// the note, and resolve the model's `session_index` against the cluster's
/// ordered id map — an out-of-range index is dropped, so a bad ref can't reach a
/// session the axis never saw. Content-less `info` entries are dropped at source.
fn extract_session_alerts(
    parsed: &serde_json::Value,
    axis: &str,
    s_index: &[uuid::Uuid],
) -> Vec<(String, String, String)> {
    let mut alerts = Vec::new();
    let Some(arr) = parsed.get("session_alerts").and_then(|a| a.as_array()) else {
        return alerts;
    };

    for entry in arr {
        let Some(idx) = entry.get("session_index").and_then(|s| s.as_u64()) else { continue };
        let level = entry.get("level").and_then(|l| l.as_str()).unwrap_or("");
        let note_raw = entry.get("note").and_then(|n| n.as_str()).unwrap_or("");

        if level != "info" && level != "minor" && level != "major" {
            continue;
        }
        let Some(sid) = s_index.get(idx as usize) else {
            tracing::warn!(axis, idx, len = s_index.len(), "dropping session alert with out-of-range S-index");
            continue;
        };

        let note = sanitize_alert_note(note_raw);
        if note.trim().is_empty() {
            if level == "info" {
                tracing::debug!(axis, session_id = %sid, "skipping content-less info alert");
                continue;
            }
            tracing::warn!(axis, session_id = %sid, level, "alert emitted without note — agent should describe");
        }

        alerts.push((sid.to_string(), level.to_string(), note));
    }

    alerts
}

/// Extract the cluster-path `cross_session_issues[]` channel for one axis: a
/// finding spanning MULTIPLE sessions, whose members are named by S-index and
/// resolved against the cluster's ordered id map. Out-of-range indices are
/// dropped; an issue with no resolvable member is dropped whole. Returns
/// `(level, note, source_session_ids)`.
fn extract_cross_session_issues(
    parsed: &serde_json::Value,
    axis: &str,
    s_index: &[uuid::Uuid],
) -> Vec<(String, String, Vec<uuid::Uuid>)> {
    let mut issues = Vec::new();
    let Some(arr) = parsed.get("cross_session_issues").and_then(|a| a.as_array()) else {
        return issues;
    };

    for entry in arr {
        let level = entry.get("level").and_then(|l| l.as_str()).unwrap_or("");
        if level != "info" && level != "minor" && level != "major" {
            continue;
        }
        let note = sanitize_alert_note(entry.get("note").and_then(|n| n.as_str()).unwrap_or(""));
        if note.trim().is_empty() {
            tracing::warn!(axis, level, "dropping cross-session issue without a note");
            continue;
        }
        let mut ids: Vec<uuid::Uuid> = Vec::new();
        if let Some(idxs) = entry.get("source_session_indices").and_then(|a| a.as_array()) {
            for v in idxs {
                let Some(i) = v.as_u64() else { continue };
                match s_index.get(i as usize) {
                    Some(id) if !ids.contains(id) => ids.push(*id),
                    Some(_) => {}
                    None => tracing::warn!(axis, idx = i, len = s_index.len(), "dropping out-of-range S-index in cross-session issue"),
                }
            }
        }
        if ids.is_empty() {
            tracing::warn!(axis, "dropping cross-session issue with no resolvable member sessions");
            continue;
        }
        issues.push((level.to_string(), note, ids));
    }

    issues
}

/// `max_tokens` for an analysis call answering `n_axes` axes at once, bounded
/// by the model's resolved output cap (`COALESCE(model → catalog)`) so the
/// request never asks for more than the upstream can emit — an over-ask is a
/// hard 400 on some providers. A model preset on the route can still override
/// the wire value (preset wins post-translation).
fn merged_max_tokens(n_axes: usize, model_max_output: Option<i32>) -> usize {
    let asked = (16_384 + 2_048 * n_axes.saturating_sub(1)).min(21_333);
    match model_max_output {
        Some(cap) if cap > 0 => asked.min(cap as usize),
        _ => asked,
    }
}

/// Append the shared context tail — active programs, per-member memory, and
/// per-member rejected suggestions — to a pooled call's user message.
fn push_group_context_tail(
    context: &mut String,
    members: &[&ExpertWithProgress],
    rejected: &[&[String]],
    active_programs: &[String],
) {
    if !active_programs.is_empty() {
        context.push_str("## Currently Active Transform Programs\n\n");
        let programs_text = active_programs.join("\n");
        let capped = if programs_text.len() > PROGRAMS_BUDGET {
            format!("{}...[truncated]", safe_truncate(&programs_text, PROGRAMS_BUDGET))
        } else {
            programs_text
        };
        context.push_str(&capped);
        context.push_str("\nDo NOT propose programs that duplicate existing ones.\n");
    }

    // Each member's memory renders at the FULL solo budget — `memory_update`
    // is a full replacement, so a truncated view would erode the axis's
    // memory a slice at a time (the model rewrites only what it can see).
    // MEMORY_BUDGET == MEMORY_CAP keeps the round-trip lossless.
    for m in members {
        if m.input_types.iter().any(|t| t == "memory") && !m.memory.is_empty() {
            context.push_str(&format!("\n## Your Memory ({})\n\n", m.expert.axis));
            let capped = if m.memory.len() > MEMORY_BUDGET {
                format!("{}...[truncated]", safe_truncate(&m.memory, MEMORY_BUDGET))
            } else {
                m.memory.clone()
            };
            context.push_str(&capped);
            context.push_str("\n\n");
        }
    }

    let rejected_cap = REJECTED_BUDGET / members.len().max(1);
    for (m, rej) in members.iter().zip(rejected) {
        if rej.is_empty() {
            continue;
        }
        context.push_str(&format!("## Previously Rejected Suggestions ({})\n\n", m.expert.axis));
        context.push_str("The following proposals were rejected by the admin. Do NOT re-propose them:\n");
        let rejected_text: String = rej.iter().map(|t| format!("- {t}\n")).collect();
        let capped = if rejected_text.len() > rejected_cap {
            format!("{}...[truncated]", safe_truncate(&rejected_text, rejected_cap))
        } else {
            rejected_text
        };
        context.push_str(&capped);
        context.push('\n');
    }
}

/// Fixed context cost of a pooled call (everything except the session /
/// cluster rendering): wrapper + tool schema allowance, the merged system
/// prompt, and the capped memory / programs / rejected sections.
fn group_fixed_cost(
    system_prompt_len: usize,
    members: &[&ExpertWithProgress],
    rejected: &[&[String]],
    active_programs: &[String],
) -> usize {
    let memory_chars: usize = members
        .iter()
        .filter(|m| m.input_types.iter().any(|t| t == "memory"))
        .map(|m| m.memory.len().min(MEMORY_BUDGET))
        .sum();
    let programs_chars = active_programs.join("\n").len().min(PROGRAMS_BUDGET);
    let rejected_cap = REJECTED_BUDGET / members.len().max(1);
    let rejected_chars: usize = rejected
        .iter()
        .map(|r| r.iter().map(|t| t.len() + 3).sum::<usize>().min(rejected_cap))
        .sum();

    FIXED_OVERHEAD + system_prompt_len + memory_chars + programs_chars + rejected_chars
}

/// Analyze one session with a single pooled LLM call answering every member
/// axis. Returns per-member outcomes aligned with `members`: `Answered` for
/// axes present in the payload, `Missing` for omitted ones (partial accept —
/// only the omitted axis's watermark holds). Alerts are written immediately,
/// per axis, exactly like the solo path.
#[allow(clippy::too_many_arguments)]
async fn analyze_session_merged(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    client: &reqwest::Client,
    config: &AgentConfig,
    routing: &AgentRouting,
    system_prompt: &str,
    members: &[&ExpertWithProgress],
    rejected: &[&[String]],
    session: &SessionMeta,
    active_programs: &[String],
) -> anyhow::Result<Vec<AxisOutcome<SessionAnalysisResult>>> {
    let fixed_cost = group_fixed_cost(system_prompt.len(), members, rejected, active_programs);
    let session_budget = routing.context_budget.saturating_sub(fixed_cost);

    let conversation = fetch_conversation_via_db(pool, tenant_id, session.session_id).await?;
    let rendered = render_session(session, &conversation, session_budget);

    let mut context = format!("Analyze this LLM session:\n\n{rendered}");
    push_group_context_tail(&mut context, members, rejected, active_programs);

    // Frameworks ride when any member declares them.
    let wants_frameworks: Vec<String> = if members
        .iter()
        .any(|m| m.input_types.iter().any(|t| t == "security_frameworks"))
    {
        vec!["security_frameworks".to_string()]
    } else {
        Vec::new()
    };
    inject_security_frameworks(&mut context, &wants_frameworks);

    let axes: Vec<(&str, &[String])> = members
        .iter()
        .map(|m| (m.expert.axis.as_str(), m.output_types.as_slice()))
        .collect();

    tracing::debug!(
        axes = ?axes.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
        session_id = %session.session_id,
        context_len = context.len(),
        "analyzing session (pooled)"
    );

    let body = serde_json::json!({
        "model": routing.alias,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": context}
        ],
        "max_tokens": routing.max_tokens(members.len()),
        "tools": [analysis_tool_definition_for_group(&axes, false)],
        "tool_choice": super::AGENT_TOOL_CHOICE
    });

    let response = agent_analysis_call(client, config, body, routing.call_timeout()).await?;
    let parsed = parse_analysis_response(&response, "pooled").map_err(deterministic)?;

    // A payload without the `axes` wrapper recurs every cycle for this session
    // — tag deterministic so the batch skips it rather than holding.
    let Some(axes_obj) = parsed.get("axes").and_then(|a| a.as_object()) else {
        return Err(deterministic(anyhow::anyhow!(
            "pooled analysis response carries no `axes` object"
        )));
    };

    let mut outcomes = Vec::with_capacity(members.len());
    for m in members {
        let axis = &m.expert.axis;
        let Some(axis_payload) = axes_obj.get(axis) else {
            tracing::warn!(
                axis = %axis,
                session_id = %session.session_id,
                "pooled response omitted a mandatory axis — holding it for retry"
            );
            outcomes.push(AxisOutcome::Missing);
            continue;
        };

        let mut result = parse_axis_fields(axis_payload, &m.output_types, &[], &[]);
        result.alert = parse_and_write_session_alert(
            pool,
            tenant_id,
            &session.session_id.to_string(),
            axis,
            axis_payload,
            &m.output_types,
        )
        .await;

        tracing::info!(
            axis = %axis,
            session_id = %session.session_id,
            findings = result.findings.len(),
            programs = result.programs.len(),
            tool_rules = result.tool_rules.len(),
            labels = result.session_labels.len(),
            has_alert = result.alert.is_some(),
            has_memory_update = !result.memory_update.is_empty(),
            "session analysis complete (pooled)"
        );
        outcomes.push(AxisOutcome::Answered(Box::new(result)));
    }

    Ok(outcomes)
}

/// Analyze one cluster with a single pooled LLM call answering every member
/// axis. Mirrors [`analyze_session_merged`] on the cluster path: alerts ride
/// the session-targeted `session_alerts[]` channel, labels are parsed only for
/// axes that declare them, and an omitted axis returns `Missing`.
#[allow(clippy::too_many_arguments)]
async fn analyze_cluster_merged(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
    client: &reqwest::Client,
    config: &AgentConfig,
    routing: &AgentRouting,
    system_prompt: &str,
    members: &[&ExpertWithProgress],
    rejected: &[&[String]],
    sessions: &[&SessionMeta],
    active_programs: &[String],
    key_id: &uuid::Uuid,
    app_id: &str,
) -> anyhow::Result<Vec<AxisOutcome<ClusterAnalysisResult>>> {
    let fixed_cost = group_fixed_cost(system_prompt.len(), members, rejected, active_programs);
    let cluster_budget = routing.context_budget.saturating_sub(fixed_cost);

    let (cluster_text, cidx) =
        render_cluster(pool, tenant_id, sessions, cluster_budget, key_id, app_id).await?;
    let mut context = format!("Analyze this session cluster:\n\n{cluster_text}");
    push_group_context_tail(&mut context, members, rejected, active_programs);

    let wants_frameworks: Vec<String> = if members
        .iter()
        .any(|m| m.input_types.iter().any(|t| t == "security_frameworks"))
    {
        vec!["security_frameworks".to_string()]
    } else {
        Vec::new()
    };
    inject_security_frameworks(&mut context, &wants_frameworks);

    let axes: Vec<(&str, &[String])> = members
        .iter()
        .map(|m| (m.expert.axis.as_str(), m.output_types.as_slice()))
        .collect();

    tracing::debug!(
        axes = ?axes.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
        key_id = %key_id,
        app_id,
        sessions = sessions.len(),
        context_len = context.len(),
        "analyzing session cluster (pooled)"
    );

    let body = serde_json::json!({
        "model": routing.alias,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": context}
        ],
        "max_tokens": routing.max_tokens(members.len()),
        "tools": [analysis_tool_definition_for_group(&axes, true)],
        "tool_choice": super::AGENT_TOOL_CHOICE
    });

    let response = agent_analysis_call(client, config, body, routing.call_timeout()).await?;
    let parsed = parse_analysis_response(&response, "pooled")?;

    let Some(axes_obj) = parsed.get("axes").and_then(|a| a.as_object()) else {
        anyhow::bail!("pooled cluster analysis response carries no `axes` object");
    };

    let mut outcomes = Vec::with_capacity(members.len());
    for m in members {
        let axis = &m.expert.axis;
        let Some(axis_payload) = axes_obj.get(axis) else {
            tracing::warn!(
                axis = %axis,
                key_id = %key_id,
                "pooled cluster response omitted a mandatory axis — holding it for retry"
            );
            outcomes.push(AxisOutcome::Missing);
            continue;
        };

        let fields = parse_axis_fields(axis_payload, &m.output_types, &cidx.s_index, &cidx.spawn_points);
        let (alerts, cross_session_issues) = if m.output_types.iter().any(|t| t == "alert") {
            (
                extract_session_alerts(axis_payload, axis, &cidx.s_index),
                extract_cross_session_issues(axis_payload, axis, &cidx.s_index),
            )
        } else {
            (Vec::new(), Vec::new())
        };

        tracing::info!(
            axis = %axis,
            key_id = %key_id,
            app_id,
            labels = fields.session_labels.len(),
            programs = fields.programs.len(),
            tool_rules = fields.tool_rules.len(),
            alerts = alerts.len(),
            cross_issues = cross_session_issues.len(),
            "cluster analysis complete (pooled)"
        );

        outcomes.push(AxisOutcome::Answered(Box::new(ClusterAnalysisResult {
            session_labels: fields.session_labels,
            programs: fields.programs,
            tool_rules: fields.tool_rules,
            findings: fields.findings,
            alerts,
            cross_session_issues,
            memory_update: fields.memory_update,
        })));
    }

    Ok(outcomes)
}

/// Update expert memory in DB.
async fn update_expert_memory(pool: &crate::db::Db, tenant_id: uuid::Uuid, expert_id: uuid::Uuid, memory: &str) {
    let Ok(mut db) = TenantConn::acquire(pool, TenantId::from_row(tenant_id)).await else {
        return;
    };
    if let Err(e) = sqlx::query(
        "UPDATE agent_experts SET memory = $2, updated_at = now() WHERE id = $1",
    )
    .bind(expert_id)
    .bind(memory)
    .execute(db.conn())
    .await
    {
        tracing::error!(%expert_id, "agent expert memory update failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A proxy that refuses the first call with 429 (and `retry_after`, if
    /// any) and answers the second; returns its URL and when each call came.
    async fn refusing_proxy(retry_after: Option<&'static str>) -> (String, std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = calls.clone();
        tokio::spawn(async move {
            for n in 0..2 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                seen.lock().unwrap().push(std::time::Instant::now());
                let reply = if n == 0 {
                    let hint = retry_after.map(|v| format!("retry-after: {v}\r\n")).unwrap_or_default();
                    format!("HTTP/1.1 429 Too Many Requests\r\n{hint}content-length: 2\r\nconnection: close\r\n\r\n{{}}")
                } else {
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".to_string()
                };
                let _ = sock.write_all(reply.as_bytes()).await;
            }
        });
        (format!("http://{addr}"), calls)
    }

    fn proxy_config(proxy_url: String) -> AgentConfig {
        AgentConfig {
            proxy_url,
            api_key: "ak-test".into(),
            app_id: "agent".into(),
            interval_secs: 60,
            session_cooldown_mins: 0,
            run_window: None,
        }
    }

    async fn retry_gap(retry_after: Option<&'static str>, timeout: std::time::Duration) -> std::time::Duration {
        let (url, calls) = refusing_proxy(retry_after).await;
        let client = reqwest::Client::new();
        agent_proxy_call(&client, &proxy_config(url), &serde_json::json!({}), timeout)
            .await
            .expect("the retry is answered");
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        calls[1] - calls[0]
    }

    #[tokio::test]
    async fn a_refused_agent_call_waits_as_long_as_the_proxy_says() {
        let gap = retry_gap(Some("2"), std::time::Duration::from_secs(30)).await;
        assert!(gap >= std::time::Duration::from_secs(2), "retried after {gap:?}");
    }

    #[tokio::test]
    async fn a_refusal_without_a_hint_keeps_the_ordinary_backoff() {
        let gap = retry_gap(None, std::time::Duration::from_secs(30)).await;
        // The ordinary backoff, not a stall; which wait is chosen is held exactly
        // by `a_wait_longer_than_one_call_may_take_is_not_retried`.
        assert!(gap >= std::time::Duration::from_secs(1) && gap < std::time::Duration::from_secs(5), "retried after {gap:?}");
    }

    #[test]
    fn a_wait_longer_than_one_call_may_take_is_not_retried() {
        let hint = |value: &str| {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::RETRY_AFTER, value.parse().unwrap());
            headers
        };
        let call = std::time::Duration::from_secs(30);
        let (long, short) = (hint("120"), hint("30"));
        let wait = |status, headers| agent_retry_backoff(status, headers, 1, call);
        assert_eq!(wait(reqwest::StatusCode::TOO_MANY_REQUESTS, &long), None);
        // The boundary's near side: a hint of exactly one call is waited.
        assert_eq!(wait(reqwest::StatusCode::TOO_MANY_REQUESTS, &short), Some(call));
        // Only a 429's hint is read: a 503's is an upstream's, already honoured by the proxy.
        assert_eq!(wait(reqwest::StatusCode::SERVICE_UNAVAILABLE, &long), Some(std::time::Duration::from_secs(1)));
    }

    fn ts(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn watermark_holds_when_oldest_session_transiently_fails() {
        // Batch oldest-first [ts1=transient-fail, ts2=ok, ts3=ok]: oldest held →
        // no advance and nothing counted, so ts1 is retried next cycle.
        let success = vec![ts(2), ts(3)];
        let advanceable = success.clone();
        let (wm, covered) = contiguous_watermark(&advanceable, &success, Some(ts(1)));
        assert_eq!(wm, None);
        assert_eq!(covered, 0);
    }

    #[test]
    fn watermark_advances_to_contiguous_prefix_on_mid_transient_failure() {
        // [ts1=ok, ts2=transient-fail, ts3=ok]: advance only to ts1; ts2 (held)
        // and ts3 (success beyond the held failure) are retried next cycle.
        let success = vec![ts(1), ts(3)];
        let advanceable = success.clone();
        let (wm, covered) = contiguous_watermark(&advanceable, &success, Some(ts(2)));
        assert_eq!(wm, Some(ts(1)));
        assert_eq!(covered, 1);
    }

    #[test]
    fn watermark_covers_whole_batch_when_all_succeed() {
        let success = vec![ts(1), ts(2), ts(3)];
        let (wm, covered) = contiguous_watermark(&success, &success, None);
        assert_eq!(wm, Some(ts(3)));
        assert_eq!(covered, 3);
    }

    #[test]
    fn watermark_advances_past_deterministic_skip() {
        // [ts1=skip(deterministic), ts2=ok, ts3=ok]: the skip is advanceable, so
        // the watermark passes it (no stall) but only the 2 successes count.
        let success = vec![ts(2), ts(3)];
        let advanceable = vec![ts(1), ts(2), ts(3)];
        let (wm, covered) = contiguous_watermark(&advanceable, &success, None);
        assert_eq!(wm, Some(ts(3)));
        assert_eq!(covered, 2);
    }

    #[test]
    fn watermark_skip_then_hold_before_transient() {
        // [ts1=ok, ts2=skip, ts3=transient-fail, ts4=ok]: advance past the skip
        // to ts2, hold before ts3; only ts1 counts (ts4 is beyond the hold).
        let success = vec![ts(1), ts(4)];
        let advanceable = vec![ts(1), ts(2), ts(4)];
        let (wm, covered) = contiguous_watermark(&advanceable, &success, Some(ts(3)));
        assert_eq!(wm, Some(ts(2)));
        assert_eq!(covered, 1);
    }

    #[test]
    fn retry_status_classification() {
        use reqwest::StatusCode;
        assert!(status_is_retryable(StatusCode::TOO_MANY_REQUESTS));
        assert!(status_is_retryable(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(status_is_retryable(StatusCode::BAD_GATEWAY));
        assert!(!status_is_retryable(StatusCode::BAD_REQUEST));
        assert!(!status_is_retryable(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn deterministic_status_classification() {
        use reqwest::StatusCode;
        // Session-specific 4xx → skip.
        assert!(proxy_status_is_deterministic(StatusCode::BAD_REQUEST));
        assert!(proxy_status_is_deterministic(StatusCode::UNPROCESSABLE_ENTITY));
        assert!(proxy_status_is_deterministic(StatusCode::NOT_FOUND));
        // Auth/permission/throttle/time-based/server → transient (hold/retry).
        assert!(!proxy_status_is_deterministic(StatusCode::UNAUTHORIZED));
        assert!(!proxy_status_is_deterministic(StatusCode::FORBIDDEN));
        assert!(!proxy_status_is_deterministic(StatusCode::TOO_MANY_REQUESTS));
        assert!(!proxy_status_is_deterministic(StatusCode::REQUEST_TIMEOUT));
        assert!(!proxy_status_is_deterministic(StatusCode::TOO_EARLY));
        assert!(!proxy_status_is_deterministic(StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn deterministic_failure_is_detected_through_chain() {
        let det = deterministic(anyhow::anyhow!("bad shape"));
        assert!(is_deterministic_failure(&det));
        let plain = anyhow::anyhow!("connection reset");
        assert!(!is_deterministic_failure(&plain));
    }

    #[test]
    fn retry_budget_timeout_at_most_once() {
        // Timeout: only the first attempt may retry (at most one retry total).
        assert!(agent_retry_allowed(true, 1, 2));
        assert!(!agent_retry_allowed(true, 2, 2));
        // Connect / 429 / 5xx: up to max_retries attempts may retry.
        assert!(agent_retry_allowed(false, 1, 2));
        assert!(agent_retry_allowed(false, 2, 2));
        assert!(!agent_retry_allowed(false, 3, 2));
        // max_retries = 0 disables non-timeout retries.
        assert!(!agent_retry_allowed(false, 1, 0));
    }

    #[test]
    fn test_merge_memory_empty_update_keeps_existing() {
        let existing = "## Baselines\nNormal traffic.";
        assert_eq!(merge_memory(existing, ""), existing);
    }

    #[test]
    fn test_sanitize_alert_note_clean_passthrough() {
        let note = "[security:minor] PII detected in user message — PHONE_NUMBER\n[quality:info] Normal session.";
        assert_eq!(sanitize_alert_note(note), note);
    }

    #[test]
    fn test_sanitize_alert_note_collapses_repetition_loop() {
        // A weak model degenerated into a runaway repetition loop.
        let degenerate = format!("[security:minor] noticed {}done", "agentic-".repeat(500));
        let out = sanitize_alert_note(&degenerate);
        assert!(out.chars().count() <= 401, "line not capped: {}", out.chars().count());
        assert!(out.contains('…'), "repetition not collapsed: {out}");
        // The leading context survives; the wall of repeats does not.
        assert!(out.starts_with("[security:minor] noticed agentic-agentic-agentic"));
        assert!(!out.contains("agentic-agentic-agentic-agentic-agentic-agentic-agentic"));
    }

    #[test]
    fn test_sanitize_alert_note_caps_total_length_and_lines() {
        let many_lines = (0..100)
            .map(|i| format!("[quality:info] line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let out = sanitize_alert_note(&many_lines);
        assert!(out.lines().count() <= 24);
        assert!(out.chars().count() <= 3001);
    }

    #[test]
    fn test_collapse_repetition_preserves_short_lines() {
        let line = "[cost_efficiency:info] Simple task on gpt-4o.";
        assert_eq!(collapse_repetition(line), line);
    }

    #[test]
    fn test_collapse_repetition_preserves_legitimate_short_runs() {
        // A token count and a separator are short runs — must survive intact.
        let line = "[cost_efficiency:info] used 1000000 tokens over ------ the window here";
        assert_eq!(collapse_repetition(line), line);
    }

    #[test]
    fn test_collapse_repetition_utf8_unit() {
        // Repeated multi-byte unit must collapse on a char boundary, never panic.
        let line = format!("prefix {}suffix", "café-".repeat(40));
        let out = collapse_repetition(&line);
        assert!(out.contains('…'));
        assert!(out.starts_with("prefix café-café-café-"));
    }

    #[test]
    fn test_merge_memory_replaces_entirely() {
        let existing = "old memory content";
        let update = "## Baselines\nNew baseline data.";
        assert_eq!(merge_memory(existing, update), update);
    }

    #[test]
    fn test_merge_memory_truncates_oversized() {
        let update = "x\n".repeat(3000);
        let result = merge_memory("old", &update);
        assert!(result.len() <= MEMORY_CAP + 20);
        assert!(result.starts_with("[truncated]\n"));
    }

    #[test]
    fn test_render_session_with_events() {
        let meta = SessionMeta {
            session_id: uuid::Uuid::nil(),
            user_id: None,
            key_id: None,
            turn_count: 3,
            total_tokens: Some(5000),
            spend: Some(crate::routes::SpendTotal { currency: streamscope_core::pricing::Currency::USD, amount: 0.02 }),
            first_timestamp: None,
            last_timestamp: None,
            last_latency_ms: None,
            model_requested: None,
            model_used: Some("gpt-4o".to_string()),
            user_email: Some("user@test.com".to_string()),
            app_id: Some("claude-code".to_string()),
            first_user_prompt: Some("Hello world".to_string()),
        };
        let conv = serde_json::json!({
            "events": [
                {"type": "system_prompt", "content": "You are a helpful assistant.", "turn": 0},
                {"type": "message", "role": "user", "content": "Hello world", "turn": 0, "is_new": true},
                {"type": "message", "role": "assistant", "content": "Hi! How can I help?", "turn": 0, "is_new": true},
                {"type": "tool_call", "name": "bash", "arguments": {}, "id": "1", "turn": 1, "is_new": true},
                {"type": "tool_call", "name": "bash", "arguments": {}, "id": "2", "turn": 2, "is_new": true},
            ]
        });
        let result = render_session(&meta, &conv, 5000);
        assert!(result.contains("### System Prompt"));
        assert!(result.contains("helpful assistant"));
        assert!(result.contains("bash(2)"));
        assert!(result.contains("Hello world"));
        assert!(result.contains("Topic:"));
    }

    /// The session header states the spend in the currency it was booked in,
    /// and says so when no single figure states it; a call's line states its
    /// own — never a `$` that would mislabel a tenant keeping its books in
    /// another currency.
    #[test]
    fn a_rendered_session_names_its_spend_currency() {
        let meta = |spend| SessionMeta {
            session_id: uuid::Uuid::nil(),
            user_id: None,
            key_id: None,
            turn_count: 1,
            total_tokens: Some(10),
            spend,
            first_timestamp: None,
            last_timestamp: None,
            last_latency_ms: None,
            model_requested: None,
            model_used: Some("gpt-4o".to_string()),
            user_email: None,
            app_id: None,
            first_user_prompt: None,
        };
        // A charged media call, so its line's figure is rendered too.
        let conv = serde_json::json!({ "events": [{
            "type": "media_api_call",
            "turn": 0,
            "media_call": { "endpoint": "images", "model": "img-1", "input": [], "output": [] },
            "metadata": { "spend": { "currency": "USD", "amount": 0.25 } },
        }] });
        let eur = crate::routes::SpendTotal {
            currency: streamscope_core::pricing::Currency::parse("EUR").unwrap(),
            amount: 1.5,
        };
        let one = render_session(&meta(Some(eur)), &conv, 5000);
        assert!(one.contains("cost: 1.50 EUR)"), "{one}");
        // A call's own figure names its own currency, never the session's.
        assert!(one.contains("[images] (model: img-1) cost 0.2500 USD"), "{one}");
        assert!(!one.contains("0.2500 EUR"), "{one}");
        assert!(!one.contains('$'), "{one}");
        let none = render_session(&meta(None), &conv, 5000);
        assert!(none.contains("cost: not stated in one currency)"), "{none}");
        assert!(none.contains("[images] (model: img-1) cost 0.2500 USD"), "{none}");
        assert!(!none.contains("0.2500 EUR"), "{none}");
        assert!(!none.contains('$'), "{none}");
        assert_eq!(render_spend(Some(eur), 3), "1.500 EUR");
    }

    #[test]
    fn test_render_window_derived_caps_and_finish_marker() {
        let meta = SessionMeta {
            session_id: uuid::Uuid::nil(),
            user_id: None,
            key_id: None,
            turn_count: 2,
            total_tokens: Some(5000),
            spend: Some(crate::routes::SpendTotal { currency: streamscope_core::pricing::Currency::USD, amount: 0.02 }),
            first_timestamp: None,
            last_timestamp: None,
            last_latency_ms: None,
            model_requested: None,
            model_used: Some("gpt-4o".to_string()),
            user_email: Some("user@test.com".to_string()),
            app_id: Some("rag-app".to_string()),
            first_user_prompt: Some("What does the doc say?".to_string()),
        };
        // A long retrieved document arriving as a tool_result (the RAG shape) —
        // 1500 chars, well over the old fixed 500-char tool cap.
        let long_doc = "D".repeat(1500);
        let conv = serde_json::json!({
            "events": [
                {"type": "message", "role": "user", "content": "What does the doc say?", "turn": 0},
                {"type": "tool_call", "name": "retrieve", "arguments": {"q": "doc"}, "turn": 0},
                {"type": "tool_result", "content": long_doc, "turn": 0},
                {"type": "message", "role": "assistant", "content": "partial ans", "turn": 1,
                 "metadata": {"finish_reason": "length"}},
            ]
        });

        // Big-window judge: the full retrieved doc is visible (cap scaled up).
        let big = render_session(&meta, &conv, 200_000);
        assert!(big.contains(&long_doc), "large budget must surface full tool_result");
        assert!(big.contains("finish: length"), "abnormal finish_reason must render");

        // Small-window judge: the same doc is truncated (floor behavior intact).
        let small = render_session(&meta, &conv, 5000);
        assert!(!small.contains(&long_doc), "small budget must still truncate");
    }

    #[test]
    fn test_parse_tool_call_response() {
        let response = serde_json::json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "id": "call_123",
                        "type": "function",
                        "function": {
                            "name": "submit_analysis",
                            "arguments": r#"{"findings":[{"severity":"high","category":"pii","description":"Email in prompt"}],"proposed_programs":[],"alert_level":"minor","alert_note":"PII detected","memory_update":"Saw PII pattern"}"#
                        }
                    }]
                }
            }]
        });
        let parsed = parse_analysis_response(&response, "security").unwrap();
        let findings = parsed["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "high");
        assert_eq!(parsed["alert_level"], "minor");
        assert_eq!(parsed["memory_update"], "Saw PII pattern");
    }

    #[test]
    fn a_nul_in_the_analysis_is_replaced_before_anything_stores_it() {
        let response = serde_json::json!({
            "choices": [{"message": {"tool_calls": [{"function": {
                "name": "submit_analysis",
                "arguments": "{\"alert_note\":\"a\\u0000b\",\"memory_update\":\"m\"}"
            }}]}}]
        });
        let parsed = parse_analysis_response(&response, "security").unwrap();
        assert_eq!(parsed["alert_note"], "a\u{FFFD}b");
        assert_eq!(parsed["memory_update"], "m");
    }

    #[test]
    fn test_no_tool_calls_returns_error() {
        // No tool_calls — should return error so session is retried
        let response = serde_json::json!({
            "choices": [{
                "message": {
                    "content": "Some text response without tool calls"
                },
                "finish_reason": "stop"
            }]
        });
        let result = parse_analysis_response(&response, "quality");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no tool_calls"));
    }

    #[test]
    fn test_tool_definition_transform() {
        // Typical built-in expert: transform_suggestion + alert + memory
        let tool = analysis_tool_definition(&[
            "transform_suggestion".to_string(),
            "alert".to_string(),
            "memory".to_string(),
        ], false);
        assert_eq!(tool["type"], "function");
        assert_eq!(tool["function"]["name"], "submit_analysis");
        let params = &tool["function"]["parameters"];
        assert_eq!(params["type"], "object");
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "findings"));
        assert!(required.iter().any(|v| v == "proposed_programs"));
        assert!(required.iter().any(|v| v == "alert_level"));
        // memory_update is present but NOT required
        assert!(!required.iter().any(|v| v == "memory_update"));
        let props = params["properties"].as_object().unwrap();
        assert!(props.contains_key("memory_update"));
        // session_labels should NOT be present
        assert!(!props.contains_key("session_labels"));
    }

    #[test]
    fn test_tool_definition_transform_no_alert_no_memory() {
        // Expert with only transform_suggestion (no alert, no memory)
        let tool = analysis_tool_definition(&["transform_suggestion".to_string()], false);
        let params = &tool["function"]["parameters"];
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "findings"));
        assert!(required.iter().any(|v| v == "proposed_programs"));
        // alert and memory should NOT be present
        assert!(!required.iter().any(|v| v == "alert_level"));
        let props = params["properties"].as_object().unwrap();
        assert!(!props.contains_key("alert_level"));
        assert!(!props.contains_key("memory_update"));
    }

    #[test]
    fn test_tool_definition_session_label() {
        // Typical linkage expert: session_label + alert + memory
        let tool = analysis_tool_definition(&[
            "session_label".to_string(),
            "alert".to_string(),
            "memory".to_string(),
        ], false);
        let params = &tool["function"]["parameters"];
        let required = params["required"].as_array().unwrap();
        // session_labels is required
        assert!(required.iter().any(|v| v == "session_labels"));
        // alert_level is required when "alert" output type present
        assert!(required.iter().any(|v| v == "alert_level"));
        // findings, proposed_programs NOT present (not needed for label-only expert)
        assert!(!required.iter().any(|v| v == "findings"));
        assert!(!required.iter().any(|v| v == "proposed_programs"));
        let props = params["properties"].as_object().unwrap();
        assert!(props.contains_key("session_labels"));
        assert!(props.contains_key("alert_level"));
        assert!(props.contains_key("memory_update")); // present but optional
        assert!(!props.contains_key("findings"));
        assert!(!props.contains_key("proposed_programs"));
    }

    #[test]
    fn test_tool_definition_tool_rules() {
        let tool = analysis_tool_definition(&[
            "tool_rules".to_string(),
            "alert".to_string(),
        ], false);
        let params = &tool["function"]["parameters"];
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "findings"));
        assert!(required.iter().any(|v| v == "proposed_tool_rules"));
        assert!(required.iter().any(|v| v == "alert_level"));
        assert!(!required.iter().any(|v| v == "proposed_programs"));
        let props = params["properties"].as_object().unwrap();
        assert!(props.contains_key("proposed_tool_rules"));
        assert!(!props.contains_key("memory_update")); // no "memory" output type
    }

    #[test]
    fn test_render_session_small_budget() {
        let meta = SessionMeta {
            session_id: uuid::Uuid::nil(),
            user_id: None,
            key_id: None,
            turn_count: 5,
            total_tokens: Some(10000),
            spend: Some(crate::routes::SpendTotal { currency: streamscope_core::pricing::Currency::USD, amount: 0.05 }),
            first_timestamp: None,
            last_timestamp: None,
            last_latency_ms: None,
            model_requested: None,
            model_used: Some("gpt-4o".to_string()),
            user_email: Some("test@example.com".to_string()),
            app_id: None,
            first_user_prompt: None,
        };
        let conv = serde_json::json!({});
        let result = render_session(&meta, &conv, 200);
        assert!(result.contains("gpt-4o"));
        assert!(!result.contains("### System Prompt"));
    }

    #[test]
    fn test_render_session_with_media_api_call() {
        let meta = SessionMeta {
            session_id: uuid::Uuid::nil(),
            user_id: None,
            key_id: None,
            turn_count: 4,
            total_tokens: Some(1000),
            spend: Some(crate::routes::SpendTotal { currency: streamscope_core::pricing::Currency::USD, amount: 0.10 }),
            first_timestamp: None,
            last_timestamp: None,
            last_latency_ms: None,
            model_requested: None,
            model_used: Some("gpt-4o".to_string()),
            user_email: Some("user@test.com".to_string()),
            app_id: None,
            first_user_prompt: Some("Generate an image".to_string()),
        };
        let conv = serde_json::json!({
            "events": [
                {"type": "message", "role": "user", "content": "Generate an image", "turn": 0, "is_new": true},
                {
                    "type": "media_api_call",
                    "media_call": {
                        "endpoint": "image_generation",
                        "model": "dall-e-3",
                        "input": [{"type": "text", "text": "A sunset over mountains"}],
                        "output": [],
                        "params": {}
                    },
                    "turn": 1,
                    "is_new": true,
                    "metadata": {"spend": {"currency": "USD", "amount": 0.04}, "model_used": "dall-e-3", "tokens_in": 0, "tokens_out": 0, "latency_ms": 5000, "ttft_ms": 0, "finish_reason": ""}
                },
                {
                    "type": "media_api_call",
                    "media_call": {
                        "endpoint": "audio_transcription",
                        "model": "whisper-1",
                        "input": [],
                        "output": [{"type": "text", "text": "The meeting started at nine"}],
                        "params": {}
                    },
                    "turn": 2,
                    "is_new": true,
                    "metadata": {"spend": {"currency": "USD", "amount": 0.006}, "model_used": "whisper-1", "tokens_in": 0, "tokens_out": 0, "latency_ms": 1200, "ttft_ms": 0, "finish_reason": ""}
                }
            ]
        });
        let result = render_session(&meta, &conv, 5000);
        // Image generation event
        assert!(result.contains("[image_generation]"), "missing image_generation: {result}");
        assert!(result.contains("dall-e-3"), "missing model: {result}");
        assert!(result.contains("cost 0.0400 USD"), "missing cost: {result}");
        assert!(result.contains("A sunset over mountains"), "missing input text: {result}");
        // Transcription event with arrow separator for output text
        assert!(result.contains("[audio_transcription]"), "missing audio_transcription: {result}");
        assert!(result.contains("\u{2192}"), "missing arrow for transcription output: {result}");
        assert!(result.contains("The meeting started"), "missing transcription text: {result}");
        // Media summary
        assert!(result.contains("Media:"), "missing Media summary: {result}");
        assert!(result.contains("image_generation(1)"), "missing image_generation count: {result}");
        assert!(result.contains("audio_transcription(1)"), "missing audio_transcription count: {result}");
    }

    #[test]
    fn test_render_session_with_chat_media_attachments() {
        let meta = SessionMeta {
            session_id: uuid::Uuid::nil(),
            user_id: None,
            key_id: None,
            turn_count: 2,
            total_tokens: Some(3000),
            spend: Some(crate::routes::SpendTotal { currency: streamscope_core::pricing::Currency::USD, amount: 0.05 }),
            first_timestamp: None,
            last_timestamp: None,
            last_latency_ms: None,
            model_requested: None,
            model_used: Some("gpt-4o".to_string()),
            user_email: Some("user@test.com".to_string()),
            app_id: None,
            first_user_prompt: Some("Describe this image".to_string()),
        };
        let conv = serde_json::json!({
            "events": [
                {"type": "message", "role": "user", "content": "Describe this image", "turn": 0, "is_new": true},
                {
                    "type": "media",
                    "role": "user",
                    "content_type": "image",
                    "media_type": "image/png",
                    "title": "photo.png",
                    "size_bytes": 251904,
                    "turn": 0,
                    "is_new": true
                },
                {
                    "type": "media",
                    "role": "user",
                    "content_type": "document",
                    "media_type": "application/pdf",
                    "title": "report.pdf",
                    "size_bytes": 102400,
                    "turn": 1,
                    "is_new": true
                },
                {"type": "message", "role": "assistant", "content": "The image shows a landscape.", "turn": 1, "is_new": true}
            ]
        });
        let result = render_session(&meta, &conv, 5000);
        // Image attachment
        assert!(result.contains("[image attachment]"), "missing image attachment: {result}");
        assert!(result.contains("(image/png)"), "missing MIME type: {result}");
        assert!(result.contains("photo.png"), "missing title: {result}");
        assert!(result.contains("246KB"), "missing size: {result}");
        // Document attachment
        assert!(result.contains("[document attachment]"), "missing document attachment: {result}");
        assert!(result.contains("report.pdf"), "missing doc title: {result}");
        // Media summary
        assert!(result.contains("Media:"), "missing Media summary: {result}");
        assert!(result.contains("image(1)"), "missing image count: {result}");
        assert!(result.contains("document(1)"), "missing document count: {result}");
    }

    #[test]
    fn test_render_session_mixed_chat_and_media_api() {
        let meta = SessionMeta {
            session_id: uuid::Uuid::nil(),
            user_id: None,
            key_id: None,
            turn_count: 4,
            total_tokens: Some(5000),
            spend: Some(crate::routes::SpendTotal { currency: streamscope_core::pricing::Currency::USD, amount: 0.15 }),
            first_timestamp: None,
            last_timestamp: None,
            last_latency_ms: None,
            model_requested: None,
            model_used: Some("gpt-4o".to_string()),
            user_email: Some("user@test.com".to_string()),
            app_id: None,
            first_user_prompt: Some("Analyze this".to_string()),
        };
        let conv = serde_json::json!({
            "events": [
                {"type": "message", "role": "user", "content": "Analyze this", "turn": 0, "is_new": true},
                {"type": "media", "role": "user", "content_type": "image", "media_type": "image/jpeg", "size_bytes": 50000, "turn": 0, "is_new": true},
                {"type": "message", "role": "assistant", "content": "I can see a chart.", "turn": 0, "is_new": true},
                {"type": "tool_call", "name": "analyze", "arguments": {}, "id": "tc1", "turn": 1, "is_new": true},
                {"type": "tool_result", "tool_call_id": "tc1", "content": "Analysis complete", "turn": 1, "is_new": true},
                {
                    "type": "media_api_call",
                    "media_call": {
                        "endpoint": "audio_speech",
                        "model": "tts-1",
                        "input": [{"type": "text", "text": "Here is the summary"}],
                        "output": [],
                        "params": {}
                    },
                    "turn": 2,
                    "is_new": true,
                    "metadata": {"spend": {"currency": "USD", "amount": 0.015}, "model_used": "tts-1", "tokens_in": 0, "tokens_out": 0, "latency_ms": 300, "ttft_ms": 0, "finish_reason": ""}
                }
            ]
        });
        let result = render_session(&meta, &conv, 8000);
        // Regular messages present
        assert!(result.contains("Analyze this"), "missing user message: {result}");
        assert!(result.contains("I can see a chart"), "missing assistant message: {result}");
        // Chat media attachment present
        assert!(result.contains("[image attachment]"), "missing chat image: {result}");
        // Tool call present
        assert!(result.contains("analyze"), "missing tool call: {result}");
        // Media API call present
        assert!(result.contains("[audio_speech]"), "missing audio_speech: {result}");
        assert!(result.contains("tts-1"), "missing TTS model: {result}");
        // Both summaries present
        assert!(result.contains("Tools:"), "missing Tools summary: {result}");
        assert!(result.contains("Media:"), "missing Media summary: {result}");
        assert!(result.contains("image(1)"), "missing image count (chat media): {result}");
        assert!(result.contains("audio_speech(1)"), "missing audio_speech count: {result}");
    }


    // ─── Merge grouping ───

    fn ginput(idx: usize, path: GroupPath, alias: &str, pidx: usize, merge: bool) -> GroupingInput {
        GroupingInput {
            expert_idx: idx,
            path,
            routing_alias: alias.to_string(),
            profile_idx: pidx,
            merge_enabled: merge,
        }
    }

    #[test]
    fn group_experts_pools_same_path_routing_profile() {
        let inputs = vec![
            ginput(0, GroupPath::Session, "m", 0, true),
            ginput(1, GroupPath::Session, "m", 0, true),
            ginput(2, GroupPath::Session, "m", 0, true),
        ];
        let groups = group_experts(&inputs);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, GroupPath::Session);
        assert_eq!(groups[0].2, vec![0, 1, 2]);
    }

    #[test]
    fn group_experts_merge_disabled_is_solo() {
        let inputs = vec![
            ginput(0, GroupPath::Session, "m", 0, true),
            ginput(1, GroupPath::Session, "m", 0, false),
            ginput(2, GroupPath::Session, "m", 0, true),
        ];
        let groups = group_experts(&inputs);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].2, vec![0, 2]);
        assert_eq!(groups[1].2, vec![1]);
    }

    #[test]
    fn group_experts_splits_on_path_routing_and_profile() {
        let inputs = vec![
            ginput(0, GroupPath::Session, "m", 0, true),
            ginput(1, GroupPath::Cluster, "m", 0, true),
            ginput(2, GroupPath::Session, "other-model", 0, true),
            ginput(3, GroupPath::Session, "m", 1, true),
            ginput(4, GroupPath::Cluster, "m", 0, true),
        ];
        let groups = group_experts(&inputs);
        assert_eq!(groups.len(), 4);
        assert_eq!(groups[0], (GroupPath::Session, 0, vec![0]));
        assert_eq!(groups[1], (GroupPath::Cluster, 0, vec![1, 4]));
        assert_eq!(groups[2], (GroupPath::Session, 0, vec![2]));
        assert_eq!(groups[3], (GroupPath::Session, 1, vec![3]));
    }

    #[test]
    fn group_experts_dual_path_expert_joins_both_pools() {
        // An expert with both session and session_cluster inputs contributes
        // one entry per path and lands in both pools.
        let inputs = vec![
            ginput(0, GroupPath::Session, "m", 0, true),
            ginput(1, GroupPath::Session, "m", 0, true),
            ginput(1, GroupPath::Cluster, "m", 0, true),
            ginput(2, GroupPath::Cluster, "m", 0, true),
        ];
        let groups = group_experts(&inputs);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0], (GroupPath::Session, 0, vec![0, 1]));
        assert_eq!(groups[1], (GroupPath::Cluster, 0, vec![1, 2]));
    }

    #[test]
    fn cluster_applicability_gates_linkage_style_members_on_singletons() {
        let link_outputs = vec!["session_label".to_string(), "memory".to_string()];
        let anomaly_outputs = vec![
            "transform_suggestion".to_string(),
            "alert".to_string(),
            "memory".to_string(),
        ];
        // Linkage-style (labels+memory only): needs 2+ sessions.
        assert!(!member_applies_to_cluster(&link_outputs, 1));
        assert!(member_applies_to_cluster(&link_outputs, 2));
        // Alert/transform members analyze singletons too.
        assert!(member_applies_to_cluster(&anomaly_outputs, 1));
        assert!(member_applies_to_cluster(&anomaly_outputs, 5));
    }

    // ─── Merged tool schema ───

    #[test]
    fn group_tool_definition_requires_every_axis_with_assessment() {
        let sec_outputs = vec![
            "transform_suggestion".to_string(),
            "alert".to_string(),
            "memory".to_string(),
        ];
        let tp_outputs = vec![
            "transform_suggestion".to_string(),
            "tool_rules".to_string(),
            "alert".to_string(),
            "memory".to_string(),
        ];
        let members: Vec<(&str, &[String])> = vec![
            ("security", sec_outputs.as_slice()),
            ("tool_policy", tp_outputs.as_slice()),
        ];
        let tool = analysis_tool_definition_for_group(&members, false);
        let params = &tool["function"]["parameters"];

        assert_eq!(params["required"], serde_json::json!(["axes"]));
        let axes = &params["properties"]["axes"];
        let axes_required: Vec<&str> = axes["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(axes_required, vec!["security", "tool_policy"]);

        for axis in ["security", "tool_policy"] {
            let entry = &axes["properties"][axis];
            let required: Vec<&str> = entry["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert!(required.contains(&"assessment"), "{axis} missing assessment: {required:?}");
            assert!(entry["properties"]["assessment"].is_object());
            // Session pool: scalar alert channel.
            assert!(entry["properties"]["alert_level"].is_object());
            assert!(entry["properties"]["session_alerts"].is_null());
        }
        // Only tool_policy carries the tool-rule channel.
        assert!(axes["properties"]["tool_policy"]["properties"]["proposed_tool_rules"].is_object());
        assert!(axes["properties"]["security"]["properties"]["proposed_tool_rules"].is_null());
    }

    #[test]
    fn group_tool_definition_cluster_uses_session_alerts_channel() {
        let link_outputs = vec!["session_label".to_string(), "memory".to_string()];
        let anomaly_outputs = vec![
            "transform_suggestion".to_string(),
            "alert".to_string(),
            "memory".to_string(),
        ];
        let members: Vec<(&str, &[String])> = vec![
            ("session_linkage", link_outputs.as_slice()),
            ("anomaly", anomaly_outputs.as_slice()),
        ];
        let tool = analysis_tool_definition_for_group(&members, true);
        let axes = &tool["function"]["parameters"]["properties"]["axes"];

        let anomaly = &axes["properties"]["anomaly"];
        assert!(anomaly["properties"]["session_alerts"].is_object());
        assert!(anomaly["properties"]["cross_session_issues"].is_object(), "alert output ⇒ cross-session channel");
        assert!(anomaly["properties"]["alert_level"].is_null());
        // Cluster refs are by S-index, never a UUID.
        assert!(anomaly["properties"]["session_alerts"]["items"]["properties"]["session_index"].is_object());
        assert!(anomaly["properties"]["session_alerts"]["items"]["properties"]["session_id"].is_null());

        let link = &axes["properties"]["session_linkage"];
        assert!(link["properties"]["session_labels"].is_object());
        assert!(link["properties"]["session_labels"]["items"]["properties"]["session_index"].is_object(), "linkage refs by S-index");
        assert!(link["properties"]["session_alerts"].is_null(), "no alert output type on linkage");
        assert!(link["properties"]["cross_session_issues"].is_null(), "no alert output type on linkage");
    }

    #[test]
    fn solo_tool_definition_keeps_legacy_scalar_alert_shape() {
        let outputs = vec![
            "transform_suggestion".to_string(),
            "alert".to_string(),
            "memory".to_string(),
        ];
        let tool = analysis_tool_definition(&outputs, false);
        let props = &tool["function"]["parameters"]["properties"];
        assert!(props["alert_level"].is_object());
        assert!(props["axes"].is_null());
        assert!(props["session_alerts"].is_null());
    }

    // ─── Axis payload parsing ───

    #[test]
    fn parse_axis_fields_gates_memory_on_output_types() {
        let payload = serde_json::json!({
            "findings": [{"severity": "high", "category": "sec", "description": "d"}],
            "memory_update": "remember this"
        });
        let with_memory = parse_axis_fields(
            &payload,
            &["transform_suggestion".to_string(), "memory".to_string()],
            &[],
            &[],
        );
        assert_eq!(with_memory.findings.len(), 1);
        assert_eq!(with_memory.memory_update, "remember this");

        let without_memory =
            parse_axis_fields(&payload, &["transform_suggestion".to_string()], &[], &[]);
        assert!(without_memory.memory_update.is_empty());
    }

    #[test]
    fn extract_session_alerts_resolves_index_and_drops_out_of_range() {
        let s0 = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let s1 = uuid::Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let s_index = vec![s0, s1];
        let payload = serde_json::json!({
            "session_alerts": [
                {"session_index": 0, "level": "minor", "note": "unusual volume"},
                {"session_index": 9, "level": "major", "note": "out-of-range index"},
                {"session_index": 1, "level": "bogus", "note": "bad level"},
                {"session_index": 1, "level": "info", "note": "   "}
            ]
        });
        let alerts = extract_session_alerts(&payload, "anomaly", &s_index);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].0, s0.to_string());
        assert_eq!(alerts[0].1, "minor");
        assert_eq!(alerts[0].2, "unusual volume");
    }

    #[test]
    fn extract_cross_session_issues_resolves_indices() {
        let s0 = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let s1 = uuid::Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let s_index = vec![s0, s1];
        let payload = serde_json::json!({
            "cross_session_issues": [
                {"source_session_indices": [0, 1, 9], "level": "major", "note": "coordinated pattern"},
                {"source_session_indices": [7, 8], "level": "major", "note": "all out of range"},
                {"source_session_indices": [0], "level": "info", "note": "   "}
            ]
        });
        let issues = extract_cross_session_issues(&payload, "anomaly", &s_index);
        assert_eq!(issues.len(), 1, "the all-out-of-range and empty-note issues are dropped");
        assert_eq!(issues[0].0, "major");
        assert_eq!(issues[0].2, vec![s0, s1], "index 9 dropped, 0 and 1 resolved");
    }

    #[test]
    fn parse_axis_fields_confirms_spawn_anchor_and_overrides_turn() {
        use crate::conversation::DetectedSpawnPoint;
        let s0 = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let s1 = uuid::Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let s_index = vec![s0, s1];
        // Parent S0 has two detected spawn points; the child S1 confirms P1.
        let spawn_points = vec![
            vec![
                DetectedSpawnPoint {
                    turn_number: 2,
                    tool_call_id: "toolu_a".into(),
                    tool_name: "Task".into(),
                    prompt_preview: "first".into(),
                },
                DetectedSpawnPoint {
                    turn_number: 6,
                    tool_call_id: "toolu_b".into(),
                    tool_name: "Task".into(),
                    prompt_preview: "second".into(),
                },
            ],
            vec![],
        ];
        let payload = serde_json::json!({
            "session_labels": [
                // Confirms P1 → anchor id toolu_b, turn overridden to 6 (not the
                // model's 99 estimate).
                {"session_index": 1, "label_type": "parent_session_id", "parent_session_index": 0,
                 "confidence": "high", "note": "spawned", "spawn_turn": 99, "parent_spawn_point_index": 1},
            ]
        });
        let fields = parse_axis_fields(&payload, &["session_label".to_string()], &s_index, &spawn_points);
        assert_eq!(fields.session_labels.len(), 1);
        let label = &fields.session_labels[0];
        assert_eq!(label.session_id, s1.to_string());
        assert_eq!(label.label_value, s0.to_string());
        assert_eq!(label.spawn_tool_call_id.as_deref(), Some("toolu_b"));
        assert_eq!(label.spawn_turn, Some(6), "code-detected turn overrides the model estimate");
    }

    #[test]
    fn parse_axis_fields_out_of_range_spawn_index_keeps_model_turn() {
        let s0 = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let s1 = uuid::Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let s_index = vec![s0, s1];
        let spawn_points = vec![
            vec![crate::conversation::DetectedSpawnPoint {
                turn_number: 2,
                tool_call_id: "toolu_a".into(),
                tool_name: "Task".into(),
                prompt_preview: "only one".into(),
            }],
            vec![],
        ];
        let payload = serde_json::json!({
            "session_labels": [
                {"session_index": 1, "label_type": "parent_session_id", "parent_session_index": 0,
                 "confidence": "medium", "note": "temporal", "spawn_turn": 4, "parent_spawn_point_index": 9},
            ]
        });
        let fields = parse_axis_fields(&payload, &["session_label".to_string()], &s_index, &spawn_points);
        let label = &fields.session_labels[0];
        assert_eq!(label.spawn_tool_call_id, None, "out-of-range P-index → no anchor");
        assert_eq!(label.spawn_turn, Some(4), "falls back to the model's estimate");
    }

    #[test]
    fn merged_max_tokens_scales_and_caps() {
        assert_eq!(merged_max_tokens(1, None), 16_384);
        assert_eq!(merged_max_tokens(2, None), 18_432);
        assert_eq!(merged_max_tokens(4, None), 21_333);
        assert_eq!(merged_max_tokens(10, None), 21_333);
        // Model output cap bounds the ask; zero/negative caps are ignored.
        assert_eq!(merged_max_tokens(5, Some(8192)), 8192);
        assert_eq!(merged_max_tokens(1, Some(4096)), 4096);
        assert_eq!(merged_max_tokens(5, Some(65536)), 21_333);
        assert_eq!(merged_max_tokens(5, Some(0)), 21_333);
    }

    /// The ask never exceeds the window room the input budget leaves: at the
    /// default 32k window the prompt may fill 19 200 tokens, so 12 800 remain
    /// and the 16 384 solo ask is cut to it; one token more room than the ask
    /// leaves the ask alone, and the model's own cap still wins below both.
    #[test]
    fn max_tokens_fits_the_window_room() {
        let routing = |window: i32, mo: Option<i32>| {
            let budget = (window as f64 * CONTEXT_USAGE_RATIO) as usize;
            AgentRouting {
                alias: "m".into(),
                context_budget: budget * CHARS_PER_TOKEN,
                max_output_tokens: mo,
                output_room: (window as usize).saturating_sub(budget),
            }
        };
        assert_eq!(routing(DEFAULT_CONTEXT_WINDOW, None).max_tokens(1), 12_800);
        assert_eq!(routing(DEFAULT_CONTEXT_WINDOW, Some(4096)).max_tokens(1), 4096);
        // 40 961 × 0.4 leaves 16 385 free — one more than the solo ask.
        assert_eq!(routing(40_961, None).max_tokens(1), 16_384);
        assert_eq!(routing(40_960, None).max_tokens(1), 16_384);
        assert_eq!(routing(40_955, None).max_tokens(1), 16_382);
        assert_eq!(routing(1_000_000, None).max_tokens(5), 21_333);
        // Whatever the window, prompt budget + ask stays inside it.
        for window in [8_000, 32_000, 128_000, 200_000, 1_000_000] {
            let r = routing(window, None);
            assert!(r.context_budget / CHARS_PER_TOKEN + r.max_tokens(10) <= window as usize, "{window}");
        }
    }

    #[test]
    fn call_timeout_scales_with_output_budget() {
        let base = crate::settings::admin_settings().agent_http_timeout;
        let routing = |mo: Option<i32>| AgentRouting {
            alias: "m".into(),
            context_budget: 1,
            max_output_tokens: mo,
            output_room: usize::MAX,
        };
        assert_eq!(routing(None).call_timeout(), base);
        assert_eq!(routing(Some(8192)).call_timeout(), base);
        assert_eq!(routing(Some(40_000)).call_timeout(), base * 2);
        assert_eq!(routing(Some(65_536)).call_timeout(), base * 3);
        // Capped at 3× no matter how large the budget.
        assert_eq!(routing(Some(1_000_000)).call_timeout(), base * 3);
    }

    #[test]
    fn deterministic_400_detection_targets_only_wire_400s() {
        let wire_400 = anyhow::Error::new(DeterministicFailure {
            msg: "proxy returned 400 Bad Request: x".into(),
            status: Some(400),
        });
        let wire_422 = anyhow::Error::new(DeterministicFailure {
            msg: "proxy returned 422: x".into(),
            status: Some(422),
        });
        let local = deterministic(anyhow::anyhow!("no tool_calls in response"));
        let transient = anyhow::anyhow!("proxy returned 429: x");
        assert!(is_deterministic_400(&wire_400));
        assert!(!is_deterministic_400(&wire_422));
        assert!(!is_deterministic_400(&local));
        assert!(!is_deterministic_400(&transient));
        // All DeterministicFailure shapes still classify as deterministic.
        assert!(is_deterministic_failure(&wire_400));
        assert!(is_deterministic_failure(&wire_422));
        assert!(is_deterministic_failure(&local));
        assert!(!is_deterministic_failure(&transient));
    }

    #[test]
    fn tools_fingerprint_is_stable_and_discriminating() {
        let a = serde_json::json!([{"type":"function","function":{"name":"submit_analysis"}}]);
        let b = serde_json::json!([{"type":"function","function":{"name":"submit_analysis"}}]);
        let c = serde_json::json!([{"type":"function","function":{"name":"other"}}]);
        assert_eq!(tools_fingerprint(&a), tools_fingerprint(&b));
        assert_ne!(tools_fingerprint(&a), tools_fingerprint(&c));
    }
}
