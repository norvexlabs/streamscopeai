//! The session list over the materialized `sessions` table, with the latest
//! turn's requested model and provider read from `conversation_turns ⋈
//! llm_audit`. The user and the workspaces it returns come from its
//! [`AuditScope`]; every other filter from its [`SessionListQuery`]. Beside it,
//! the reads of one session's own row: its linked parent and children, and the
//! alert and linkage its conversation shows.

use std::collections::HashSet;

use uuid::Uuid;

use super::scope::AuditScope;
use super::search::{SearchRows, SearchWalk};
use crate::sql_pattern::{contains_pattern, search_pattern};
use crate::db::tenant::Scoped;
use crate::routes::{ApiError, SpendTotal, spend_total};
use streamscope_core::pricing::Currency;
use crate::routes::audit::{
    LinkedCounts, LinkedSessions, SessionLink, SessionLinkEvidence, SessionLinkKind, SessionLinkage,
    SessionListQuery, SessionSort, SessionSummary, SpawnAnchor,
};
use crate::routes::portal::PortalDataScope;

/// The page size of a session list that names none.
pub(crate) const SESSIONS_DEFAULT_LIMIT: i64 = 50;

/// Which linked sessions a read names beside its own rows: the bind indices of
/// its view's user (`uuid`) and workspaces (`uuid[]`), bound from
/// [`AuditScope::linked_view`] — both NULL for a tenant-wide reader. A linked
/// session outside the view is not named: a child's parent id and its link's
/// confidence, spawn turn and anchor read NULL, and a parent's hidden children
/// are not counted. Session links are written per tenant (the ingest's quote
/// links, the agent's expert path), so without this a portal row would say
/// that another member's session exists and how it is linked.
#[derive(Clone, Copy)]
struct LinkedView {
    user: u32,
    workspaces: u32,
}

impl LinkedView {
    /// Admits the `sessions` row aliased `alias`.
    fn admits_row(self, alias: &'static str) -> String {
        let Self { user: u, workspaces: w } = self;
        format!(
            "(${u}::uuid IS NULL OR {alias}.user_id = ${u}) \
             AND (${w}::uuid[] IS NULL OR {alias}.workspace_id = ANY(${w}))"
        )
    }

    /// Admits the linked session whose id is `id` (a column of the linkage
    /// subquery). A tenant-wide view names it without reading its row.
    fn admits(self, id: &'static str) -> String {
        let Self { user: u, workspaces: w } = self;
        format!(
            "((${u}::uuid IS NULL AND ${w}::uuid[] IS NULL) \
              OR EXISTS (SELECT 1 FROM sessions ls WHERE ls.session_id = {id} AND {row}))",
            row = self.admits_row("ls"),
        )
    }

    /// The relation that links the session whose id is `linked` to the one it
    /// came from — as a `child` of its parent or the `successor` of the
    /// conversation it continues — joined to that other member `pm`, kept only
    /// when the view admits it.
    /// Every writer links a session at most once, so it is single-valued; a
    /// read that needs one row takes [`UPWARD_ORDER`]'s first.
    fn as_linked(self, linked: &'static str) -> String {
        format!(
            "FROM cross_session_relation_members cm \
               JOIN cross_session_relation_members pm ON pm.relation_id = cm.relation_id AND pm.role = {OTHER_ROLE} \
               JOIN cross_session_relations r ON r.id = cm.relation_id AND r.kind IN {LINK_KINDS} \
               WHERE cm.session_id = {linked} AND cm.role IN {UPWARD_ROLES} AND {admits}",
            admits = self.admits("pm.session_id"),
        )
    }

    /// The lateral joins carrying session `s`'s links, read once per row:
    /// - `lk`, its own link ([`Self::as_linked`]): the session it is linked
    ///   to, the link's kind, its confidence as stored (`'content'` for a link
    ///   the ingest read from a quote, `'high'`/`'medium'` for an agent link),
    ///   spawn turn, and spawn anchor —
    ///   the tool-call id of the call in the parent a child was spawned from
    ///   (NULL for every other link);
    /// - `lf`, the sessions linked to it ([`Self::linked_from`]): how many
    ///   children, and the first continuation.
    ///
    /// Every read of [`LINKAGE_COLUMNS`] joins it after `sessions s`.
    fn join(self) -> String {
        format!(
            "LEFT JOIN LATERAL (SELECT pm.session_id AS parent_session_id, r.kind AS linkage_kind, \
               r.confidence AS linkage_confidence, r.spawn_turn AS linkage_spawn_turn, \
               r.spawn_tool_call_id AS linkage_spawn_tool_call_id \
               {linked} ORDER BY {UPWARD_ORDER} LIMIT 1) lk ON true \
             LEFT JOIN LATERAL (SELECT COUNT(*) FILTER (WHERE r.kind = 'linkage')::bigint AS sub_agents, \
               (array_agg(cm.session_id ORDER BY r.created_at, r.id) \
                  FILTER (WHERE r.kind = 'continuation'))[1] AS continued_in \
               {linked_from}) lf ON true",
            linked = self.as_linked("s.session_id"),
            linked_from = self.linked_from(),
        )
    }

    /// The sessions linked to session `s` — its children, its continuation —
    /// that the view admits: `s` is the other member `m` of each
    /// relation, whose linked member is `cm`.
    fn linked_from(self) -> String {
        format!(
            "FROM cross_session_relation_members m \
               JOIN cross_session_relation_members cm ON cm.relation_id = m.relation_id AND cm.role IN {UPWARD_ROLES} \
               JOIN cross_session_relations r ON r.id = m.relation_id AND r.kind IN {LINK_KINDS} \
               WHERE m.session_id = s.session_id AND m.role = {OTHER_ROLE} AND {admits}",
            admits = self.admits("cm.session_id"),
        )
    }
}

/// The relation kinds that link one session to another; `issue` groups.
const LINK_KINDS: &str = "('linkage', 'continuation')";
/// The role of the session a link starts from, in each kind.
const UPWARD_ROLES: &str = "('child', 'successor')";
/// The role of the session the linked member `cm` is linked to.
const OTHER_ROLE: &str = "(CASE cm.role WHEN 'child' THEN 'parent' ELSE 'predecessor' END)";
/// Which of a session's links a one-row read names, should two writers have
/// raced past each other's guard: a child link first, then the oldest.
const UPWARD_ORDER: &str = "(cm.role <> 'child'), r.created_at, r.id";

/// The view of a read whose one own parameter is `$1`: the view's user and
/// workspaces are bound at `$2` / `$3`, right after it.
const LINKED_AT_2: LinkedView = LinkedView { user: 2, workspaces: 3 };

/// A session's links as [`LinkColumns`] decodes them, read from
/// [`LinkedView::join`]'s `lk` and `lf`.
const LINKAGE_COLUMNS: &str = "lk.parent_session_id AS link_session_id, lk.linkage_kind AS link_kind, \
     lk.linkage_confidence AS link_confidence, lk.linkage_spawn_turn AS link_spawn_turn, \
     lk.linkage_spawn_tool_call_id AS link_spawn_tool_call_id, \
     lf.sub_agents AS links_sub_agents, \
     lf.continued_in AS links_continued_in";

/// A session's links as [`LINKAGE_COLUMNS`] reads them: its own link and the
/// sessions linked to it, in the store's vocabulary until [`Self::link`] and
/// [`Self::links`] state them in the API's.
#[derive(sqlx::FromRow, Default)]
pub(crate) struct LinkColumns {
    link_session_id: Option<Uuid>,
    link_kind: Option<String>,
    link_confidence: Option<String>,
    link_spawn_turn: Option<i32>,
    link_spawn_tool_call_id: Option<String>,
    links_sub_agents: Option<i64>,
    links_continued_in: Option<Uuid>,
}

impl LinkColumns {
    /// The session this one is linked to, and how. A spawn point is stated for
    /// a sub-agent only, and only when its turn is known.
    fn link(&self) -> Option<SessionLink> {
        let kind = link_kind(self.link_kind.as_deref()?)?;
        let spawned_at = (kind == SessionLinkKind::SubAgent)
            .then_some(self.link_spawn_turn)
            .flatten()
            .map(|turn_number| SpawnAnchor {
                turn_number,
                tool_call_id: self.link_spawn_tool_call_id.clone(),
            });
        Some(SessionLink {
            session_id: self.link_session_id?,
            kind,
            evidence: link_evidence(self.link_confidence.as_deref()),
            spawned_at,
        })
    }

    /// The sessions linked to this one; `None` when there are none.
    fn links(&self) -> Option<LinkedCounts> {
        let counts = LinkedCounts {
            sub_agents: self.links_sub_agents.unwrap_or(0),
            continued_in: self.links_continued_in,
        };
        (counts.sub_agents > 0 || counts.continued_in.is_some()).then_some(counts)
    }
}

/// A link kind as stored, in the API's vocabulary. [`LINK_KINDS`] is the set
/// a read admits, so any other value is no link.
fn link_kind(stored: &str) -> Option<SessionLinkKind> {
    match stored {
        "linkage" => Some(SessionLinkKind::SubAgent),
        "continuation" => Some(SessionLinkKind::Continuation),
        _ => None,
    }
}

/// A link's stored confidence as the evidence it names. The ingest writes
/// `content`; every other value is an expert's, whose parser reads anything
/// but `high` as `medium`.
fn link_evidence(stored: Option<&str>) -> SessionLinkEvidence {
    match stored {
        Some("content") => SessionLinkEvidence::Quote,
        Some("high") => SessionLinkEvidence::AgentHigh,
        _ => SessionLinkEvidence::AgentMedium,
    }
}

/// A [`SessionSummary`] as the row states it: the summary's own columns, and
/// the session's spend still as its running total and the classification of
/// the currencies behind it, which [`SessionSummaryRow::into_summary`] turns
/// into one figure or none. Every session read decodes this, never a bare
/// `SessionSummary` (whose `spend` the row does not carry).
#[derive(sqlx::FromRow)]
struct SessionSummaryRow {
    #[sqlx(flatten)]
    summary: SessionSummary,
    #[sqlx(flatten)]
    links: LinkColumns,
    total_cost: f64,
    cost_currency: Option<String>,
    cost_currency_count: i16,
}

/// A session's spend from its row's running total and classification
/// (`cost_currency_count`, written per turn by the edge ingest; a charge is
/// never unclassified — `sessions_charge_is_classified`). `None` means no
/// single figure can be stated:
/// - nothing charged — zero in `fallback`, the tenant's accounting currency,
///   whatever the state: a zero is the same in every currency;
/// - **1** — the total, in `cost_currency`;
/// - **0** holding a charge — refused by the schema, and `None` here all the
///   same: never a confident zero;
/// - **2** — turns booked in more than one currency: `None`.
fn session_spend(
    count: i16,
    currency: Option<String>,
    total_cost: f64,
    fallback: Currency,
) -> Option<SpendTotal> {
    if total_cost == 0.0 {
        return Some(SpendTotal { currency: fallback, amount: 0.0 });
    }
    match count {
        0 => None,
        n => spend_total(i64::from(n), currency, total_cost, fallback),
    }
}

impl SessionSummaryRow {
    fn into_summary(self, fallback: Currency) -> SessionSummary {
        SessionSummary {
            spend: session_spend(self.cost_currency_count, self.cost_currency, self.total_cost, fallback),
            link: self.links.link(),
            links: self.links.links(),
            ..self.summary
        }
    }
}

/// The summaries of `rows`. The tenant's accounting currency is read once, and
/// only when a row that charged nothing needs it to denominate its zero.
async fn into_summaries(conn: &mut Scoped, rows: Vec<SessionSummaryRow>) -> Vec<SessionSummary> {
    let fallback = if rows.iter().any(|r| r.total_cost == 0.0) {
        crate::routes::pricing::accounting_currency(conn).await
    } else {
        Currency::USD
    };
    rows.into_iter().map(|r| r.into_summary(fallback)).collect()
}

/// The columns of a [`SessionSummary`] every read takes from `sessions s` and
/// its linkage, named as the [`SessionSummaryRow`]'s fields. Each read adds the rest by name
/// — `model_requested`, `workspace_name`, `provider`, `key_name`,
/// `key_prefix` — as a typed NULL
/// where it has none, so the summary decodes by name, never by position. A read
/// of them joins its view's [`LinkedView::join`].
fn summary_columns() -> &'static str {
    static COLUMNS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!(
            "s.session_id, s.turn_count::bigint AS turn_count, \
             (s.total_prompt_tokens + s.total_completion_tokens)::bigint AS total_tokens, \
             s.total_cache_creation_tokens, s.total_cache_read_tokens, s.total_reasoning_tokens, \
             s.total_cost, s.cost_currency, s.cost_currency_count, s.created_at AS first_timestamp, s.updated_at AS last_timestamp, \
             s.last_latency_ms, s.model_used, s.user_id, s.user_email, s.key_id, s.app_id, \
             s.alert_level, s.alert_expert_axis, s.alert_note, s.first_user_prompt, \
             {LINKAGE_COLUMNS}"
        )
    });
    &COLUMNS
}

/// A session's linked parent and children inside a portal caller's
/// [`PortalDataScope`]: only those the scope admits — the member's own, or a
/// shared workspace's.
pub(crate) async fn linked_sessions_in_portal_scope(
    conn: &mut Scoped,
    session_id: Uuid,
    scope: &PortalDataScope,
) -> Result<LinkedSessions, ApiError> {
    linked_sessions(conn, session_id, &AuditScope::portal(scope)).await
}

/// A session's linked parent and children across the whole tenant — the
/// console's view, which RLS alone confines.
pub(crate) async fn linked_sessions_tenant_wide(
    conn: &mut Scoped,
    session_id: Uuid,
) -> Result<LinkedSessions, ApiError> {
    linked_sessions(conn, session_id, &AuditScope::tenant(None, None)).await
}

/// The linked-session reads, confined by `scope`'s [`AuditScope::linked_view`]:
/// the parent, the children, and the linkage each of their summaries names in
/// turn. Reached only through the two entry points above.
async fn linked_sessions(
    conn: &mut Scoped,
    session_id: Uuid,
    scope: &AuditScope,
) -> Result<LinkedSessions, ApiError> {
    let (view_user, view_workspaces) = scope.linked_view();

    // The session it is linked to (its parent, the conversation it
    // continues), only when the view admits it.
    let parent = sqlx::query_as::<_, SessionSummaryRow>(sqlx::AssertSqlSafe(&*format!(
        "SELECT {summary}, \
         NULL::text AS model_requested, \
         NULL::text AS workspace_name, NULL::text AS provider, \
         NULL::text AS key_name, NULL::text AS key_prefix \
         FROM sessions s {join} \
         WHERE s.session_id = (SELECT pm.session_id {linked} ORDER BY {UPWARD_ORDER} LIMIT 1)",
        summary = summary_columns(),
        join = LINKED_AT_2.join(),
        linked = LINKED_AT_2.as_linked("$1"),
    )))
    .bind(session_id)
    .bind(view_user)
    .bind(view_workspaces.clone())
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("get_session_linked parent query: {e}");
        ApiError::internal("Failed to query linked parent session")
    })?;

    // The sessions linked to this one (its children, its continuation) the
    // view admits, each naming its link. Only a sub-agent anchors
    // to a spawn point.
    let children = sqlx::query_as::<_, SessionSummaryRow>(sqlx::AssertSqlSafe(&*format!(
        "SELECT {summary}, \
         NULL::text AS model_requested, \
         NULL::text AS workspace_name, NULL::text AS provider, \
         NULL::text AS key_name, NULL::text AS key_prefix \
         FROM sessions s {join} \
         WHERE s.session_id IN (SELECT cm.session_id FROM cross_session_relation_members pm \
                JOIN cross_session_relation_members cm ON cm.relation_id = pm.relation_id \
                  AND cm.role IN {UPWARD_ROLES} AND pm.role = {OTHER_ROLE} \
                WHERE pm.session_id = $1) \
         AND lk.parent_session_id = $1 AND {admits} \
         ORDER BY s.created_at",
        summary = summary_columns(),
        join = LINKED_AT_2.join(),
        admits = LINKED_AT_2.admits_row("s"),
    )))
    .bind(session_id)
    .bind(view_user)
    .bind(view_workspaces)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("get_session_linked children query: {e}");
        ApiError::internal("Failed to query linked child sessions")
    })?;

    // One pass, so the accounting currency is read at most once.
    let has_parent = parent.is_some();
    let mut summaries = into_summaries(conn, parent.into_iter().chain(children).collect()).await;
    let parent = has_parent.then(|| summaries.remove(0));
    Ok(LinkedSessions { parent, children: summaries })
}

/// A session's alert, links and `app_id`, for its conversation.
#[derive(Default)]
pub(crate) struct ConversationSessionRow {
    pub alert_level: Option<String>,
    pub alert_expert_axis: Option<String>,
    pub alert_note: Option<String>,
    pub link: Option<SessionLink>,
    pub links: Option<LinkedCounts>,
    pub app_id: Option<String>,
}

/// [`ConversationSessionRow`] as the row states it.
#[derive(sqlx::FromRow)]
struct ConversationSessionColumns {
    alert_level: Option<String>,
    alert_expert_axis: Option<String>,
    alert_note: Option<String>,
    app_id: Option<String>,
    #[sqlx(flatten)]
    links: LinkColumns,
}

/// The conversation's session row; its links name a session only when
/// `scope`'s [`AuditScope::linked_view`] admits it.
pub(crate) async fn conversation_session(
    conn: &mut Scoped,
    session_id: Uuid,
    scope: &AuditScope,
) -> sqlx::Result<Option<ConversationSessionRow>> {
    let (view_user, view_workspaces) = scope.linked_view();
    let row = sqlx::query_as::<_, ConversationSessionColumns>(sqlx::AssertSqlSafe(&*format!(
        "SELECT s.alert_level, s.alert_expert_axis, s.alert_note, {LINKAGE_COLUMNS}, s.app_id \
         FROM sessions s {join} WHERE s.session_id = $1",
        join = LINKED_AT_2.join(),
    )))
    .bind(session_id)
    .bind(view_user)
    .bind(view_workspaces)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|r| ConversationSessionRow {
        link: r.links.link(),
        links: r.links.links(),
        alert_level: r.alert_level,
        alert_expert_axis: r.alert_expert_axis,
        alert_note: r.alert_note,
        app_id: r.app_id,
    }))
}

/// A list row's columns: the summary's, and those [`MODEL_REQUESTED_JOIN`] and
/// [`WORKSPACE_JOIN`] supply. The linked sessions a row names are confined by
/// the view its [`LinkedView::join`] reads, bound ahead of the read's own
/// filters.
fn session_cols() -> String {
    format!(
        "{summary}, \
         mr.model_requested, \
         ws.name AS workspace_name, mr.provider AS provider, \
         ak.name AS key_name, ak.key_prefix",
        summary = summary_columns(),
    )
}

/// Lateral subquery to get model_requested + provider from the most recent
/// llm_audit entry via conversation_turns (LLM-only cols → no need to JOIN
/// gateway_audit on this hot path).
const MODEL_REQUESTED_JOIN: &str = "LEFT JOIN LATERAL ( \
     SELECT a.model_requested, a.provider FROM conversation_turns ct2 \
     JOIN llm_audit a ON a.request_id = ct2.request_id AND a.timestamp = ct2.timestamp \
     WHERE ct2.session_id = s.session_id \
     ORDER BY ct2.timestamp DESC LIMIT 1 \
 ) mr ON true";

/// `ak` supplies the issuing key's name/prefix, which only a key-authenticated
/// session has. The workspace badge comes from the session's own column, so it
/// still resolves for a session whose `key_id` is a spec-OAuth token's jti.
const WORKSPACE_JOIN: &str = "LEFT JOIN api_keys ak ON ak.id = s.key_id \
     LEFT JOIN workspaces ws ON ws.id = s.workspace_id";

/// Where a session stands in the order its turns landed: the id of the ingest
/// transaction that last added a turn to it (`sessions.landed_xid`), then the
/// session id. A session landed later stands after every position a scan has
/// passed, whatever time a gateway stamped on its turns.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) struct LandedKey {
    pub xid: i64,
    pub session_id: Uuid,
}

impl LandedKey {
    /// A position as its two columns store it: set only when both are.
    pub(crate) fn from_columns(xid: Option<i64>, session_id: Option<Uuid>) -> Option<Self> {
        Some(Self { xid: xid?, session_id: session_id? })
    }

    /// Before every session landed by transaction `xid` or a later one, after
    /// every session landed by an earlier one.
    pub(crate) fn before(xid: i64) -> Self {
        Self { xid, session_id: Uuid::nil() }
    }
}

/// `<xid>.<session id>`: the one spelling of a position, in a log line, a
/// notification key or an audit row.
impl std::fmt::Display for LandedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.xid, self.session_id)
    }
}

/// One page of [`list_sessions_landed`].
pub(crate) struct LandedPage {
    /// The page, in landing order, each session with its key.
    pub rows: Vec<(SessionSummary, LandedKey)>,
    /// The scan listed `limit` keys: more may follow the last one. (A session
    /// deleted between the scan's two reads is not in `rows`.)
    pub full: bool,
    /// Every transaction with a smaller id had ended when the page was read, so
    /// no session lands before `LandedKey::before(bound)` after it.
    pub bound: i64,
}

/// The oldest transaction id still running on the server. Every turn landed by
/// a smaller one is committed (or rolled back); every stamp still to commit is
/// at least this. Within one database cluster it never moves back, so a stored
/// position past it was taken in another cluster (a backup restored into a new
/// one, whose ids start over).
pub(crate) async fn landing_bound(conn: &mut Scoped) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT pg_snapshot_xmin(pg_current_snapshot())::text::bigint")
        .fetch_one(&mut *conn)
        .await?)
}

/// The position from which every session active after `active_after` (and up
/// to `active_until`, when given) is read: before each such session's stamp, and
/// before every transaction still running. Sessions active at or before it may
/// stand after it too; a reader that must skip them filters on their activity.
pub(crate) async fn landing_start(
    conn: &mut Scoped,
    active_after: chrono::DateTime<chrono::Utc>,
    active_until: Option<chrono::DateTime<chrono::Utc>>,
) -> anyhow::Result<LandedKey> {
    let bound = landing_bound(conn).await?;
    let first: Option<i64> = sqlx::query_scalar(
        "SELECT MIN(landed_xid) FROM sessions \
         WHERE updated_at > $1 AND ($2::timestamptz IS NULL OR updated_at <= $2)",
    )
    .bind(active_after)
    .bind(active_until)
    .fetch_one(&mut *conn)
    .await?;
    Ok(LandedKey::before(first.map_or(bound, |f| f.min(bound))))
}

/// Clear every stamp at or past the next transaction id: no transaction of this
/// cluster has written one, so the cluster restored them from another (a backup
/// restored into a new one, whose ids start over). A session that loses its
/// stamp is read again once a turn reaches it. Returns how many were cleared.
///
/// Two statements, so an ingest committing in between is never mistaken for one:
/// the read sees only committed stamps, each below its snapshot's next id, and the
/// clear applies only where the stamp is still the one read — an ingest's new
/// stamp makes the re-checked row differ.
pub(crate) async fn forget_foreign_stamps(conn: &mut Scoped) -> anyhow::Result<u64> {
    let foreign: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT session_id, landed_xid FROM sessions \
         WHERE landed_xid >= pg_snapshot_xmax(pg_current_snapshot())::text::bigint",
    )
    .fetch_all(&mut *conn)
    .await?;
    if foreign.is_empty() {
        return Ok(0);
    }
    let (ids, stamps): (Vec<Uuid>, Vec<i64>) = foreign.into_iter().unzip();
    Ok(sqlx::query(
        "UPDATE sessions s SET landed_xid = NULL \
         FROM unnest($1::uuid[], $2::bigint[]) AS f(sid, xid) \
         WHERE s.session_id = f.sid AND s.landed_xid = f.xid",
    )
    .bind(ids)
    .bind(stamps)
    .execute(&mut *conn)
    .await?
    .rows_affected())
}

/// The expert agent's scan: up to `limit` sessions of the scope in the order
/// their turns landed, after `after` (from the first stamped session when
/// `None`), each active after `active_after` when one is given and not the user
/// `exclude_email`'s. Only sessions landed by a transaction that had ended when
/// the scan began are listed ([`LandedPage::bound`]). A session no turn has
/// landed on since landing order was recorded (`landed_xid` NULL) is never listed.
pub(crate) async fn list_sessions_landed(
    conn: &mut Scoped,
    after: Option<LandedKey>,
    active_after: Option<chrono::DateTime<chrono::Utc>>,
    exclude_email: &str,
    limit: i64,
    scope: &AuditScope,
) -> anyhow::Result<LandedPage> {
    let bound = landing_bound(conn).await?;
    // The list's own filters: `updated_since` is exclusive.
    let mut query = SessionListQuery::default();
    query.updated_since = active_after;
    query.exclude_user = Some(exclude_email.to_string());

    // The bound at `$1`, the position (when there is one) at `$2` / `$3`, the
    // filters after it. The position is a condition only when it is set, so the
    // index range starts there under a generic plan too. No linkage filter is
    // set, so the view the filters are handed binds nothing.
    let mut sql = "SELECT s.session_id, s.landed_xid FROM sessions s WHERE s.landed_xid < $1".to_string();
    let first_filter = if after.is_some() {
        sql.push_str(" AND (s.landed_xid, s.session_id) > ($2, $3)");
        4
    } else {
        2
    };
    let (limit_idx, _) = push_session_filters(&mut sql, &query, scope, LINKED_AT_2, first_filter);
    sql.push_str(&format!(" ORDER BY s.landed_xid, s.session_id LIMIT ${limit_idx}"));
    let mut first = sqlx::query_as::<_, (Uuid, i64)>(sqlx::AssertSqlSafe(&*sql)).bind(bound);
    if let Some(after) = after {
        first = first.bind(after.xid).bind(after.session_id);
    }
    let keys: Vec<(Uuid, i64)> = bind_session_filters(first, &query, scope)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;
    let full = i64::try_from(keys.len()).unwrap_or(i64::MAX) >= limit;
    if keys.is_empty() {
        return Ok(LandedPage { rows: Vec::new(), full, bound });
    }

    // The rows of those keys, through a tenant-wide view: the scope chose them.
    let sql = format!(
        "SELECT {cols} FROM unnest($1::uuid[]) AS k(sid) \
         JOIN sessions s ON s.session_id = k.sid {join} {MODEL_REQUESTED_JOIN} {WORKSPACE_JOIN}",
        cols = session_cols(),
        join = LINKED_AT_2.join(),
    );
    let ids: Vec<Uuid> = keys.iter().map(|k| k.0).collect();
    let rows: Vec<SessionSummaryRow> = sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
        .bind(ids)
        .bind(None::<Uuid>)
        .bind(None::<Vec<Uuid>>)
        .fetch_all(&mut *conn)
        .await?;
    let mut by_id: std::collections::HashMap<Uuid, SessionSummary> =
        into_summaries(conn, rows).await.into_iter().map(|s| (s.session_id, s)).collect();
    // A session deleted between the two reads is left out.
    let rows = keys
        .into_iter()
        .filter_map(|(session_id, xid)| by_id.remove(&session_id).map(|s| (s, LandedKey { xid, session_id })))
        .collect();
    Ok(LandedPage { rows, full, bound })
}

/// Core session list logic — the console's and the portal's.
/// Callers are responsible for clamping `query.limit` to an acceptable maximum
/// before invoking — this function trusts the passed-through value so handlers
/// can overfetch by +1 without the clamp silently stripping it — and for
/// refusing `sort=alerts` with a search term ([`SessionSort::check_with_search`]),
/// which is read here as `newest`.
///
/// A search walks `search_sessions` (001_init.sql) with [`SearchWalk`]: the
/// function answers the text match — the session's model and first prompt, a
/// turn's requested model or response, a message it carried, a system prompt
/// it used — inside the window, the user and the workspaces, and every other
/// filter applies to the keys it returns.
pub(crate) async fn list_sessions_impl(
    conn: &mut Scoped,
    query: SessionListQuery,
    scope: &AuditScope,
) -> anyhow::Result<SearchRows<SessionSummary>> {
    // `parent_session_id` names a session whatever the view: a confined
    // (portal) scope may not use it, or it would tell a member that a session
    // it may not see has children. The `linked` filter reads links through the
    // view (`LinkedView`), as the row's own linkage columns do.
    if scope.linked_view() != (None, None) && query.parent_session_id.is_some() {
        anyhow::bail!("the parent-session filter is not available to a confined scope");
    }
    let limit = query.limit.unwrap_or(SESSIONS_DEFAULT_LIMIT);
    let offset = crate::routes::resolve_offset(query.offset);
    let search = search_pattern(query.search.as_deref());
    let sort = query.sort.unwrap_or_default();

    let (view_user, view_workspaces) = scope.linked_view();
    let model_req_join = MODEL_REQUESTED_JOIN;
    let workspace_join = WORKSPACE_JOIN;

    let Some(pattern) = search else {
        // The view at `$1` / `$2`, the filters after it.
        let linked = LinkedView { user: 1, workspaces: 2 };
        let mut sql = format!(
            "SELECT {cols} FROM sessions s {join} {model_req_join} {workspace_join} WHERE 1=1",
            cols = session_cols(),
            join = linked.join(),
        );
        let (bind_idx, _) = push_session_filters(&mut sql, &query, scope, linked, 3);
        let order_clause = match sort {
            SessionSort::Alerts => "ORDER BY CASE WHEN s.alert_level = 'major' THEN 0 WHEN s.alert_level = 'minor' THEN 1 ELSE 2 END, s.updated_at DESC, s.session_id DESC",
            SessionSort::Oldest => "ORDER BY s.updated_at ASC, s.session_id ASC",
            SessionSort::Newest => "ORDER BY s.updated_at DESC, s.session_id DESC",
        };
        sql.push_str(&format!(" {order_clause} LIMIT ${bind_idx} OFFSET ${}", bind_idx + 1));
        let first = sqlx::query_as(sqlx::AssertSqlSafe(&*sql)).bind(view_user).bind(view_workspaces);
        let rows: Vec<SessionSummaryRow> = bind_session_filters(first, &query, scope)
            .bind(limit)
            .bind(offset)
            .fetch_all(&mut *conn)
            .await?;
        let rows = into_summaries(conn, rows).await;
        return Ok(SearchRows { rows, scan_cut: false });
    };

    // The keys come back in the walk's order; the page keeps it. The filters
    // and the limit run on the bare session rows first, so only the rows the
    // page still needs reach the per-session joins (the latest turn's model is
    // a probe across every turn partition).
    let mut sql = "WITH page AS MATERIALIZED ( \
         SELECT s.session_id, k.ord FROM unnest($1::uuid[]) WITH ORDINALITY AS k(sid, ord) \
         JOIN sessions s ON s.session_id = k.sid WHERE 1=1"
        .to_string();
    // The keys at `$1`, the view at `$2` / `$3`, the filters after it.
    let (limit_idx, post_filtered) = push_session_filters(&mut sql, &query, scope, LINKED_AT_2, 4);
    sql.push_str(&format!(
        " ORDER BY k.ord LIMIT ${limit_idx}) \
         SELECT {cols} FROM page p JOIN sessions s ON s.session_id = p.session_id \
         {join} {model_req_join} {workspace_join} ORDER BY p.ord",
        cols = session_cols(),
        join = LINKED_AT_2.join(),
    ));

    // The search's own window: the tightest of the two bounds each side.
    let from = query.start.into_iter().chain(query.updated_since).max();
    let to = query.end.into_iter().chain(query.updated_before).min();
    // The workspace filter as the search applies it: an unattributed session
    // (`include_keyless`) is the one in the nil workspace, as below.
    let search_workspaces = scope.workspace_ids().map(|ids| {
        let mut ids = ids.to_vec();
        if scope.include_keyless() {
            ids.push(Uuid::nil());
        }
        ids
    });
    let oldest_first = sort == SessionSort::Oldest;
    let mut walk = SearchWalk::new(offset.saturating_add(limit), post_filtered);
    let mut seen: HashSet<Uuid> = HashSet::new();
    let mut rows: Vec<SessionSummaryRow> = Vec::new();
    loop {
        let (cursor_ts, cursor_id) = walk.cursor().unzip();
        let keys = sqlx::query_as::<_, (Uuid, chrono::DateTime<chrono::Utc>)>(
            "SELECT session_id, updated_at FROM search_sessions($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&pattern)
        .bind(from)
        .bind(to)
        .bind(oldest_first)
        .bind(cursor_ts)
        .bind(cursor_id)
        .bind(walk.batch())
        .bind(scope.user_id())
        .bind(search_workspaces.clone())
        .fetch_all(&mut *conn)
        .await?;
        // `updated_at` moves with every ingest, so a session updated between two
        // calls moves past the cursor: oldest first it can come back from the
        // second (it is listed where first seen); newest first it jumps above
        // the cursor and this walk does not list it — the next load lists it
        // first, which is what a newest-first list means.
        let fresh: Vec<Uuid> = keys.iter().map(|k| k.0).filter(|id| seen.insert(*id)).collect();
        if !fresh.is_empty() {
            let first = sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
                .bind(fresh)
                .bind(view_user)
                .bind(view_workspaces.clone());
            let found: Vec<SessionSummaryRow> = bind_session_filters(first, &query, scope)
                .bind(i64::try_from(walk.needed().saturating_sub(rows.len())).unwrap_or(i64::MAX))
                .fetch_all(&mut *conn)
                .await?;
            rows.extend(found);
        }
        if !walk.advance(keys.len(), keys.last().map(|k| (k.1, k.0)), rows.len()) {
            break;
        }
    }
    let rows: Vec<SessionSummaryRow> = rows
        .into_iter()
        .skip(usize::try_from(offset).unwrap_or(0))
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .collect();
    let rows = into_summaries(conn, rows).await;
    Ok(SearchRows { rows, scan_cut: walk.cut() })
}

/// Append the session list's filters to `sql`, numbering binds from
/// `bind_idx`; [`bind_session_filters`] binds them in the same order. Returns
/// the next bind index, and whether a filter the search lookup does not apply
/// itself was added (it applies the user, the workspaces and the window's
/// inclusive bounds).
fn push_session_filters(
    sql: &mut String,
    query: &SessionListQuery,
    scope: &AuditScope,
    view: LinkedView,
    mut bind_idx: u32,
) -> (u32, bool) {
    let mut post_filtered = false;
    if scope.user_id().is_some() {
        sql.push_str(&format!(" AND s.user_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.model.is_some() {
        sql.push_str(&format!(" AND s.model_used ILIKE ${bind_idx}"));
        bind_idx += 1;
        post_filtered = true;
    }
    if query.start.is_some() {
        sql.push_str(&format!(" AND s.updated_at >= ${bind_idx}"));
        bind_idx += 1;
    }
    if query.end.is_some() {
        sql.push_str(&format!(" AND s.updated_at < ${bind_idx}"));
        bind_idx += 1;
    }
    if query.alert_level.is_some() {
        sql.push_str(&format!(" AND s.alert_level = ${bind_idx}"));
        bind_idx += 1;
        post_filtered = true;
    }
    if query.updated_since.is_some() {
        // Exclusive, where the search's lower bound is inclusive: it narrows
        // the search's keys afterwards.
        sql.push_str(&format!(" AND s.updated_at > ${bind_idx}"));
        bind_idx += 1;
        post_filtered = true;
    }
    if query.updated_before.is_some() {
        sql.push_str(&format!(" AND s.updated_at < ${bind_idx}"));
        bind_idx += 1;
    }
    if query.app_id.is_some() {
        sql.push_str(&format!(" AND s.app_id = ${bind_idx}"));
        bind_idx += 1;
        post_filtered = true;
    }
    if query.exclude_user.is_some() {
        sql.push_str(&format!(
            " AND (s.user_email IS NULL OR s.user_email != ${bind_idx})"
        ));
        bind_idx += 1;
        post_filtered = true;
    }
    if query.user_email.is_some() {
        sql.push_str(&format!(" AND s.user_email ILIKE ${bind_idx}"));
        bind_idx += 1;
        post_filtered = true;
    }
    // `parent_session_id` asks about links whatever the view:
    // `list_sessions_impl` refuses it to a confined scope.
    if query.parent_session_id.is_some() {
        // The sessions linked to the given one: each is the linked member of a
        // relation whose other member is the queried session.
        sql.push_str(&format!(
            " AND EXISTS (SELECT 1 FROM cross_session_relation_members cm \
                JOIN cross_session_relation_members pm ON pm.relation_id = cm.relation_id AND pm.role = {OTHER_ROLE} \
                JOIN cross_session_relations r ON r.id = cm.relation_id AND r.kind IN {LINK_KINDS} \
                WHERE cm.session_id = s.session_id AND cm.role IN {UPWARD_ROLES} AND pm.session_id = ${bind_idx})"
        ));
        bind_idx += 1;
        post_filtered = true;
    }
    if scope.workspace_ids().is_some() {
        // The session's OWN workspace, never its issuing key's: an MCP session
        // authenticated by a spec-OAuth token carries that token's jti in
        // `key_id` rather than an `api_keys` id, and the console always sends
        // an explicit workspace set.
        let unattributed = if scope.include_keyless() {
            "s.workspace_id = '00000000-0000-0000-0000-000000000000'::uuid OR "
        } else {
            ""
        };
        sql.push_str(&format!(
            " AND ({unattributed}s.workspace_id = ANY(${bind_idx}))"
        ));
        bind_idx += 1;
    }
    // Linkage as the row states it through the view: a linked session the
    // view admits (what `links` counts), a session it is linked to that the
    // view admits (what `link` names). A link to a session outside the view is no
    // link here, so the filter never says one exists.
    let has_children = format!("EXISTS (SELECT 1 {linked})", linked = view.linked_from());
    let has_parent = format!("EXISTS (SELECT 1 {linked})", linked = view.as_linked("s.session_id"));
    match query.linked {
        Some(SessionLinkage::HasChildren) => sql.push_str(&format!(" AND {has_children}")),
        Some(SessionLinkage::HasParent) => sql.push_str(&format!(" AND {has_parent}")),
        Some(SessionLinkage::Unlinked) => sql.push_str(&format!(" AND NOT {has_children} AND NOT {has_parent}")),
        None => {}
    }
    (bind_idx, post_filtered || query.linked.is_some())
}

/// Bind [`push_session_filters`]' parameters, in its order.
fn bind_session_filters<'q, O>(
    mut q: sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
    query: &SessionListQuery,
    scope: &'q AuditScope,
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
    if let Some(user_id) = scope.user_id() {
        q = q.bind(user_id);
    }
    if let Some(model) = &query.model {
        q = q.bind(contains_pattern(model));
    }
    if let Some(start_ts) = query.start {
        q = q.bind(start_ts);
    }
    if let Some(end_ts) = query.end {
        q = q.bind(end_ts);
    }
    if let Some(alert_level) = query.alert_level {
        q = q.bind(alert_level.as_str());
    }
    if let Some(updated_since) = query.updated_since {
        q = q.bind(updated_since);
    }
    if let Some(updated_before) = query.updated_before {
        q = q.bind(updated_before);
    }
    if let Some(app_id) = &query.app_id {
        q = q.bind(app_id.clone());
    }
    if let Some(exclude_user) = &query.exclude_user {
        q = q.bind(exclude_user.clone());
    }
    if let Some(user_email) = &query.user_email {
        q = q.bind(contains_pattern(user_email));
    }
    if let Some(parent_session_id) = query.parent_session_id {
        q = q.bind(parent_session_id);
    }
    if let Some(workspace_ids) = scope.workspace_ids() {
        q = q.bind(workspace_ids);
    }
    q
}

#[cfg(test)]
mod spend_tests {
    use super::*;

    fn eur() -> Currency {
        Currency::parse("EUR").unwrap()
    }

    /// One case per state of the row's classification, charged and not: a
    /// session that charged nothing states zero in the accounting currency
    /// whatever its state; otherwise only a row in one currency states its
    /// total.
    #[test]
    fn a_session_states_its_spend_only_in_one_currency() {
        let usd = |amount| Some((Currency::USD, amount));
        for (count, currency, total, expect) in [
            (0, None, 0.0, Some((eur(), 0.0))),
            (0, None, 1.5, None),
            (1, Some("USD"), 1.5, usd(1.5)),
            (1, Some("USD"), 0.0, Some((eur(), 0.0))),
            (1, None, 1.5, None),
            (1, Some("dollars"), 1.5, None),
            (2, None, 1.5, None),
            (2, None, 0.0, Some((eur(), 0.0))),
        ] {
            let got = session_spend(count, currency.map(str::to_string), total, eur());
            assert_eq!(got.map(|s| (s.currency, s.amount)), expect, "count {count:?} currency {currency:?}");
        }
    }
}

#[cfg(test)]
mod link_tests {

    use super::*;

    fn columns(kind: &str, confidence: &str) -> LinkColumns {
        LinkColumns {
            link_session_id: Some(Uuid::nil()),
            link_kind: Some(kind.to_string()),
            link_confidence: Some(confidence.to_string()),
            link_spawn_turn: Some(3),
            link_spawn_tool_call_id: Some("call_1".to_string()),
            ..LinkColumns::default()
        }
    }

    /// One case per stored kind and confidence, and the values no writer
    /// stores: an unknown kind is no link, an unknown confidence an expert's
    /// medium, as the expert's own parser reads it.
    #[test]
    fn every_stored_link_is_stated_in_the_api_vocabulary() {
        for (kind, expect) in [
            ("linkage", Some(SessionLinkKind::SubAgent)),
            ("continuation", Some(SessionLinkKind::Continuation)),
            ("auxiliary", None),
            ("issue", None),
        ] {
            assert_eq!(columns(kind, "content").link().map(|l| l.kind), expect, "{kind}");
        }
        for (confidence, expect) in [
            ("content", SessionLinkEvidence::Quote),
            ("high", SessionLinkEvidence::AgentHigh),
            ("medium", SessionLinkEvidence::AgentMedium),
            ("certain", SessionLinkEvidence::AgentMedium),
        ] {
            assert_eq!(columns("linkage", confidence).link().map(|l| l.evidence), Some(expect), "{confidence}");
        }
    }

    /// A spawn point is a sub-agent's alone, and needs its turn; the call is
    /// stated only when stored.
    #[test]
    fn only_a_sub_agent_names_where_it_was_spawned() {
        let anchor = SpawnAnchor { turn_number: 3, tool_call_id: Some("call_1".to_string()) };
        assert_eq!(columns("linkage", "content").link().and_then(|l| l.spawned_at), Some(anchor));
        assert_eq!(columns("continuation", "content").link().and_then(|l| l.spawned_at), None);
        let turn_only = LinkColumns { link_spawn_tool_call_id: None, ..columns("linkage", "high") };
        assert_eq!(
            turn_only.link().and_then(|l| l.spawned_at),
            Some(SpawnAnchor { turn_number: 3, tool_call_id: None })
        );
        let no_turn = LinkColumns { link_spawn_turn: None, ..columns("linkage", "high") };
        assert_eq!(no_turn.link().and_then(|l| l.spawned_at), None);
        let unnamed = LinkColumns { link_session_id: None, ..columns("linkage", "high") };
        assert!(unnamed.link().is_none());
    }

    /// Counts are stated when anything is linked, a continuation alone included.
    #[test]
    fn linked_counts_are_absent_only_when_nothing_is_linked() {
        assert_eq!(LinkColumns::default().links(), None);
        let zero = LinkColumns { links_sub_agents: Some(0), ..LinkColumns::default() };
        assert_eq!(zero.links(), None);
        let continued = LinkColumns { links_continued_in: Some(Uuid::nil()), ..zero };
        assert_eq!(
            continued.links(),
            Some(LinkedCounts { sub_agents: 0, continued_in: Some(Uuid::nil()) })
        );
        let sub = LinkColumns { links_sub_agents: Some(2), ..LinkColumns::default() };
        assert_eq!(sub.links().map(|c| c.sub_agents), Some(2));
    }
}
