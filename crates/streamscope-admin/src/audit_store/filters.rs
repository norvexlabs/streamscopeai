//! The SQL every fact read is assembled from: the FROM-clause joins of
//! `gateway_audit` to each child (`llm_audit`, `mcp_audit`, `web_audit`,
//! `a2a_audit`), and the dashboards' WHERE-clause builder.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// FROM-clause fragment that joins the two-table audit shape (`gateway_audit`
/// parent + `llm_audit` child, migration `001_init.sql`). References to
/// `request_id`, `timestamp`, and `tenant_id` resolve unambiguously to the
/// merged `USING` columns; other gateway columns (user_id, key_id, app_id,
/// session_id, user_agent, ip, detection_method, kind, latency_total_ms,
/// status_code, error_*) route to `g`, and LLM-specific columns route to `a`,
/// so a query names most columns bare and only the FROM clause carries the
/// join.
pub const AUDIT_LOG_JOIN: &str =
    "gateway_audit g JOIN llm_audit a USING (request_id, timestamp, tenant_id)";

/// FROM-clause fragment for the MCP audit join. Sibling of `AUDIT_LOG_JOIN`.
/// `gateway_audit g` is on the left so columns named bare resolve identically
/// across the two consts (status_code, latency_total_ms, user_id, etc. all
/// route to `g`). MCP-specific columns (method, virtual_server_id, tool_id,
/// resource_uri, ...) route to `m`.
pub const MCP_AUDIT_JOIN: &str =
    "gateway_audit g JOIN mcp_audit m USING (request_id, timestamp, tenant_id)";

/// FROM-clause fragment for the web-search audit join. Sibling of
/// `AUDIT_LOG_JOIN` and `MCP_AUDIT_JOIN`. Web-specific columns route to `w`.
pub const WEB_AUDIT_JOIN: &str =
    "gateway_audit g JOIN web_audit w USING (request_id, timestamp, tenant_id)";

/// FROM-clause fragment for the A2A audit join. Sibling of `AUDIT_LOG_JOIN`
/// and `MCP_AUDIT_JOIN`. A2A-specific columns route to `a2`.
pub const A2A_AUDIT_JOIN: &str =
    "gateway_audit g JOIN a2a_audit a2 USING (request_id, timestamp, tenant_id)";

/// The timestamp columns a window is stated on, one per partitioned table of
/// the join. Postgres prunes a table's partitions only by a condition on that
/// table: the join's equality does not carry a range across, and a bare
/// `timestamp` under `USING` is `g`'s. So a windowed read of
/// `AUDIT_LOG_JOIN` states the window on both `g` and `a`, or it scans every
/// retained week of `llm_audit`. Pass one of these to `push_time_window` /
/// `window_sql`, never a single side of a join.
pub const AUDIT_LOG_WINDOW: &[&str; 2] = &["g.timestamp", "a.timestamp"];
/// Window columns of `MCP_AUDIT_JOIN`; see `AUDIT_LOG_WINDOW`.
pub const MCP_AUDIT_WINDOW: &[&str; 2] = &["g.timestamp", "m.timestamp"];
/// Window columns of `WEB_AUDIT_JOIN`; see `AUDIT_LOG_WINDOW`.
pub const WEB_AUDIT_WINDOW: &[&str; 2] = &["g.timestamp", "w.timestamp"];
/// Window columns of `A2A_AUDIT_JOIN`; see `AUDIT_LOG_WINDOW`.
pub const A2A_AUDIT_WINDOW: &[&str; 2] = &["g.timestamp", "a2.timestamp"];
/// Window columns of `AUDIT_LOG_JOIN` joined to its turn (`conversation_turns ct`).
pub const AUDIT_LOG_TURN_WINDOW: &[&str; 3] = &["g.timestamp", "a.timestamp", "ct.timestamp"];

/// `AND {col} >= $lo` then `AND {col} < $hi` for every column of `cols`, all
/// reading the same two placeholders — the window of a hand-written fact read.
/// `cols` is a fixed-size array: an empty one fails to compile at its call,
/// never leaving a statement silently without its window.
pub fn window_sql<const N: usize>(cols: &'static [&'static str; N], lo: u32, hi: u32) -> String {
    since_sql(cols, lo) + until_sql(cols, hi).as_str()
}

/// `AND {col} >= $lo` for every column of `cols` — a window open at its end.
pub fn since_sql<const N: usize>(cols: &'static [&'static str; N], lo: u32) -> String {
    const { assert!(N > 0, "a window on no column bounds nothing") };
    cols.iter().map(|col| format!(" AND {col} >= ${lo}")).collect()
}

/// `AND {col} < $hi` for every column of `cols` — a window open at its start.
pub fn until_sql<const N: usize>(cols: &'static [&'static str; N], hi: u32) -> String {
    const { assert!(N > 0, "a window on no column bounds nothing") };
    cols.iter().map(|col| format!(" AND {col} < ${hi}")).collect()
}

/// Owned bind value carried by `AnalyticsFilterBuilder`. Internal — handlers
/// don't construct these directly.
#[derive(Debug, Clone)]
enum FilterBind {
    Uuid(Uuid),
    UuidArray(Vec<Uuid>),
    Str(String),
    DateTime(DateTime<Utc>),
}

/// Builder for analytics WHERE-clause SQL fragments + ordered bind values.
///
/// Centralises the "build dynamic WHERE + track bind index + bind values in
/// order" pattern across every analytics handler. Use granular `push_*`
/// methods so each handler emits only the columns its target table actually
/// has — this keeps the helper schema-aware without baking a table-by-table
/// preset list into the type.
///
/// Usage:
/// ```ignore
/// let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
/// let scope = query.scope();
/// let mut filters = AnalyticsFilterBuilder::new(2);  // $1 reserved for tenant_id
/// filters.push_time_window(AUDIT_LOG_WINDOW, (start, end));
/// if let Some(uid) = scope.user_id { filters.push_eq_uuid("user_id", uid); }
/// if let Some(ws) = &scope.workspace_ids { filters.push_workspaces("g.workspace_id", ws); }
///
/// let sql = format!("SELECT ... FROM {AUDIT_LOG_JOIN} WHERE tenant_id = $1{}", filters.where_sql());
/// let mut q = sqlx::query_as::<_, MyRow>(&sql).bind(tenant_id);
/// q = filters.apply_query_as(q);
/// ```
///
/// # Column names are `&'static str` — keep them that way
///
/// Every `push_*` interpolates its column name straight into the SQL, because a
/// column is an identifier and Postgres does not bind identifiers. The *values*
/// are always bound (`$N`), so the column name is the only injection surface —
/// and `&'static str` closes it in the type system: a `String` built from an HTTP
/// query parameter cannot coerce to `&'static str`, so `push_eq_str(&query.sort,
/// …)` does not compile. Widening any of these back to `&str` would silently
/// reopen that surface; the bound is load-bearing, not incidental.
#[allow(dead_code)]
pub struct AnalyticsFilterBuilder {
    sql: String,
    next_idx: u32,
    binds: Vec<FilterBind>,
}

#[allow(dead_code)]
impl AnalyticsFilterBuilder {
    /// `first_bind_idx` is the next placeholder index after the caller's
    /// existing binds (e.g. 2 if `$1 = tenant_id`).
    pub fn new(first_bind_idx: u32) -> Self {
        Self { sql: String::new(), next_idx: first_bind_idx, binds: Vec::new() }
    }

    /// Append `AND {col} >= $N AND {col} < $N+1` for every column of `cols`;
    /// bind start, end once. Over a join of facts, `cols` names the timestamp
    /// of every fact in it (`AUDIT_LOG_WINDOW`, …); over one table, that
    /// table's column alone (`&["timestamp"]`). Returns the two placeholders,
    /// for a fact the caller joins outside these conditions (an outer join's
    /// ON clause).
    pub fn push_time_window<const N: usize>(
        &mut self,
        cols: &'static [&'static str; N],
        window: (DateTime<Utc>, DateTime<Utc>),
    ) -> (u32, u32) {
        let placeholders = (self.next_idx, self.next_idx + 1);
        self.sql.push_str(&window_sql(cols, placeholders.0, placeholders.1));
        self.binds.push(FilterBind::DateTime(window.0));
        self.binds.push(FilterBind::DateTime(window.1));
        self.next_idx += 2;
        placeholders
    }

    /// Append `AND {col} = $N` for a UUID. `col` is verbatim — pass
    /// `"user_id"` for single-table queries or `"s.user_id"` when disambiguating
    /// joined columns.
    pub fn push_eq_uuid(&mut self, col: &'static str, value: Uuid) {
        self.sql.push_str(&format!(" AND {col} = ${}", self.next_idx));
        self.binds.push(FilterBind::Uuid(value));
        self.next_idx += 1;
    }

    /// Append `AND {col} != $N` for a UUID.
    pub fn push_ne_uuid(&mut self, col: &'static str, value: Uuid) {
        self.sql.push_str(&format!(" AND {col} != ${}", self.next_idx));
        self.binds.push(FilterBind::Uuid(value));
        self.next_idx += 1;
    }

    /// Append the workspace filter `AND {col} = ANY($N)` over a set of workspace
    /// ids. `col` selects the alias the handler's FROM clause uses —
    /// `"g.workspace_id"` under an audit join, bare `"workspace_id"` over
    /// `gateway_audit`, or `"sessions.workspace_id"` / `"s.workspace_id"` over
    /// `sessions`, which carries its own attribution. A workspace
    /// is matched when it is in the requested set; the UI ships every workspace
    /// except the Agent one by default, so agent traffic is hidden simply by not
    /// being selected — no special-case predicate.
    pub fn push_workspaces(&mut self, col: &'static str, ids: &[Uuid]) {
        self.sql.push_str(&format!(" AND {col} = ANY(${})", self.next_idx));
        self.binds.push(FilterBind::UuidArray(ids.to_vec()));
        self.next_idx += 1;
    }

    /// Append a correlated workspace `EXISTS` for handlers whose FROM clause
    /// (`conversation_turns` join `sessions`) carries no `workspace_id` column.
    /// Matches the turn's audit row by `(request_id, timestamp, tenant_id)` and
    /// requires that row's `workspace_id` be in the requested set. Pass the
    /// turn-side column names, and the placeholders of the turn's window (what
    /// `push_time_window` returned), which bound the audit row too so the
    /// probe reads only the window's partitions.
    pub fn push_exists_workspaces(
        &mut self,
        rid_col: &'static str,
        ts_col: &'static str,
        tenant_col: &'static str,
        (lo, hi): (u32, u32),
        ids: &[Uuid],
    ) {
        let window = window_sql(&["g.timestamp"], lo, hi);
        self.sql.push_str(&format!(
            " AND EXISTS (SELECT 1 FROM gateway_audit g WHERE g.request_id = {rid_col} \
             AND g.timestamp = {ts_col} AND g.tenant_id = {tenant_col}{window} AND g.workspace_id = ANY(${}))",
            self.next_idx
        ));
        self.binds.push(FilterBind::UuidArray(ids.to_vec()));
        self.next_idx += 1;
    }

    /// Append a dashboard's scope filters over `gateway_audit g` — app, user,
    /// workspaces — each only when given. The MCP, A2A, Web and LLM-usage
    /// dashboards scope through this one method.
    pub fn push_scope(&mut self, app: Option<&str>, user: Option<Uuid>, workspaces: Option<&[Uuid]>) {
        if let Some(app) = app {
            self.push_eq_str("g.app_id", app);
        }
        if let Some(uid) = user {
            self.push_eq_uuid("g.user_id", uid);
        }
        if let Some(ws) = workspaces {
            self.push_workspaces("g.workspace_id", ws);
        }
    }

    /// Append `AND {col} = $N` for a string.
    pub fn push_eq_str(&mut self, col: &'static str, value: &str) {
        self.sql.push_str(&format!(" AND {col} = ${}", self.next_idx));
        self.binds.push(FilterBind::Str(value.to_string()));
        self.next_idx += 1;
    }

    /// Append `AND {col} ILIKE $N` for case-insensitive substring match.
    pub fn push_ilike(&mut self, col: &'static str, value: &str) {
        self.sql.push_str(&format!(" AND {col} ILIKE ${}", self.next_idx));
        self.binds.push(FilterBind::Str(value.to_string()));
        self.next_idx += 1;
    }

    /// SQL fragment with all pushed conditions, leading with " AND " (or empty).
    pub fn where_sql(&self) -> &str {
        &self.sql
    }

    /// Next placeholder index — for handlers that bind extra fields after.
    pub fn next_bind_idx(&self) -> u32 {
        self.next_idx
    }

    /// Apply ordered binds to a `query_as`. Returns the bound query.
    pub fn apply_query_as<'q, O>(
        &self,
        mut q: sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
        for b in &self.binds {
            q = match b {
                FilterBind::Uuid(v) => q.bind(*v),
                FilterBind::UuidArray(v) => q.bind(v.clone()),
                FilterBind::Str(v) => q.bind(v.clone()),
                FilterBind::DateTime(v) => q.bind(*v),
            };
        }
        q
    }

    /// Apply ordered binds to a `query_scalar`. Returns the bound query.
    pub fn apply_query_scalar<'q, O>(
        &self,
        mut q: sqlx::query::QueryScalar<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
        for b in &self.binds {
            q = match b {
                FilterBind::Uuid(v) => q.bind(*v),
                FilterBind::UuidArray(v) => q.bind(v.clone()),
                FilterBind::Str(v) => q.bind(v.clone()),
                FilterBind::DateTime(v) => q.bind(*v),
            };
        }
        q
    }

    /// Apply ordered binds to a non-typed `query`. Returns the bound query.
    pub fn apply_query<'q>(
        &self,
        mut q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        for b in &self.binds {
            q = match b {
                FilterBind::Uuid(v) => q.bind(*v),
                FilterBind::UuidArray(v) => q.bind(v.clone()),
                FilterBind::Str(v) => q.bind(v.clone()),
                FilterBind::DateTime(v) => q.bind(*v),
            };
        }
        q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_builder_emits_expected_sql() {
        let mut fb = AnalyticsFilterBuilder::new(2);
        let s = Utc::now() - chrono::Duration::days(7);
        let e = Utc::now();
        fb.push_time_window(&["timestamp"], (s, e));
        fb.push_eq_uuid("user_id", Uuid::nil());
        fb.push_ne_uuid("user_id", Uuid::nil());
        let sql = fb.where_sql();
        assert!(sql.contains("timestamp >= $2 AND timestamp < $3"));
        assert!(sql.contains("user_id = $4"));
        assert!(sql.contains("user_id != $5"));
        assert_eq!(fb.next_bind_idx(), 6);
    }

    #[test]
    fn a_join_window_bounds_every_fact_on_the_same_binds() {
        let mut fb = AnalyticsFilterBuilder::new(2);
        fb.push_time_window(AUDIT_LOG_WINDOW, (Utc::now(), Utc::now()));
        assert_eq!(
            fb.where_sql(),
            " AND g.timestamp >= $2 AND a.timestamp >= $2 AND g.timestamp < $3 AND a.timestamp < $3"
        );
        assert_eq!(fb.binds.len(), 2);
        assert_eq!(fb.next_bind_idx(), 4);
    }

    #[test]
    fn an_open_window_bounds_every_fact_from_the_start_inclusive_to_the_end_exclusive() {
        assert_eq!(since_sql(AUDIT_LOG_WINDOW, 4), " AND g.timestamp >= $4 AND a.timestamp >= $4");
        assert_eq!(until_sql(AUDIT_LOG_WINDOW, 5), " AND g.timestamp < $5 AND a.timestamp < $5");
    }

    #[test]
    fn the_workspace_probe_bounds_the_audit_row_by_the_window() {
        let mut fb = AnalyticsFilterBuilder::new(2);
        let window = fb.push_time_window(&["ct.timestamp"], (Utc::now(), Utc::now()));
        assert_eq!(window, (2, 3));
        fb.push_exists_workspaces("ct.request_id", "ct.timestamp", "ct.tenant_id", window, &[Uuid::nil()]);
        let sql = fb.where_sql();
        assert!(sql.contains("g.tenant_id = ct.tenant_id AND g.timestamp >= $2 AND g.timestamp < $3"), "{sql}");
        assert!(sql.contains("g.workspace_id = ANY($4)"), "{sql}");
    }

    #[test]
    fn filter_builder_handles_qualified_columns() {
        let mut fb = AnalyticsFilterBuilder::new(3);
        fb.push_eq_str("s.app_id", "claude-code");
        fb.push_eq_uuid("s.user_id", Uuid::nil());
        fb.push_ilike("a.model_used", "gpt-4%");
        let sql = fb.where_sql();
        assert!(sql.contains("s.app_id = $3"));
        assert!(sql.contains("s.user_id = $4"));
        assert!(sql.contains("a.model_used ILIKE $5"));
    }
}
