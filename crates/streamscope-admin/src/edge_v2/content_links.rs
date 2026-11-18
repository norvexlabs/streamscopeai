//! Links between conversations, read from what a new one QUOTES.
//!
//! A conversation's opening (`streamscope_core::proxy::fingerprint`) may quote
//! a recent turn of the same user:
//!
//! | The opening carries… | Relation (quoting session's role) |
//! |---|---|
//! | the whole of a string argument of one of its tool calls (of 3 lines or more, or half the opening) | `linkage` (`child`), anchored on that call |
//! | 3 lines of its answer, or the whole of it as half the opening or more | `continuation` (`successor`) — the agent's compaction |
//!
//! Each rule holds on its own, so a link is only ever written from a true
//! quote; among the texts an opening quotes, the one it carries the most lines
//! of wins (an argument on a tie, an answer when both reach the cap): a
//! subagent's prompt carries its argument
//! whole and little of any answer, a compaction's summary carries the answer
//! and any argument it repeats is a part of it. Nothing quoted, no link — a
//! missed link is acceptable, a wrong one is not; no header ever links.
//!
//! A text is quoted only once it exists — an answer or an argument from its
//! turn's end — by an opening that starts later (give or take
//! [`CLOCK_MARGIN_SECS`], two edges' clocks): an answer within
//! [`WINDOW_HOURS`], an argument within [`ARGUMENT_WINDOW_MINUTES`] (a subagent
//! opens moments after its call; a file a call wrote, pasted later, is no
//! spawn). An opening is ignored when its session already had a turn before it
//! (a turn of a session under way served where its history was not held).
//!
//! Turns land in either order (two replicas, two outboxes), so one decision
//! ([`decide`]) is taken from the stored rows for every opening a landing turn
//! touches: its own, and each later one that quotes it. A session is linked
//! at most once (the one-link index), the first link written; whichever true
//! quote lands first may be that one. Each quoting session is decided under a
//! savepoint of its own, in session order, so a failure loses only its link.

use chrono::{DateTime, Utc};
use streamscope_core::proxy::fingerprint::{ANSWER_MAX, TurnFingerprints};
use uuid::Uuid;

use crate::db::tenant::IngestConn;

/// How far back an answer is quoted, in hours — and how long the fingerprints
/// are kept.
pub(crate) const WINDOW_HOURS: i32 = 24;

/// How far back a tool-call argument is quoted, in minutes: a subagent opens
/// right after the call that spawns it. Retention drops argument rows past it.
pub(crate) const ARGUMENT_WINDOW_MINUTES: i32 = 15;

/// How much later than an opening's start a quoted text may have come to
/// exist, in seconds: two edges' clocks differ.
const CLOCK_MARGIN_SECS: i32 = 5;

/// The fewest lines of a text an opening must carry, unless it carries the
/// text whole as half its own lines or more.
const QUOTE_MIN: i64 = 3;

/// A turn the ingest just inserted, and what it can quote or be quoted by.
pub(crate) struct LandedTurn<'r> {
    pub tenant: Uuid,
    pub user: Uuid,
    pub request: Uuid,
    pub session: Uuid,
    pub turn_number: Option<i32>,
    /// When the request reached the gateway: its opening exists from then.
    pub started: DateTime<Utc>,
    /// When its answer was complete: its answer and arguments exist from then.
    pub ended: DateTime<Utc>,
    pub fingerprints: &'r TurnFingerprints,
}

/// What kind of text of an earlier turn is quoted; on a tie of lines carried,
/// the first is preferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Argument,
    Answer,
}

impl Kind {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "argument" => Some(Kind::Argument),
            "answer" => Some(Kind::Answer),
            _ => None,
        }
    }
}

/// One text of an earlier turn, and how many of its lines an opening carries.
#[derive(Debug, Clone, PartialEq)]
struct Quoted {
    kind: Kind,
    session: Uuid,
    request: Uuid,
    turn_number: Option<i32>,
    tool_call_id: String,
    part: i16,
    part_size: i16,
    /// When the text came to exist (see [`LandedTurn`]).
    timestamp: DateTime<Utc>,
    hits: i64,
}

impl Quoted {
    /// Whether an opening of `opening_size` lines quotes this text: 3 of its
    /// lines (an argument only whole), or the whole of it as half the opening
    /// or more — so one stray line shared by two conversations is no quote.
    fn is_quoted(&self, opening_size: i64) -> bool {
        let size = i64::from(self.part_size);
        let whole = size > 0 && self.hits == size;
        let half = 2 * self.hits >= opening_size;
        match self.kind {
            Kind::Argument => whole && (size >= QUOTE_MIN || half),
            Kind::Answer => self.hits >= QUOTE_MIN || (whole && half),
        }
    }
}

/// The text an opening of `opening_size` lines quotes among `quoted`: the one
/// it carries the most lines of, an argument on a tie — an answer when both
/// are carried to the cap, where a long summary can no longer outnumber an
/// argument it repeats — then the most recent turn; or none.
fn quoted_by(opening_size: i64, quoted: &[Quoted]) -> Option<&Quoted> {
    let at_cap = |q: &Quoted| usize::try_from(q.hits).is_ok_and(|h| h >= ANSWER_MAX);
    quoted.iter().filter(|q| q.is_quoted(opening_size)).min_by(|a, b| {
        let kinds = if at_cap(a) && at_cap(b) { b.kind.cmp(&a.kind) } else { a.kind.cmp(&b.kind) };
        b.hits
            .cmp(&a.hits)
            .then(kinds)
            .then(b.timestamp.cmp(&a.timestamp))
            .then(a.request.cmp(&b.request))
            .then(a.tool_call_id.cmp(&b.tool_call_id))
            .then(a.part.cmp(&b.part))
    })
}

/// Store the fingerprints of `turns` and write the links they make. Best
/// effort: a failure is logged and undone, and never fails the ingest.
pub(crate) async fn link_turns(conn: &mut IngestConn, turns: &[LandedTurn<'_>]) {
    if turns.is_empty() {
        return;
    }
    // The fingerprints under a savepoint of their own: a link that fails must
    // not take them with it — a turn's texts are stored once, when it lands.
    let stored = async {
        let mut sp = conn.savepoint().await?;
        store(sp.conn(), turns).await?;
        sp.commit().await
    }
    .await;
    if let Err(e) = stored {
        tracing::warn!("fingerprints of {} turn(s) not stored: {e}", turns.len());
        return;
    }
    // Every read and write on the request's transaction runs under a
    // savepoint: a statement that fails outside one would abort it, and the
    // whole share with it.
    let touched = async {
        let mut sp = conn.savepoint().await?;
        let openings = openings_touched(sp.conn(), turns).await?;
        sp.commit().await.map(|()| openings)
    }
    .await;
    let openings = match touched {
        Ok(openings) => openings,
        Err(e) => {
            tracing::warn!("content links of {} turn(s) not looked for: {e}", turns.len());
            return;
        }
    };
    for opening in openings {
        let decided = async {
            let mut sp = conn.savepoint().await?;
            decide(sp.conn(), &opening).await?;
            sp.commit().await
        }
        .await;
        if let Err(e) = decided {
            tracing::warn!(session = %opening.session, "content link not written: {e}");
        }
    }
}

/// One row per segment of each text of each turn.
async fn store(conn: &mut IngestConn, turns: &[LandedTurn<'_>]) -> Result<(), sqlx::Error> {
    #[derive(Default)]
    struct Rows {
        tenant: Vec<Uuid>,
        user: Vec<Uuid>,
        kind: Vec<&'static str>,
        fp: Vec<i64>,
        request: Vec<Uuid>,
        session: Vec<Uuid>,
        turn_number: Vec<Option<i32>>,
        tool_call_id: Vec<String>,
        part: Vec<i16>,
        part_size: Vec<i16>,
        timestamp: Vec<DateTime<Utc>>,
    }
    let mut rows = Rows::default();
    let mut push = |turn: &LandedTurn<'_>, kind: &'static str, tool_call_id: &str, part: i16, segments: &[i64], at: DateTime<Utc>| {
        let part_size = i16::try_from(segments.len()).unwrap_or(i16::MAX);
        for fp in segments {
            rows.tenant.push(turn.tenant);
            rows.user.push(turn.user);
            rows.kind.push(kind);
            rows.fp.push(*fp);
            rows.request.push(turn.request);
            rows.session.push(turn.session);
            rows.turn_number.push(turn.turn_number);
            rows.tool_call_id.push(tool_call_id.to_string());
            rows.part.push(part);
            rows.part_size.push(part_size);
            rows.timestamp.push(at);
        }
    };
    for turn in turns {
        let fps = turn.fingerprints;
        push(turn, "answer", "", 0, &fps.answer, turn.ended);
        push(turn, "opening", "", 0, &fps.opening, turn.started);
        for argument in &fps.arguments {
            push(turn, "argument", &argument.call_id, argument.part, &argument.segments, turn.ended);
        }
    }
    if rows.fp.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO turn_fingerprints (tenant_id, user_id, kind, fp, request_id, session_id, turn_number, \
             tool_call_id, part, part_size, timestamp) \
         SELECT * FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::bigint[], $5::uuid[], $6::uuid[], $7::int[], \
             $8::text[], $9::smallint[], $10::smallint[], $11::timestamptz[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&rows.tenant)
    .bind(&rows.user)
    .bind(&rows.kind)
    .bind(&rows.fp)
    .bind(&rows.request)
    .bind(&rows.session)
    .bind(&rows.turn_number)
    .bind(&rows.tool_call_id)
    .bind(&rows.part)
    .bind(&rows.part_size)
    .bind(&rows.timestamp)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// An opening to decide a link for: the quoting session and the request whose
/// opening it is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Opening {
    session: Uuid,
    request: Uuid,
    tenant: Uuid,
}

/// Every opening `turns` touch, in session order: each one's own, and each
/// stored later opening carrying a line of one's answer or arguments (landed
/// before the turn it quotes).
async fn openings_touched(conn: &mut IngestConn, turns: &[LandedTurn<'_>]) -> Result<Vec<Opening>, sqlx::Error> {
    let mut openings: Vec<Opening> = turns
        .iter()
        .filter(|t| !t.fingerprints.opening.is_empty())
        .map(|t| Opening { session: t.session, request: t.request, tenant: t.tenant })
        .collect();
    for turn in turns {
        let fps = turn.fingerprints;
        let quotable: Vec<i64> = fps.answer.iter().chain(fps.arguments.iter().flat_map(|a| &a.segments)).copied().collect();
        if quotable.is_empty() {
            continue;
        }
        let later: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT DISTINCT session_id, request_id FROM turn_fingerprints \
              WHERE tenant_id = $1 AND user_id = $2 AND kind = 'opening' AND fp = ANY($3) AND session_id <> $4 \
                AND timestamp > $5 - make_interval(secs => $6) AND timestamp <= $5 + make_interval(hours => $7)",
        )
        .bind(turn.tenant)
        .bind(turn.user)
        .bind(&quotable)
        .bind(turn.session)
        .bind(turn.ended)
        .bind(f64::from(CLOCK_MARGIN_SECS))
        .bind(WINDOW_HOURS)
        .fetch_all(&mut *conn)
        .await?;
        openings.extend(later.into_iter().map(|(session, request)| Opening { session, request, tenant: turn.tenant }));
    }
    openings.sort();
    openings.dedup();
    Ok(openings)
}

/// Decide `opening`'s link from the stored rows: the earlier text of the same
/// user it quotes ([`quoted_by`]), unless its session already had a turn
/// before it or is already linked (the one-link index).
async fn decide(conn: &mut IngestConn, opening: &Opening) -> Result<(), sqlx::Error> {
    // Already linked: nothing to decide (one probe of the one-link index, so a
    // later turn quoting an earlier one's lines does not rerun the join).
    let linked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM cross_session_relation_members \
                         WHERE tenant_id = $1 AND session_id = $2 AND role IN ('child', 'successor'))",
    )
    .bind(opening.tenant)
    .bind(opening.session)
    .fetch_one(&mut *conn)
    .await?;
    if linked {
        return Ok(());
    }
    type Row = (String, Uuid, Uuid, Option<i32>, String, i16, i16, DateTime<Utc>, i64, i16);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT t.kind, t.session_id, t.request_id, t.turn_number, t.tool_call_id, t.part, t.part_size, \
                t.timestamp, count(*), max(o.part_size) \
           FROM turn_fingerprints o \
           JOIN turn_fingerprints t ON t.tenant_id = o.tenant_id AND t.user_id = o.user_id \
                                   AND t.kind IN ('answer', 'argument') AND t.fp = o.fp \
          WHERE o.tenant_id = $1 AND o.request_id = $2 AND o.kind = 'opening' \
            AND t.session_id <> o.session_id \
            AND t.timestamp < o.timestamp + make_interval(secs => $3) \
            AND t.timestamp >= o.timestamp - CASE WHEN t.kind = 'argument' \
                THEN make_interval(mins => $4) ELSE make_interval(hours => $5) END \
            AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.tenant_id = o.tenant_id \
                              AND s.session_id = o.session_id AND s.created_at < o.timestamp) \
          GROUP BY t.kind, t.session_id, t.request_id, t.turn_number, t.tool_call_id, t.part, t.part_size, t.timestamp",
    )
    .bind(opening.tenant)
    .bind(opening.request)
    .bind(f64::from(CLOCK_MARGIN_SECS))
    .bind(ARGUMENT_WINDOW_MINUTES)
    .bind(WINDOW_HOURS)
    .fetch_all(&mut *conn)
    .await?;
    let opening_size = rows.first().map_or(0, |r| i64::from(r.9));
    let quoted: Vec<Quoted> = rows
        .into_iter()
        .filter_map(|(kind, session, request, turn_number, tool_call_id, part, part_size, timestamp, hits, _)| {
            Some(Quoted { kind: Kind::parse(&kind)?, session, request, turn_number, tool_call_id, part, part_size, timestamp, hits })
        })
        .collect();
    match quoted_by(opening_size, &quoted) {
        Some(q) => write_link(conn, opening.tenant, opening.session, q).await,
        None => Ok(()),
    }
}

/// Link `quoting` — a session opened by quoting `quoted` — to the quoted
/// turn's session, unless `quoting` is already linked (the one-link index on
/// the members, which every link writer conflicts on) or the quoted session is
/// itself linked to `quoting` (a link never closes a cycle). Under a
/// savepoint, so a refused relation leaves the transaction healthy.
async fn write_link(conn: &mut IngestConn, tenant: Uuid, quoting: Uuid, quoted: &Quoted) -> Result<(), sqlx::Error> {
    let (kind, role, other_role) = match quoted.kind {
        Kind::Argument => ("linkage", "child", "parent"),
        Kind::Answer => ("continuation", "successor", "predecessor"),
    };
    let cycle: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM cross_session_relation_members up \
                          JOIN cross_session_relation_members other ON other.relation_id = up.relation_id \
                                AND other.tenant_id = up.tenant_id AND other.role IN ('parent', 'predecessor') \
                         WHERE up.tenant_id = $1 AND up.session_id = $2 AND up.role IN ('child', 'successor') \
                           AND other.session_id = $3)",
    )
    .bind(tenant)
    .bind(quoted.session)
    .bind(quoting)
    .fetch_one(&mut *conn)
    .await?;
    if cycle {
        return Ok(());
    }
    let anchor = quoted.kind == Kind::Argument;
    let mut sp = conn.savepoint().await?;
    let relation: Uuid = sqlx::query_scalar(
        "INSERT INTO cross_session_relations (tenant_id, kind, confidence, spawn_turn, spawn_tool_call_id, origin) \
         VALUES ($1, $2, 'content', $3, $4, 'content') RETURNING id",
    )
    .bind(tenant)
    .bind(kind)
    .bind(quoted.turn_number.filter(|_| anchor))
    .bind(anchor.then_some(quoted.tool_call_id.as_str()))
    .fetch_one(sp.conn())
    .await?;
    let landed: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO cross_session_relation_members (relation_id, tenant_id, session_id, role, seq) \
         VALUES ($1, $2, $3, $4, 0) ON CONFLICT DO NOTHING RETURNING relation_id",
    )
    .bind(relation)
    .bind(tenant)
    .bind(quoting)
    .bind(role)
    .fetch_optional(sp.conn())
    .await?;
    if landed.is_none() {
        // Already linked: dropping the savepoint undoes the relation.
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO cross_session_relation_members (relation_id, tenant_id, session_id, role, seq) \
         VALUES ($1, $2, $3, $4, 0)",
    )
    .bind(relation)
    .bind(tenant)
    .bind(quoted.session)
    .bind(other_role)
    .execute(sp.conn())
    .await?;
    sp.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(minute: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + minute * 60, 0).unwrap()
    }

    fn text(kind: Kind, part_size: i16, hits: i64, minute: i64) -> Quoted {
        Quoted {
            kind,
            session: Uuid::from_u128(minute as u128 + 1),
            request: Uuid::from_u128(minute as u128 + 100),
            turn_number: Some(1),
            tool_call_id: if kind == Kind::Argument { "call_1".into() } else { String::new() },
            part: 0,
            part_size,
            timestamp: at(minute),
            hits,
        }
    }

    /// An argument is quoted only whole: of 3 lines or more, whatever the
    /// opening around it (a subagent's long prompt in its preamble); shorter,
    /// only as half the opening or more (one shared line is no spawn).
    #[test]
    fn an_argument_is_quoted_whole_and_a_short_one_as_half_the_opening() {
        let long = text(Kind::Argument, 3, 3, 0);
        assert!(long.is_quoted(500));
        assert!(!Quoted { hits: 2, ..long.clone() }.is_quoted(3));
        let short = text(Kind::Argument, 1, 1, 0);
        assert!(short.is_quoted(2));
        assert!(!short.is_quoted(3));
        assert!(!Quoted { part_size: 0, hits: 0, ..short }.is_quoted(0));
    }

    /// An answer is continued from 3 of its lines, or from the whole of a
    /// shorter one as half the opening or more.
    #[test]
    fn an_answer_is_continued_from_three_lines_or_whole_as_half_the_opening() {
        assert!(text(Kind::Answer, 20, 3, 0).is_quoted(40));
        assert!(!text(Kind::Answer, 20, 2, 0).is_quoted(4));
        assert!(text(Kind::Answer, 2, 2, 0).is_quoted(4));
        assert!(!text(Kind::Answer, 2, 2, 0).is_quoted(5));
        assert!(!text(Kind::Answer, 3, 2, 0).is_quoted(2));
    }

    /// The most lines carried wins, an argument on a tie (an answer at the cap),
/// then the latest.
    #[test]
    fn the_text_carried_most_wins_an_argument_on_a_tie() {
        // A compaction's summary repeating a tool call's argument: the answer.
        let summary = text(Kind::Answer, 20, 20, 9);
        let edit = text(Kind::Argument, 5, 5, 8);
        assert_eq!(quoted_by(25, &[edit.clone(), summary.clone()]), Some(&summary));
        // A subagent's prompt quoting a line of its parent's answer: the argument.
        let prompt = text(Kind::Argument, 30, 30, 8);
        let echoed = text(Kind::Answer, 10, 3, 9);
        assert_eq!(quoted_by(31, &[echoed, prompt.clone()]), Some(&prompt));
        // A tie: the argument.
        let tied = text(Kind::Answer, 5, 5, 9);
        assert_eq!(quoted_by(5, &[tied, edit.clone()]), Some(&edit));
        // Both carried to the cap: the answer — a summary repeating a plan.
        let full = |kind| text(kind, 32, 32, 9);
        assert_eq!(quoted_by(64, &[full(Kind::Argument), full(Kind::Answer)]).map(|q| q.kind), Some(Kind::Answer));
        // Among one kind, the latest.
        let later = text(Kind::Answer, 20, 20, 10);
        assert_eq!(quoted_by(25, &[summary, later.clone()]), Some(&later));
        // A stray line: nothing.
        assert_eq!(quoted_by(25, &[text(Kind::Answer, 20, 1, 0), text(Kind::Argument, 1, 1, 0)]), None);
    }
}
