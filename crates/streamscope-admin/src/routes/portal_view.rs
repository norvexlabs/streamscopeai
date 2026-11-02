//! What a portal member sees of a row the console sees whole.
//!
//! The rows a member may read are decided by `PortalDataScope` alone; this
//! module decides which FIELDS of those rows reach them. Today that is one
//! rule: the experts' findings on a session (its alert level, the experts that
//! raised it and their note, and the `session_alert` badge an audit row folds
//! them into) are withheld. Session linkage is not a finding and stays.
//!
//! Every portal handler returning a [`SessionSummary`], a
//! [`ConversationResponse`], a [`LinkedSessions`], an [`AuditLogRow`], a
//! [`WebAuditLogEntry`] or a [`TraceResponse`] passes it through
//! [`MemberView::for_member`] before it is serialised: clearing the
//! fields in the UI alone would still ship them in the JSON. A filter or an
//! order on a withheld field is ignored by the handler, never applied, so the
//! rows returned cannot reveal it either.

use streamscope_core::audit::AuditBadge;

use super::audit::{AuditLogRow, ConversationResponse, LinkedSessions, SessionSummary, TraceResponse, WebAuditLogEntry};

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

    #[test]
    fn a_list_keeps_every_row_and_views_each_as_a_member() {
        let rows = vec![Seen(false), Seen(false), Seen(false)].for_member();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| *r == Seen(true)));
    }
}
