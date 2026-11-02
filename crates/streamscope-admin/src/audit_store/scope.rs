//! Whose rows a list may return.

use uuid::Uuid;

use crate::routes::portal::PortalDataScope;
use crate::routes::{WorkspaceIds, parse_workspace_ids};

/// Whose rows a list may return: an optional user, and an optional set of
/// workspaces (with, for the session list, the unattributed sessions beside
/// them). Every list in the store reads the user and the workspaces from here
/// and from nowhere else.
///
/// **The fields are private.** The pair `(None, None)` means every row in the
/// tenant, so a reader is handed it only by a constructor that names its
/// caller — [`Self::portal`] never builds it, [`Self::tenant`] is for the
/// readers that may see the whole tenant. Which constructor a handler calls is
/// the claim read in review: a portal handler builds its scope with
/// [`Self::portal`] alone, never [`Self::tenant`].
pub(crate) struct AuditScope {
    user_id: Option<Uuid>,
    /// Never `Some(empty)`: an empty set is no filter, as `parse_workspace_ids`
    /// reads it.
    workspace_ids: Option<Vec<Uuid>>,
    include_keyless: bool,
    /// Whether the user and the workspaces are an access confinement (the
    /// portal's) rather than a filter on a tenant-wide view: only a confined
    /// scope also confines the linked sessions its rows name.
    confined: bool,
}

impl AuditScope {
    /// The portal: exactly what [`PortalDataScope::resolve`] allowed — the
    /// caller's own rows, or every row of the one workspace that shares with
    /// its members; a portal `ak-` key additionally confined to its workspace.
    /// The session and audit search lookups take it as `p_user` /
    /// `p_workspaces`.
    pub(crate) fn portal(scope: &PortalDataScope) -> Self {
        Self {
            user_id: scope.user_id(),
            workspace_ids: scope.workspace_id().map(|w| vec![w]),
            include_keyless: false,
            confined: true,
        }
    }

    /// A tenant-wide reader (the console, the agent, analytics) narrowed by an
    /// optional user and an optional workspace filter. An empty workspace set
    /// is no filter.
    pub(crate) fn tenant(user_id: Option<Uuid>, workspace_ids: Option<WorkspaceIds>) -> Self {
        Self {
            user_id,
            workspace_ids: parse_workspace_ids(&workspace_ids),
            include_keyless: false,
            confined: false,
        }
    }

    /// With a workspace filter, also admit the sessions carrying no workspace
    /// attribution (the nil workspace). Read only by the session list, and only
    /// when a workspace filter is set.
    pub(crate) fn including_keyless(mut self, include_keyless: bool) -> Self {
        self.include_keyless = include_keyless;
        self
    }

    pub(crate) fn user_id(&self) -> Option<Uuid> {
        self.user_id
    }

    /// The workspace filter; `None` for every workspace.
    pub(crate) fn workspace_ids(&self) -> Option<&[Uuid]> {
        self.workspace_ids.as_deref()
    }

    pub(crate) fn include_keyless(&self) -> bool {
        self.include_keyless
    }

    /// The user and the workspaces a linked session (a row's parent or child)
    /// must belong to for the row to name it: the portal's confinement, and
    /// `(None, None)` — every linked session in the tenant — for a tenant-wide
    /// reader, whose user and workspace filters narrow its rows, not what
    /// they may link to.
    pub(crate) fn linked_view(&self) -> (Option<Uuid>, Option<Vec<Uuid>>) {
        if self.confined { (self.user_id, self.workspace_ids.clone()) } else { (None, None) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: Uuid = Uuid::from_u128(1);
    const WS: Uuid = Uuid::from_u128(2);

    #[test]
    fn a_portal_scope_over_own_rows_keeps_the_user() {
        // `resolve`'s answer for a request that names no workspace (a human
        // session): the caller's own rows, never every row of the tenant.
        let own = AuditScope::portal(&PortalDataScope::for_test(Some(USER), None));
        assert_eq!(own.user_id(), Some(USER));
        assert_eq!(own.workspace_ids(), None);
        // An `ak-` key's own rows: the user and its one workspace.
        let key = AuditScope::portal(&PortalDataScope::for_test(Some(USER), Some(WS)));
        assert_eq!(key.user_id(), Some(USER));
        assert_eq!(key.workspace_ids(), Some(&[WS][..]));
        assert!(!key.include_keyless());
        assert_eq!(key.linked_view(), (Some(USER), Some(vec![WS])));
    }

    #[test]
    fn a_widened_portal_scope_keeps_the_workspace() {
        let shared = AuditScope::portal(&PortalDataScope::for_test(None, Some(WS)));
        assert_eq!(shared.user_id(), None);
        assert_eq!(shared.workspace_ids(), Some(&[WS][..]));
        assert!(!shared.include_keyless());
    }

    #[test]
    fn an_empty_workspace_set_is_no_workspace_filter() {
        let empty = AuditScope::tenant(None, Some(WorkspaceIds(Vec::new())));
        assert_eq!(empty.workspace_ids(), None);
        assert_eq!(
            empty.workspace_ids().map(<[Uuid]>::to_vec),
            parse_workspace_ids(&Some(WorkspaceIds(Vec::new()))),
        );
        // The positive control: a non-empty set is the filter, the user with it.
        let one = AuditScope::tenant(Some(USER), Some(WorkspaceIds(vec![WS])));
        assert_eq!(one.user_id(), Some(USER));
        assert_eq!(one.workspace_ids(), Some(&[WS][..]));
    }

    #[test]
    fn only_a_portal_scope_confines_the_linked_sessions() {
        // A tenant-wide reader's user and workspace narrow its rows; a linked
        // parent or child elsewhere in the tenant is still named.
        let filtered = AuditScope::tenant(Some(USER), Some(WorkspaceIds(vec![WS])));
        assert_eq!(filtered.linked_view(), (None, None));
        // The portal names only what it admits: the shared workspace's.
        let shared = AuditScope::portal(&PortalDataScope::for_test(None, Some(WS)));
        assert_eq!(shared.linked_view(), (None, Some(vec![WS])));
        // The caller's own rows.
        let own = AuditScope::portal(&PortalDataScope::for_test(Some(USER), None));
        assert_eq!(own.linked_view(), (Some(USER), None));
    }

    #[test]
    fn keyless_is_off_unless_asked_for() {
        let scope = AuditScope::tenant(None, Some(WorkspaceIds(vec![WS])));
        assert!(!scope.include_keyless());
        assert!(scope.including_keyless(true).include_keyless());
        let off = AuditScope::tenant(None, None).including_keyless(false);
        assert!(!off.include_keyless());
    }
}
