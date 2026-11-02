//! Portal self-service ownership gates.
//!
//! A `TenantConn` connection is RLS-scoped to its TENANT, never to a user. The
//! portal member surface is scoped by a [`PortalDataScope`], so every
//! detail/media endpoint MUST verify the addressed resource is inside it BEFORE
//! reusing a tenant-scoped core. Each gate admits exactly what the scope does:
//! the caller's own rows (its `user_id`), those of the one workspace an `ak-`
//! key is bound to (its `workspace_id` beside the user), or — when `resolve`
//! widened the read to a shared workspace — every row of that workspace (no
//! user, the workspace). Each half is a no-op only when absent (`IS NULL`), and
//! `resolve` never leaves both absent. Each gate collapses "not found" and "not
//! yours" into a single 404 so a member cannot probe which session/request/blob
//! exists tenant-wide.

use uuid::Uuid;

use crate::db::tenant::Scoped;
use crate::routes::portal::PortalDataScope;
use crate::routes::{ApiError, ApiErrorCode};

/// 404 unless `session_id` is inside the caller's [`PortalDataScope`] — their
/// own row, or any row of a workspace that shares with its members.
pub(crate) async fn assert_session_owned(
    conn: &mut Scoped,
    session_id: Uuid,
    scope: &PortalDataScope,
) -> Result<(), ApiError> {
    let owned: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM sessions s WHERE s.session_id = $1 \
         AND ($2::uuid IS NULL OR s.user_id = $2) \
         AND ($3::uuid IS NULL OR s.workspace_id = $3) \
         LIMIT 1",
    )
    .bind(session_id)
    .bind(scope.user_id())
    .bind(scope.workspace_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("assert_session_owned: {e}");
        ApiError::internal("internal error")
    })?;
    if owned.is_none() {
        return Err(ApiError::not_found("Session not found", ApiErrorCode::SessionNotFound));
    }
    Ok(())
}

/// 404 unless `request_id` is inside the caller's [`PortalDataScope`]. Bridges
/// via `gateway_audit` — the only table carrying `(request_id, user_id,
/// workspace_id)` together.
pub(crate) async fn assert_request_owned(
    conn: &mut Scoped,
    request_id: Uuid,
    scope: &PortalDataScope,
) -> Result<(), ApiError> {
    let owned: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM gateway_audit WHERE request_id = $1 \
         AND ($2::uuid IS NULL OR user_id = $2) \
         AND ($3::uuid IS NULL OR workspace_id = $3) LIMIT 1",
    )
    .bind(request_id)
    .bind(scope.user_id())
    .bind(scope.workspace_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("assert_request_owned: {e}");
        ApiError::internal("internal error")
    })?;
    if owned.is_none() {
        return Err(ApiError::not_found("Request not found", ApiErrorCode::AuditRecordNotFound));
    }
    Ok(())
}

/// 404 unless media blob `hash` is referenced by `request_id` AND that request
/// is inside the caller's [`PortalDataScope`]. A media blob
/// row is content-addressed with no owner column, so ownership is proven
/// transitively through the referencing request's `llm_audit` media fields.
///
/// The reference is matched where the GATEWAY wrote it, and nowhere else: a
/// `content_hash` entry of `chat_media_summary` (the hash of bytes the request
/// carried) or a `blob_ref` block directly in `media_call.input` / `.output`
/// (the bytes the gateway captured). Never a substring of the row's text, and
/// never a deeper descent: a media call also carries the caller's own words (a
/// speech input, an image prompt) and every unrecognised body field
/// (`params.extra`), so either would let a caller who knows a teammate's hash
/// write it into a request of their own and read the teammate's blob through
/// it. `strict` with `silent` makes a row without those arrays a plain miss.
pub(crate) async fn assert_media_owned(
    conn: &mut Scoped,
    request_id: Uuid,
    hash: &str,
    scope: &PortalDataScope,
) -> Result<(), ApiError> {
    let owned: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM gateway_audit g \
         JOIN llm_audit a USING (request_id, timestamp, tenant_id) \
         WHERE g.request_id = $1 \
         AND ($2::uuid IS NULL OR g.user_id = $2) \
         AND ($3::uuid IS NULL OR g.workspace_id = $3) \
         AND (a.chat_media_summary @> jsonb_build_array(jsonb_build_object('content_hash', $4::text)) \
              OR jsonb_path_exists(a.media_call, \
                   'strict $.input[*] ? (@.type == \"blob_ref\" && @.content_hash == $h)', \
                   jsonb_build_object('h', $4::text), true) \
              OR jsonb_path_exists(a.media_call, \
                   'strict $.output[*] ? (@.type == \"blob_ref\" && @.content_hash == $h)', \
                   jsonb_build_object('h', $4::text), true)) \
         LIMIT 1",
    )
    .bind(request_id)
    .bind(scope.user_id())
    .bind(scope.workspace_id())
    .bind(hash)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("assert_media_owned: {e}");
        ApiError::internal("internal error")
    })?;
    if owned.is_none() {
        return Err(
            ApiError::not_found("Media blob not found", ApiErrorCode::MediaBlobNotFound)
        );
    }
    Ok(())
}

/// 404 unless tool-definition `hash` is referenced by a conversation turn
/// (`tools_available_hash` / `tools_effective_hash`) inside the caller's
/// [`PortalDataScope`]. A `tool_definitions` row is content-addressed with no
/// owner column, so ownership is proven transitively through the turns the
/// scope admits. The hash indexes on `conversation_turns`
/// keep this a narrow lookup; the 64-hex SHA-256 makes a coincidental hit
/// impossible.
pub(crate) async fn assert_tool_definition_owned(
    conn: &mut Scoped,
    hash: &str,
    scope: &PortalDataScope,
) -> Result<(), ApiError> {
    let owned: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM conversation_turns t \
         JOIN gateway_audit g ON g.tenant_id = t.tenant_id AND g.request_id = t.request_id \
           AND g.timestamp = t.timestamp \
         WHERE ($1::uuid IS NULL OR g.user_id = $1) \
         AND ($2::uuid IS NULL OR g.workspace_id = $2) \
         AND $3 IN (t.tools_available_hash, t.tools_effective_hash) \
         LIMIT 1",
    )
    .bind(scope.user_id())
    .bind(scope.workspace_id())
    .bind(hash)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("assert_tool_definition_owned: {e}");
        ApiError::internal("internal error")
    })?;
    if owned.is_none() {
        return Err(
            ApiError::not_found("Tool definition not found", ApiErrorCode::AuditRecordNotFound),
        );
    }
    Ok(())
}
