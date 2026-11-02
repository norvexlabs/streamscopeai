//! Cross-cutting axum middleware for the admin API.

pub mod admin_audit;
pub mod audit_common;
pub mod error_body;
pub mod ip_rate_limit;
pub mod portal_audit;
pub mod request_id;
pub mod run_to_completion;
pub mod security_audit;

pub use admin_audit::admin_audit_mw;
pub use audit_common::{AuditDiffSink, PortalAuditTarget};
pub use error_body::json_error_body_mw;
pub use ip_rate_limit::{
    automation_key_ip_rate_limit_mw, claim_exchange_ip_rate_limit_mw, pre_auth_ip_rate_limit_mw,
    AutomationKeyUnverified, DistinctKeyFailures,
};
pub use portal_audit::portal_audit_mw;
pub use request_id::request_id_mw;
pub use run_to_completion::run_to_completion_mw;
pub use security_audit::security_audit_mw;
