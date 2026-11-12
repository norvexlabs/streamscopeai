//! Client-config template system shared by the admin server and the
//! `ssai` CLI: the profile/template wire types and the pure
//! Handlebars-based render engine with per-format escaping and post-render
//! validation. No I/O, no async, no server dependencies — the server builds
//! the placeholder map (DB/auth/key-mint entangled) and the web quickstart or
//! the CLI render with the exact same code.
//!
//! [`destination`] is the other half of what the CLI is provisioned with: the
//! entry syntax of a tenant's destination lists and the matcher the sandbox
//! guard applies (and the server's Web filter).

pub mod companions;
pub mod destination;
pub mod fixture;
pub mod render;
pub mod types;

pub use companions::{companion_files, CompanionFile};
pub use render::{
    local_command_line, mcp_client_header_placeholder, mcp_header_item, mcp_local_server_item, render, RenderError, Value, API_KEY_PLACEHOLDER, PROJECT_SCOPE, YAML_STRING_HELPER,
    UPSTREAM_API_KEY_PLACEHOLDER,
};
pub use types::{
    default_llm_template_index, composite_identity, keyed_entry_identity, scalar_identity, string_entry_identity, ClientProfile, ClientProfileTemplate, CompanionTemplate, companion_project_path,
    KeyDelivery, LocalMcpForm, McpAuthMode, TemplateFormat, TemplateKind, STRING_ENTRIES,
};
