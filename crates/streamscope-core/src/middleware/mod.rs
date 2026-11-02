//! Request middleware — cross-cutting concerns applied before and after proxying.
//!
//! Each sub-module handles one concern: client attribution ([`attribution`]),
//! the whole-transfer deadline on a request body ([`body_deadline`]), keyed
//! rate limiting ([`rate_limit`]), source-IP throttling of unauthenticated
//! surfaces ([`ip_rate_limit`]), token estimation ([`tokens`]), and debug
//! introspection ([`debug_echo`]).

pub mod attribution;
pub mod body_deadline;
pub mod debug_echo;
pub mod ip_rate_limit;
pub mod rate_limit;
pub mod tokens;
