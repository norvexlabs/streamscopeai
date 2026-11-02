//! Built-in [`super::url_filter::UrlFilter`] implementations.
//!
//! [`destination_list::DestinationListFilter`] applies the tenant's
//! destination lists attached to the Web tool. When none is attached the chain
//! is empty and never runs.

pub mod destination_list;

pub use destination_list::DestinationListFilter;
