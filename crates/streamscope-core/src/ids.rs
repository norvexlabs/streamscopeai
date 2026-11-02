//! Request-id minting.
//!
//! Every fact row's `request_id` (LLM, media, analyze, MCP, A2A, web) and the
//! admin plane's correlation id are minted here, as UUIDv7: the leading 48 bits
//! are the Unix time in milliseconds and the process-wide counter after them
//! keeps ids minted by one process strictly increasing. Ids minted close in time
//! therefore land next to each other in every `(tenant_id, request_id, …)` btree,
//! instead of scattering across its leaves as random v4 ids do.
//!
//! The id is an identifier only. No reader derives a time bound from it — the
//! row's own `timestamp` is the partition key — and the ingest accepts any UUID
//! version an edge sends.
//!
//! Its leading hex digits are the mint time, shared by every id minted in the
//! same span (8 digits: ~65 s; 12: ~16 ms), across tenants, so no identifier is
//! ever a slice of one. An id built from a request id for a client — a
//! translated response's or message's id, a minted tool-call id — carries the
//! whole id, through [`client_id`].

use uuid::Uuid;

/// Mint a fresh request id (UUIDv7) for a fact row or an admin correlation id.
///
/// Keep every fact mint site on this function: an id minted elsewhere with
/// another version still ingests, but loses the index locality v7 buys.
pub fn mint_request_id() -> Uuid {
    Uuid::now_v7()
}

/// A request id as a client-facing identifier's body: the whole id, without
/// its hyphens (a UUID's simple form). Never shortened — a prefix is the mint
/// time and a short tail too few random bits to stay unique.
pub fn client_id(request_id: &str) -> String {
    request_id.replace('-', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Uuid::now_v7` draws from one process-wide context, so ids are
    /// strictly increasing across every thread of a process — never across
    /// processes or replicas.
    #[test]
    fn a_minted_request_id_is_v7_and_strictly_increasing() {
        let ids: Vec<Uuid> = (0..10_000).map(|_| mint_request_id()).collect();
        for id in &ids {
            assert_eq!(id.get_version_num(), 7, "{id} is not a v7 id");
        }
        for pair in ids.windows(2) {
            assert!(
                pair[0] < pair[1],
                "ids minted in sequence must increase: {} then {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn a_client_id_is_the_whole_request_id() {
        let a = mint_request_id();
        let b = mint_request_id();
        assert_eq!(client_id(&a.to_string()), a.simple().to_string());
        // Two ids minted together share their time prefix, never a client id.
        assert_ne!(client_id(&a.to_string()), client_id(&b.to_string()));
        assert_eq!(client_id("req-1"), "req1");
    }
}
