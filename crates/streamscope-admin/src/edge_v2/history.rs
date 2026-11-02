//! A turn's history as a chain of fixed-size chunks of message hashes
//! (`turn_history_chunks`).
//!
//! A history of n message hashes is cut at fixed boundaries of
//! [`HISTORY_CHUNK`]: chunk k holds hashes `[16k, 16k+16)`, the last one
//! possibly fewer. A chunk's hash covers its parent's hash and its own hashes,
//! so two histories that share a prefix share every FULL chunk of it, and the
//! turn that adds m messages to its session stores at most `m / 16 + 2` new
//! chunks instead of its whole history. The stored chain is walked back into
//! the ordered array by `turn_message_hashes` (`001_init.sql`), which must
//! agree with [`message_hashes`] here.

use sha2::{Digest, Sha256};

/// How many message hashes a full chunk holds. Changing it changes every chunk
/// hash, so a stored chain would no longer match the chunks a new turn derives.
pub(crate) const HISTORY_CHUNK: usize = 16;

/// One chunk of a history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Chunk {
    pub(crate) hash: String,
    /// The previous chunk's hash; `None` on the first.
    pub(crate) parent: Option<String>,
    pub(crate) hashes: Vec<String>,
}

/// The chunks of `history`, first to last; none for an empty history.
pub(crate) fn chunks(history: &[String]) -> Vec<Chunk> {
    let mut out: Vec<Chunk> = Vec::with_capacity(history.len().div_ceil(HISTORY_CHUNK));
    for part in history.chunks(HISTORY_CHUNK) {
        let parent = out.last().map(|c| c.hash.clone());
        out.push(Chunk { hash: chunk_hash(parent.as_deref(), part), parent, hashes: part.to_vec() });
    }
    out
}

/// The hash of `history`'s last chunk — what a turn stores as its
/// `history_head`; `None` for an empty history.
pub(crate) fn head(history: &[String]) -> Option<String> {
    chunks(history).pop().map(|c| c.hash)
}

/// The history a chain of chunks spells, given them last to first (the order a
/// walk from the head finds them).
#[cfg(test)]
pub(crate) fn message_hashes(from_head: &[Chunk]) -> Vec<String> {
    from_head.iter().rev().flat_map(|c| c.hashes.iter().cloned()).collect()
}

/// sha256 over the parent's hash and the chunk's hashes, one per line, hex.
/// Message hashes are hex, so a newline cannot occur inside one.
fn chunk_hash(parent: Option<&str>, hashes: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(parent.unwrap_or("-").as_bytes());
    for m in hashes {
        h.update(b"\n");
        h.update(m.as_bytes());
    }
    hex::encode(h.finalize())
}

/// How many leading messages of `current` its session's previous turn
/// already carried, given that turn's history: its length when `current`
/// starts with it — all of `current` when it is the same history resent (a
/// retry or a regenerate adds no message) — else 0 (the turn is then written as
/// a baseline, which added its whole history).
pub(crate) fn added_from_parent(current: &[String], parent: &[String]) -> usize {
    if !parent.is_empty() && current.len() >= parent.len() && current[..parent.len()] == *parent {
        parent.len()
    } else {
        0
    }
}

/// [`added_from_parent`] when only the parent's stored chain is known: its
/// head and length. `current` starts with the parent exactly when the chain of
/// its first `count` hashes ends in the same head.
pub(crate) fn added_from_stored(current: &[String], parent_head: &str, count: usize) -> usize {
    if count > 0 && current.len() >= count && head(&current[..count]).as_deref() == Some(parent_head) {
        count
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hashes(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{i:064x}")).collect()
    }

    #[test]
    fn a_chunk_holds_sixteen_hashes_and_the_seventeenth_starts_the_next() {
        let sixteen = chunks(&hashes(16));
        assert_eq!(sixteen.len(), 1);
        assert_eq!(sixteen[0].hashes.len(), 16);
        let seventeen = chunks(&hashes(17));
        assert_eq!(seventeen.len(), 2);
        assert_eq!(seventeen[1].hashes, vec![hashes(17)[16].clone()]);
        assert_eq!(seventeen[1].parent.as_deref(), Some(seventeen[0].hash.as_str()));
        assert!(chunks(&[]).is_empty());
        assert_eq!(head(&[]), None);
    }

    #[test]
    fn a_full_chunk_is_shared_and_a_partial_one_is_not() {
        let a = chunks(&hashes(20));
        let b = chunks(&hashes(40));
        assert_eq!(a[0], b[0], "the full first chunk is shared");
        assert_ne!(a[1].hash, b[1].hash, "a partial chunk differs from the full one that grows from it");
    }

    #[test]
    fn added_from_names_the_parent_only_when_it_is_a_prefix() {
        let parent = hashes(10);
        let mut current = hashes(12);
        assert_eq!(added_from_parent(&current, &parent), 10);
        assert_eq!(added_from_stored(&current, &head(&parent).unwrap(), parent.len()), 10);
        // The same history resent added nothing; a shorter one is no
        // continuation, and neither is an edited prefix.
        assert_eq!(added_from_parent(&parent, &parent), 10);
        assert_eq!(added_from_stored(&parent, &head(&parent).unwrap(), parent.len()), 10);
        assert_eq!(added_from_parent(&parent[..9], &parent), 0);
        assert_eq!(added_from_stored(&parent[..9], &head(&parent).unwrap(), parent.len()), 0);
        current[3] = "edited".into();
        assert_eq!(added_from_parent(&current, &parent), 0);
        assert_eq!(added_from_stored(&current, &head(&parent).unwrap(), parent.len()), 0);
        assert_eq!(added_from_parent(&current, &[]), 0);
        assert_eq!(added_from_stored(&current, "x", 0), 0);
    }

    proptest! {
        /// The chain spells the history back, every chunk but the last is full,
        /// and each names its predecessor.
        #[test]
        fn the_chain_reassembles_the_history(n in 0usize..200) {
            let h = hashes(n);
            let cs = chunks(&h);
            let walked: Vec<Chunk> = cs.iter().rev().cloned().collect();
            prop_assert_eq!(message_hashes(&walked), h.clone());
            for (i, c) in cs.iter().enumerate() {
                prop_assert_eq!(c.parent.as_deref(), i.checked_sub(1).map(|p| cs[p].hash.as_str()));
                if i + 1 < cs.len() {
                    prop_assert_eq!(c.hashes.len(), HISTORY_CHUNK);
                }
            }
            prop_assert_eq!(head(&h), cs.last().map(|c| c.hash.clone()));
        }

        /// A history that extends another shares exactly its full chunks, and
        /// the stored-chain check agrees with the direct one.
        #[test]
        fn an_extension_shares_its_full_chunks(n in 1usize..120, extra in 1usize..40) {
            let shorter = hashes(n);
            let longer = hashes(n + extra);
            let (a, b) = (chunks(&shorter), chunks(&longer));
            for k in 0..n / HISTORY_CHUNK {
                prop_assert_eq!(&a[k], &b[k]);
            }
            prop_assert_eq!(added_from_parent(&longer, &shorter), n);
            prop_assert_eq!(added_from_stored(&longer, &head(&shorter).unwrap(), n), n);
        }
    }
}
