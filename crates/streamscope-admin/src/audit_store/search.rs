//! The walk a search-capable list makes over its search lookup function.

use uuid::Uuid;


/// How many lookup calls one search may make before it stops and says so
/// (`OffsetPage::scan_cut`). With [`SEARCH_BATCH`] it bounds a filtered search
/// to the first `SEARCH_ROUNDS × SEARCH_BATCH` matches of its window.
const SEARCH_ROUNDS: usize = 4;

/// The keys one lookup call is asked for when the caller filters them further:
/// any number of them may fail the caller's filters.
const SEARCH_BATCH: i64 = 5_000;

/// Rows a search-capable list fetched, and whether its search stopped at the
/// round budget ([`SearchWalk`]) before it could fill the page.
pub(crate) struct SearchRows<T> {
    pub rows: Vec<T>,
    pub scan_cut: bool,
}

/// One search's walk over its lookup function (the search lookups' contract,
/// 001_init.sql): each call returns keys strictly past the cursor; the caller
/// joins them back under its own filters and calls again from the last key
/// returned, until the page is full, the window is exhausted (a call returned
/// fewer keys than asked), or [`SEARCH_ROUNDS`] calls are spent — the one end
/// that is reported (`cut`), never a silently short page.
pub(crate) struct SearchWalk {
    /// Rows the page needs: `offset + limit`, the caller's overfetch included.
    needed: usize,
    /// Keys asked of each call.
    batch: i32,
    rounds: usize,
    cursor: Option<(chrono::DateTime<chrono::Utc>, Uuid)>,
    cut: bool,
}

impl SearchWalk {
    /// Rows the page needs: `offset + limit`, the caller's overfetch included.
    pub(crate) fn needed(&self) -> usize {
        self.needed
    }

    /// Keys to ask of the next call.
    pub(crate) fn batch(&self) -> i32 {
        self.batch
    }

    /// The key the next call starts past; `None` before the first.
    pub(crate) fn cursor(&self) -> Option<(chrono::DateTime<chrono::Utc>, Uuid)> {
        self.cursor
    }

    /// Whether the walk stopped at the round budget before the page was full.
    pub(crate) fn cut(&self) -> bool {
        self.cut
    }

    /// `post_filtered`: the caller applies a filter the lookup does not, so a
    /// call's keys need not all become rows; without one, every key is a row
    /// and one call of exactly the page fills it. No call asks for more than
    /// [`SEARCH_BATCH`] keys, however deep the page: past the round budget a
    /// search is cut, never one unbounded call.
    pub(crate) fn new(needed: i64, post_filtered: bool) -> Self {
        let needed = needed.max(1);
        let batch = if post_filtered { SEARCH_BATCH } else { needed.min(SEARCH_BATCH) };
        Self {
            needed: usize::try_from(needed).unwrap_or(usize::MAX),
            batch: i32::try_from(batch).unwrap_or(i32::MAX),
            rounds: 0,
            cursor: None,
            cut: false,
        }
    }

    /// Record one call: it returned `returned` keys, the last of them `last`,
    /// and the caller now holds `collected` rows. `true` when another call is
    /// due, from the new cursor.
    pub(crate) fn advance(
        &mut self,
        returned: usize,
        last: Option<(chrono::DateTime<chrono::Utc>, Uuid)>,
        collected: usize,
    ) -> bool {
        self.rounds += 1;
        if collected >= self.needed || returned < usize::try_from(self.batch).unwrap_or(usize::MAX) {
            return false;
        }
        self.cursor = last;
        if self.rounds >= SEARCH_ROUNDS {
            self.cut = true;
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: i64) -> Option<(chrono::DateTime<chrono::Utc>, Uuid)> {
        Some((chrono::DateTime::from_timestamp(n, 0).unwrap(), Uuid::from_u128(n as u128)))
    }

    #[test]
    fn an_unfiltered_search_asks_for_the_page_and_stops_after_one_call() {
        let mut walk = SearchWalk::new(11, false);
        assert_eq!(walk.batch, 11);
        assert!(!walk.advance(11, key(1), 11));
        assert!(!walk.cut);
    }

    #[test]
    fn no_call_asks_for_more_than_a_batch_however_deep_the_page() {
        assert_eq!(SearchWalk::new(SEARCH_BATCH, false).batch as i64, SEARCH_BATCH);
        assert_eq!(SearchWalk::new(SEARCH_BATCH + 1, false).batch as i64, SEARCH_BATCH);
        assert_eq!(SearchWalk::new(2_000_000_000, false).batch as i64, SEARCH_BATCH);
        assert_eq!(SearchWalk::new(2_000_000_000, true).batch as i64, SEARCH_BATCH);
    }

    #[test]
    fn a_filtered_search_asks_for_a_batch_and_follows_the_cursor() {
        let mut walk = SearchWalk::new(11, true);
        assert_eq!(walk.batch as i64, SEARCH_BATCH);
        assert!(walk.advance(SEARCH_BATCH as usize, key(7), 3));
        assert_eq!(walk.cursor, key(7));
        // A call returning fewer keys than asked exhausted the window.
        assert!(!walk.advance(SEARCH_BATCH as usize - 1, key(8), 5));
        assert!(!walk.cut);
    }

    #[test]
    fn the_round_budget_cuts_only_a_search_it_stopped() {
        let full = SEARCH_BATCH as usize;
        // The last allowed call fills the page: no cut.
        let mut walk = SearchWalk::new(11, true);
        for _ in 1..SEARCH_ROUNDS {
            assert!(walk.advance(full, key(1), 0));
        }
        assert!(!walk.advance(full, key(2), 11));
        assert!(!walk.cut);
        // The last allowed call leaves the page short with more keys to read: cut.
        let mut walk = SearchWalk::new(11, true);
        for _ in 1..SEARCH_ROUNDS {
            assert!(walk.advance(full, key(1), 0));
        }
        assert!(!walk.advance(full, key(2), 10));
        assert!(walk.cut);
    }
}
