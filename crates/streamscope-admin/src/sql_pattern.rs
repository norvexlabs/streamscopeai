//! The `ILIKE` patterns every free-text search and filter binds.

/// Escape ILIKE special characters so they are matched literally.
fn escape_ilike(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// The `ILIKE` pattern for a list's free-text `search` term: trimmed, escaped
/// and wrapped in `%…%`; `None` for an absent or blank term, which applies no
/// search. The traffic-log handlers refuse a term shorter than
/// [`MIN_SEARCH_CHARS`] before they get here (`routes::check_search`); a short
/// list (users, OAuth clients) applies a term of any length. A U+0000 is
/// mapped as stored text maps it (`pg_text::storable_str`): Postgres refuses
/// the byte in a bound parameter.
pub(crate) fn search_pattern(search: Option<&str>) -> Option<String> {
    search_text(search).map(|term| contains_pattern(&term))
}

/// `%value%` for a substring `ILIKE` on a caller-supplied value: escaped, and a
/// U+0000 mapped as stored text maps it (`pg_text::storable_str`) — Postgres
/// refuses the byte in a bound parameter. Every free-text filter builds its
/// pattern here.
pub(crate) fn contains_pattern(value: &str) -> String {
    format!("%{}%", escape_ilike(&streamscope_core::pg_text::storable_str(value)))
}

/// `value%` for an `ILIKE` matching a caller-supplied value from its start —
/// escaped and mapped as [`contains_pattern`] is.
pub(crate) fn prefix_pattern(value: &str) -> String {
    format!("{}%", escape_ilike(&streamscope_core::pg_text::storable_str(value)))
}

/// The term `search_pattern` matches, as text: trimmed, U+0000 mapped. `None`
/// for an absent or blank term. A filter that re-tests SQL's matches in Rust
/// starts from this, so the two never test different terms.
pub(crate) fn search_text(search: Option<&str>) -> Option<String> {
    let term = search?.trim();
    (!term.is_empty()).then(|| streamscope_core::pg_text::storable_str(term).into_owned())
}

/// The shortest traffic-log search term, in characters once trimmed: a shorter
/// one matches nearly every row and reads the whole window.
pub(crate) const MIN_SEARCH_CHARS: usize = 3;

/// A term present (not blank) but shorter than [`MIN_SEARCH_CHARS`] characters.
pub(crate) fn search_too_short(search: Option<&str>) -> bool {
    search_text(search).is_some_and(|term| term.chars().count() < MIN_SEARCH_CHARS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_search_term_is_too_short_below_three_characters_once_trimmed() {
        assert!(!search_too_short(None));
        assert!(!search_too_short(Some("")));
        assert!(!search_too_short(Some("  \t ")));
        assert!(search_too_short(Some("a")));
        assert!(search_too_short(Some("ab")));
        assert!(search_too_short(Some("  ab  ")));
        assert!(!search_too_short(Some("abc")));
        assert!(!search_too_short(Some(" abc ")));
        // Characters, not bytes: two emoji are two characters, three are enough.
        assert!(search_too_short(Some("😀😀")));
        assert!(!search_too_short(Some("😀😀😀")));
        assert!(!search_too_short(Some("é b")));
    }

    #[test]
    fn a_search_term_of_any_length_is_applied_trimmed_and_escaped() {
        assert_eq!(search_pattern(None), None);
        assert_eq!(search_pattern(Some("")), None);
        assert_eq!(search_pattern(Some(" \t\n")), None);
        assert_eq!(search_pattern(Some("q")).as_deref(), Some("%q%"));
        assert_eq!(search_pattern(Some("o1")).as_deref(), Some("%o1%"));
        assert_eq!(search_pattern(Some("  pong\t")).as_deref(), Some("%pong%"));
        assert_eq!(search_pattern(Some(" a b ")).as_deref(), Some("%a b%"));
        assert_eq!(search_pattern(Some("50%_\\")).as_deref(), Some("%50\\%\\_\\\\%"));
        assert_eq!(search_pattern(Some("a\0b")).as_deref(), Some("%a\u{FFFD}b%"));
        assert_eq!(search_pattern(Some("\0")).as_deref(), Some("%\u{FFFD}%"));
        assert_eq!(contains_pattern("a\0_b"), "%a\u{FFFD}\\_b%");
        assert_eq!(contains_pattern(""), "%%");
    }
}
