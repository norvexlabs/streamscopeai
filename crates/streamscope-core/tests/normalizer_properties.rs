//! Properties of the tool-risk canonicalisers, not examples of them.
//!
//! `config::tool_rules_normalize` reads attacker-chosen bytes: a model's tool
//! arguments, shaped by whoever is trying to get a command past a rule. Both halves
//! of every match go through it — the operator's needle at rule-compile time and the
//! live argument at evaluation time — so a canonicaliser that is wrong is not a wrong
//! answer, it is a silent bypass.
//!
//! Example tests pin the evasion someone already thought of, which is never the one
//! that breaks. Each test below states a claim the module's own doc comment makes and
//! lets the generator hunt for the counterexample. The generators are the load-bearing
//! half: `evasive()` emits `$IFS`, `${IFS%??}`, `/**/`, `--`, `%2570`, `..`, `~`,
//! backslashes, mismatched quotes, statement separators and RTL overrides, because a
//! generator that can only produce well-formed input can only prove the parser handles
//! well-formed input.
//!
//! What is deliberately NOT asserted here, because the module deliberately does not
//! claim it:
//!
//! * **Idempotence.** The decode policy is single-pass by design (`%2570` → `%70`,
//!   not `p`), so `apply(apply(x)) != apply(x)` is intended. `url_decoding_is_single_pass`
//!   pins that direction instead, so a later "fix" that recurses breaks a test.
//! * **No `/*` in SQL output.** Comment stripping runs once, so `//*x*/*` can leave a
//!   `/*` behind. Same single-pass policy; the layered shapes are matched by
//!   `tool_rules_detectors` reading shape rather than by decoding again.

use proptest::prelude::*;
use streamscope_core::config::tool_rules_normalize::{
    MULTIFORM_SEP, Normalizer, apply, apply_forms, shell_argv,
};

const ALL: [Normalizer; 6] = Normalizer::ALL;

/// Fragments a canonicaliser is supposed to defeat, plus the ones that break byte-indexed
/// slicing. A generated value is a join of these with ordinary text,
/// so the search space contains real evasions rather than only random noise.
fn evasive() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        // Ordinary content, including multi-byte UTF-8 — the class `#![warn(clippy::string_slice)]`
        // guards the module's slice sites against.
        "[a-zA-Z0-9 /._:@?=&-]{0,12}",
        "\\PC{0,6}",
        // Shell: IFS expansion, quoting, statement separators, interpreter wrappers.
        Just("$IFS".to_string()),
        Just("${IFS}".to_string()),
        Just("${IFS%??}".to_string()),
        Just("$IFSPATH".to_string()),
        Just("${IFS".to_string()),
        Just("'".to_string()),
        Just("\"".to_string()),
        Just(";".to_string()),
        Just("&&".to_string()),
        Just("||".to_string()),
        Just("|".to_string()),
        Just("bash -c ".to_string()),
        Just("sudo ".to_string()),
        // SQL: both comment shapes, the intra-keyword splitter, casing.
        Just("/**/".to_string()),
        Just("/*".to_string()),
        Just("*/".to_string()),
        Just("--".to_string()),
        Just("\n".to_string()),
        Just("\t".to_string()),
        Just("UNION".to_string()),
        Just("SELECT".to_string()),
        // URL: percent layers, scheme, authority punctuation, the IMDS aliases.
        Just("%2f".to_string()),
        Just("%2F".to_string()),
        Just("%2570".to_string()),
        Just("%".to_string()),
        Just("://".to_string()),
        Just("HTTPS://".to_string()),
        Just("Metadata.Google.INTERNAL".to_string()),
        Just("instance-data".to_string()),
        // Path: traversal, separators, the home anchor.
        Just("..".to_string()),
        Just("~".to_string()),
        Just("\\".to_string()),
        Just("//".to_string()),
        Just("/".to_string()),
        // Patch: the file headers, with and without the space after the colon.
        Just("*** Update File: ".to_string()),
        Just("*** Move to:".to_string()),
        Just("\r\n".to_string()),
        Just("\u{feff}".to_string()),
        // Bidi override — renders as reordered text, so a human-reviewed rule and the
        // bytes it matches can disagree.
        Just("\u{202e}".to_string()),
        // The structural separator, spelled both ways an argument can reach for it:
        // literally, and through the one pass that decodes.
        Just("\u{0}".to_string()),
        Just("%00".to_string()),
    ];
    proptest::collection::vec(piece, 0..14).prop_map(|parts| parts.concat())
}

/// An option a POSIX shell takes before its operand, spelled as the shell
/// reads it: a cluster of letters on `-` or `+` followed by one value word per
/// `o`/`O` it holds (`-euo pipefail`, `+O extglob`), or a long option — with
/// its value where it takes one (`--rcfile /dev/null`). Clusters here hold no
/// `c`: the property places the `-c` itself.
fn shell_option() -> impl Strategy<Value = String> {
    prop_oneof![
        ("[-+]", "[a-bd-zO]{1,3}").prop_map(|(sign, letters)| with_option_values(&format!("{sign}{letters}"))),
        Just("--login".to_string()),
        Just("--norc".to_string()),
        Just("--rcfile /dev/null".to_string()),
    ]
}

/// `cluster` followed by the value word each `o`/`O` in it takes.
fn with_option_values(cluster: &str) -> String {
    let values = cluster.chars().filter(|c| matches!(c, 'o' | 'O')).count();
    std::iter::once(cluster.to_string()).chain(std::iter::repeat_n("pipefail".to_string(), values)).collect::<Vec<_>>().join(" ")
}

/// A relative or absolute file path as a patch names it: segments that include a
/// traversal, a dot directory, a space inside a name and multi-byte UTF-8, never
/// leading or trailing whitespace (both clients trim it off the header line).
fn patch_path() -> impl Strategy<Value = String> {
    let segment = prop_oneof![
        "[a-zA-Z0-9_.-]{1,8}",
        Just("..".to_string()),
        Just(".ssh".to_string()),
        Just("my file".to_string()),
        Just("é".to_string()),
    ];
    (any::<bool>(), prop::collection::vec(segment, 1..5))
        .prop_map(|(absolute, segments)| format!("{}{}", if absolute { "/" } else { "" }, segments.join("/")))
}

/// Commands a wrapper might run — one whose head is what a rule names, and one that is
/// itself a wrapper layer (`bash -c`), since layers compose.
const WRAPPED_COMMANDS: &[&str] = &[
    "rm -rf /",
    "python -u",
    "curl https://example.test/x",
    "bash -c echo",
];

/// A wrapper paired with a spelling of its own arguments: flags that take a value,
/// flags that do not, environment assignments, and `timeout`'s leading DURATION.
fn wrapper_invocation() -> impl Strategy<Value = (&'static str, &'static str)> {
    prop::sample::select(
        &[
            ("sudo", ""),
            ("sudo", "-i"),
            ("sudo", "-n"),
            ("sudo", "-H -E"),
            ("sudo", "-u root"),
            ("sudo", "--user root"),
            ("sudo", "-u root -g wheel"),
            ("doas", ""),
            ("doas", "-u root"),
            ("env", ""),
            ("env", "-i"),
            ("env", "FOO=bar"),
            ("env", "FOO=bar BAZ=qux"),
            ("env", "-u FOO"),
            ("nohup", ""),
            ("setsid", ""),
            ("exec", ""),
            ("command", ""),
            ("builtin", ""),
            ("time", ""),
            ("time", "-p"),
            ("time", "-o /tmp/t"),
            ("timeout", "5"),
            ("timeout", "0.5"),
            ("timeout", "10s"),
            ("timeout", "-k 30 5"),
            ("timeout", "--signal KILL 5"),
            ("stdbuf", "-oL"),
            ("stdbuf", "-o L"),
            ("stdbuf", "-i0 -oL"),
            ("stdbuf", "-e 0"),
            ("busybox", ""),
        ][..],
    )
}

proptest! {
    /// "Pure; never panics; allocates one `String`." Every kind, any input.
    #[test]
    fn no_normaliser_panics_on_any_input(input in evasive()) {
        for kind in ALL {
            let _ = apply(kind, &input);
        }
    }

    /// The same claim against wholly unconstrained Unicode, so the guarantee does not
    /// depend on the evasion vocabulary above being complete.
    #[test]
    fn no_normaliser_panics_on_arbitrary_unicode(input in "\\PC*") {
        for kind in ALL {
            let _ = apply(kind, &input);
        }
    }

    /// A canonical form is a normalisation, not an expansion: no input may blow its
    /// output up super-linearly. The bound is deliberately loose — it is here to catch
    /// the class (recursive `bash -c` unwinding, repeated multi-form joins), not to pin
    /// a ratio. `Sql` alone may nearly double, emitting two forms plus the separator.
    #[test]
    fn output_never_grows_super_linearly(input in evasive()) {
        for kind in ALL {
            let out = apply(kind, &input);
            prop_assert!(
                out.len() <= 8 * input.len() + 64,
                "{kind:?} grew {} -> {} on {input:?}",
                input.len(),
                out.len()
            );
        }
    }

    /// `Raw` is documented as "Identity. Explicit no-op" — the variant that distinguishes
    /// "we considered this field" from "no profile registered". If it ever stops being
    /// the identity, every field declared low-risk starts matching something else.
    ///
    /// Exactly one character is excluded, and the exclusion IS a claim rather than a
    /// hole in this one: `MULTIFORM_SEP` is structure and never text, so no canonical
    /// form may carry one — see `no_form_ever_carries_the_separator`. Identity is
    /// asserted over every other input the generator can produce.
    #[test]
    fn raw_is_the_identity_but_for_the_structural_separator(input in evasive()) {
        let expected: String = input.chars().filter(|c| *c != MULTIFORM_SEP).collect();
        prop_assert_eq!(apply(Normalizer::Raw, &input), expected);
    }

    /// The separator marks where one canonical form ends, and the matcher is handed the
    /// forms as a LIST precisely so nothing else can claim to be one. A form that
    /// carried a separator would be read as several the normaliser never created, and
    /// a needle spanning the cut would match none of them — `https://host/pa%00th`
    /// matching neither `host/path` nor `host/pa`. So the claim is absolute, and it has
    /// to cover the pass that DECODES: `%00` is an argument asking for a boundary.
    #[test]
    fn no_form_ever_carries_the_separator(input in evasive()) {
        for kind in ALL {
            for form in apply_forms(kind, &input) {
                prop_assert!(
                    !form.contains(MULTIFORM_SEP),
                    "{kind:?} let {input:?} carry a separator into {form:?}"
                );
            }
        }
    }

    /// The form COUNT is the normaliser's own. Only `Sql` reads an input two ways, and
    /// only as the two comment-stripping readings it documents; no input may add a
    /// third, and none may split a normaliser that has nothing ambiguous to say.
    /// `Patch` is left out because its count is not a reading but the number of files
    /// the patch names — `every_file_a_patch_touches_is_a_path_form` holds it.
    #[test]
    fn only_sql_returns_more_than_one_form(input in evasive()) {
        for kind in [
            Normalizer::Shell,
            Normalizer::Url,
            Normalizer::Path,
            Normalizer::Raw,
        ] {
            prop_assert_eq!(
                apply_forms(kind, &input).len(),
                1,
                "{:?} returned several forms for {:?}",
                kind,
                input
            );
        }
        prop_assert!(
            apply_forms(Normalizer::Sql, &input).len() <= 2,
            "sql read {input:?} more than two ways"
        );
    }

    // ─── shell ────────────────────────────────────────────────────────────────

    /// "IFS-expansion evasions are expanded to a literal space before tokenisation."
    /// A surviving `$IFS` is a bypass: `rm$IFS-rf` would canonicalise to something a
    /// `rm -rf` rule cannot see. `$IFSPATH` is a *different* variable and must survive,
    /// so the claim is scoped to an expansion that actually terminates.
    #[test]
    fn a_bare_ifs_expansion_never_survives_shell(
        prefix in "[a-zA-Z0-9 /._:@=-]{0,16}",
        suffix in "[a-zA-Z0-9 /._:@=-]{0,16}",
        brace in any::<bool>(),
    ) {
        // The claim is about an expansion the *raw input* carries. Quote and backslash
        // characters are excluded from the surrounding text because shlex unescaping can
        // reconstruct the literal `$IFS` afterwards (`$\IFS`, `$'IFS'`), which the shell
        // would not expand either — so their output is correct and outside this claim.
        let expansion = if brace { "${IFS}" } else { "$IFS" };
        let input = format!("{prefix}{expansion}{suffix}");
        let out = apply(Normalizer::Shell, &input);
        let bytes = out.as_bytes();
        for (i, _) in out.match_indices("$IFS") {
            let next = bytes.get(i + 4);
            let is_identifier_continuation =
                matches!(next, Some(b) if b.is_ascii_alphanumeric() || *b == b'_');
            prop_assert!(
                is_identifier_continuation,
                "a bare $IFS survived shell normalisation of {input:?} -> {out:?}"
            );
        }
    }

    /// Canonicalisation without expansion never destroys a value. Scoped away from the
    /// three inputs where emptying is *correct*: `$IFS` alone expands to whitespace (the
    /// value genuinely is whitespace once the shell evaluates it), a lone separator like
    /// `;` is not a command, and a value that is entirely a `#` comment runs nothing at
    /// all. Outside those, an empty canonical form would make every `contains_any` rule
    /// on the field vacuous.
    ///
    /// The comment case is bounded by unit tests rather than waved away: a comment must
    /// not swallow the command *in front of* it, and a mid-word `#` must not be read as
    /// one — either would truncate a value silently, which is a bypass rather than a
    /// canonical form.
    #[test]
    fn shell_never_empties_a_value_that_carries_a_token(input in evasive()) {
        prop_assume!(!input.contains('$'));
        prop_assume!(input.chars().any(|c| c.is_ascii_alphanumeric()));
        prop_assume!(!input.trim_start().starts_with('#'));
        let out = apply(Normalizer::Shell, &input);
        prop_assert!(!out.is_empty(), "shell emptied {input:?}");
    }

    /// "On unparseable input (mismatched quotes etc.), falls back to the
    /// whitespace-collapsed original — never empties the value, since downstream
    /// `contains_any` rules rely on something non-empty being there." The fallback is
    /// the branch that matters: an attacker who can make the tokeniser give up and the
    /// value vanish has defeated every rule on that field at once, so the generator
    /// builds inputs that force the failure rather than hoping to stumble on one.
    #[test]
    fn an_unparseable_shell_value_falls_back_instead_of_vanishing(
        body in "[a-z0-9 /._-]{1,24}",
        quote in prop_oneof![Just('\''), Just('"')],
        trailing_backslash in any::<bool>(),
    ) {
        let mut input = format!("{quote}{body}");
        if trailing_backslash {
            input.push('\\');
        }
        let out = apply(Normalizer::Shell, &input);
        prop_assert!(!out.is_empty(), "unparseable value vanished: {input:?}");
    }

    /// `shell_argv` reads the *normalised* form and emits one candidate vector per
    /// statement per wrapper layer. Both bounds (`ARGV_MAX_UNWRAP`, one statement per
    /// separator) exist so a crafted chain cannot make rule evaluation super-linear,
    /// and no emitted vector may be empty — `argv[0]` is what every rule reads.
    #[test]
    fn shell_argv_is_bounded_and_never_emits_an_empty_vector(input in evasive()) {
        let normalized = apply(Normalizer::Shell, &input);
        let vectors = shell_argv(&normalized);
        // The bound comes from the separator set `shell_argv` itself splits on — a single
        // `&` is one of them, and is not a statement separator during normalisation, so a
        // whitespace-word count would understate the candidates by an order of magnitude.
        let statements = 1 + normalized.chars().filter(|c| ";|&\n".contains(*c)).count();
        prop_assert!(
            vectors.len() <= 5 * statements,
            "argv candidates exploded on {input:?}: {} vectors, {statements} statements",
            vectors.len()
        );
        for v in &vectors {
            prop_assert!(!v.is_empty(), "empty argv candidate from {input:?}");
        }
    }

    /// "A layer per wrapper": a wrapper never hides the command it runs. This is the
    /// claim behind every consumer that reads a command's head — an `argv[0]` rule,
    /// `is_piped_exec`, `is_package_install` — and its failure direction is the quiet
    /// one, a rule that validates and then never fires.
    ///
    /// The generator pairs a wrapper only with ITS OWN option spellings, and that
    /// restriction is the claim rather than a convenience: the flag table is per-wrapper
    /// because the same letter differs between them (`-i` is boolean for `sudo` and
    /// `env`, a value flag for `stdbuf`), so a flag borrowed from another wrapper
    /// describes an invocation that would not run. A wrapper's own operand (`timeout`'s
    /// DURATION) is included, because that is the shape the table used to skip entirely.
    #[test]
    fn a_wrapper_never_hides_the_command_it_runs(
        (wrapper, own_args) in wrapper_invocation(),
        command in prop::sample::select(WRAPPED_COMMANDS),
    ) {
        let line = if own_args.is_empty() {
            format!("{wrapper} {command}")
        } else {
            format!("{wrapper} {own_args} {command}")
        };
        let normalized = apply(Normalizer::Shell, &line);
        let heads: Vec<&str> = shell_argv(&normalized)
            .iter()
            .filter_map(|argv| argv.first().copied())
            .collect();
        let wrapped_head = command.split(' ').next().expect("non-empty command");
        prop_assert!(
            heads.contains(&wrapped_head),
            "{line:?} hid {wrapped_head:?} — candidate heads were {heads:?}"
        );
        // The wrapper itself stays matchable: a rule may legitimately name either.
        prop_assert!(
            heads.contains(&wrapper),
            "{line:?} lost the wrapper itself — candidate heads were {heads:?}"
        );
        // And no peel may offer one of the wrapper's own arguments as a command. That
        // is the wrong-answer direction the per-wrapper table exists to prevent, and it
        // is invisible in a heads-contains assertion on its own.
        prop_assert!(
            !heads.iter().any(|h| h.starts_with('-')),
            "{line:?} offered an option as a command head: {heads:?}"
        );
    }

    /// A POSIX-style shell given `-c` runs its first operand: Codex's `bash -lc "<command>"`,
    /// and any spelling of the same — the `c` in a cluster (`-lc`), options before and
    /// after the cluster holding it (`-ec -c`, `-c -e`), an `o` in any cluster with the
    /// value it takes (`-euo pipefail`, `-co pipefail`), a long option and its value, a
    /// `--` or a lone `-`.
    /// Every such invocation must offer the command it runs at position 0, and the
    /// interpreter stays matchable.
    #[test]
    fn a_clustered_dash_c_never_hides_the_command_it_runs(
        interpreter in prop::sample::select(&["bash", "sh", "/bin/bash", "zsh", "dash"][..]),
        before in prop::collection::vec(shell_option(), 0..3),
        cluster in ("[a-bd-z]{0,2}", "[a-bd-z]{0,2}").prop_map(|(b, a)| with_option_values(&format!("-{b}c{a}"))),
        after in prop::collection::vec(shell_option(), 0..3),
        end_of_options in prop::option::of(prop::sample::select(&["--", "-"][..])),
        command in prop::sample::select(WRAPPED_COMMANDS),
    ) {
        let mut words: Vec<String> = vec![interpreter.to_string()];
        words.extend(before);
        words.push(cluster);
        words.extend(after);
        if let Some(end) = end_of_options {
            words.push(end.into());
        }
        let line = format!("{} '{command}'", words.join(" "));
        let normalized = apply(Normalizer::Shell, &line);
        let heads: Vec<&str> = shell_argv(&normalized)
            .iter()
            .filter_map(|argv| argv.first().copied())
            .collect();
        let wrapped_head = command.split(' ').next().expect("non-empty command");
        prop_assert!(heads.contains(&wrapped_head), "{line:?} hid {wrapped_head:?} — heads were {heads:?}");
        prop_assert!(heads.contains(&interpreter), "{line:?} lost the interpreter — heads were {heads:?}");
    }

    // ─── sql ──────────────────────────────────────────────────────────────────

    /// "Lowercase … collapse runs of whitespace to a single space." Every form is
    /// `to_ascii_lowercase` then `split_whitespace().join(" ")`, so the canonical text
    /// carries no ASCII uppercase, no whitespace other than single interior spaces, and
    /// no leading or trailing space. A rule needle goes through the same pass, so a
    /// break here silently stops every SQL rule from matching.
    #[test]
    fn sql_forms_are_lowercase_and_whitespace_collapsed(input in evasive()) {
        for form in apply_forms(Normalizer::Sql, &input) {
            let form = form.as_str();
            prop_assert!(
                !form.chars().any(|c| c.is_ascii_uppercase()),
                "uppercase survived: {form:?} from {input:?}"
            );
            prop_assert!(
                !form.chars().any(|c| c.is_whitespace() && c != ' '),
                "non-space whitespace survived: {form:?} from {input:?}"
            );
            prop_assert!(!form.contains("  "), "double space: {form:?} from {input:?}");
            prop_assert_eq!(form, form.trim(), "untrimmed form from {:?}", input);
        }
    }

    /// "strip `--…\n` … comments". The line-comment scanner runs *after* block-comment
    /// stripping, so a `--` reconstructed by removing a comment between two dashes
    /// (`-/*x*/-`) is caught by the same pass — no `--` may reach the canonical form.
    #[test]
    fn sql_leaves_no_line_comment_marker(input in evasive()) {
        for form in apply_forms(Normalizer::Sql, &input) {
            prop_assert!(!form.contains("--"), "line comment survived: {form:?} from {input:?}");
        }
    }

    /// The multi-form contract: either the two comment-stripping forms agree and the
    /// canonical value is one form, or they differ and it is exactly two. A third form,
    /// or two identical ones, would change what a rule any-matches against.
    #[test]
    fn sql_emits_exactly_one_or_two_forms(input in evasive()) {
        let forms = apply_forms(Normalizer::Sql, &input);
        prop_assert!(forms.len() == 1 || forms.len() == 2, "{} forms from {input:?}", forms.len());
        if forms.len() == 2 {
            prop_assert_ne!(&forms[0], &forms[1], "two identical forms from {:?}", input);
        }
    }

    // ─── path ─────────────────────────────────────────────────────────────────

    /// "NEVER expands `~`". The proxy host is not the agent host, so resolving a home
    /// directory here would canonicalise to a path that does not exist on the machine
    /// the command runs on — and a rule written against `~/.aws/credentials` would stop
    /// matching the argument that reads it.
    #[test]
    fn path_never_expands_the_home_anchor(tail in evasive()) {
        // The anchor is prefixed by construction rather than filtered for: a
        // `prop_assume!` that a random value happens to start with `~` rejects
        // essentially every case, and the property then proves nothing.
        //
        // The anchor is the *segment* `~`, not the character. `~*` is an ordinary
        // directory name, so `~*/..` collapsing to `.` is correct lexical
        // normalisation and not an expansion — hence the separator here.
        let input = format!("~/{tail}");
        let out = apply(Normalizer::Path, &input);
        let first_segment = out.split('/').next().unwrap_or_default();
        prop_assert_eq!(first_segment, "~", "~ was resolved: {:?} -> {:?}", input, out);
    }

    /// "normalise separator (`\\` → `/`), trim trailing `/`". Two spellings of one path
    /// must not survive as two canonical forms, or a rule matches one and misses the other.
    #[test]
    fn path_has_one_separator_and_no_trailing_slash(input in evasive()) {
        let out = apply(Normalizer::Path, &input);
        prop_assert!(!out.contains('\\'), "backslash survived: {out:?} from {input:?}");
        prop_assert!(
            out.len() <= 1 || !out.ends_with('/'),
            "trailing slash survived: {out:?} from {input:?}"
        );
    }

    /// "collapse `..`". A `..` may only remain where there is nothing to pop against —
    /// first, after another `..`, or directly after the `~` anchor. A `..` following a
    /// named segment means the collapse did not run, and `/etc/../etc/shadow` would
    /// then not match a rule on `/etc/shadow`.
    #[test]
    fn path_leaves_dotdot_only_where_it_cannot_be_collapsed(input in evasive()) {
        let out = apply(Normalizer::Path, &input);
        let mut previous: Option<&str> = None;
        for segment in out.trim_start_matches('/').split('/') {
            if segment == ".." {
                prop_assert!(
                    matches!(previous, None | Some("..") | Some("~")),
                    "uncollapsed `..` after {previous:?}: {out:?} from {input:?}"
                );
            }
            previous = Some(segment);
        }
    }

    /// A path with content never canonicalises to nothing — an empty canonical value
    /// can match no `contains` rule, so a value that vanishes is a rule that stops
    /// firing on a field an operator is watching.
    ///
    /// "Content" excludes the structural separator, and that exclusion is a claim
    /// rather than a hole: it is not text, it is removed from every value entering the
    /// matcher, and a value made of nothing else has no content for a needle to name
    /// — no needle can match `"\0"` and not `""`, since an empty needle never matches
    /// either.
    #[test]
    fn path_never_empties_a_value_that_has_content(input in evasive()) {
        prop_assume!(input.chars().any(|c| c != MULTIFORM_SEP));
        prop_assert!(!apply(Normalizer::Path, &input).is_empty(), "path emptied {input:?}");
    }

    // ─── patch ────────────────────────────────────────────────────────────────

    /// "Every file a patch envelope names, `path`-normalised … once each." A file the
    /// client would add, delete, update or move to and that no form names is a path
    /// rule that never fires on the edit. The envelope is spelled the ways the two
    /// clients' parsers accept it: header lines indented or trailing whitespace (U+FEFF
    /// among it, which OpenCode's JavaScript trim strips), CRLF
    /// line ends, a heredoc wrapper, the move header under an update.
    ///
    /// Deliberately NOT a property: that ONLY those files appear. A header-shaped line
    /// inside a hunk's body is read as a file too — one path too many is the safe
    /// direction.
    #[test]
    fn every_file_a_patch_touches_is_a_path_form(
        hunks in prop::collection::vec((0usize..4, patch_path(), patch_path()), 1..6),
        indent in "[ \t\u{feff}]{0,2}",
        trailing in "[ \t\u{feff}]{0,2}",
        crlf in any::<bool>(),
        heredoc in any::<bool>(),
    ) {
        let mut lines: Vec<String> = Vec::new();
        if heredoc {
            lines.push("<<'EOF'".into());
        }
        lines.push("*** Begin Patch".into());
        let mut expected: Vec<&str> = Vec::new();
        for (kind, file, moved_to) in &hunks {
            let header = |marker: &str, path: &str| format!("{indent}{marker}{path}{trailing}");
            match kind {
                0 => {
                    lines.push(header("*** Add File: ", file));
                    lines.push("+added".into());
                    expected.push(file);
                }
                1 => {
                    lines.push(header("*** Delete File: ", file));
                    expected.push(file);
                }
                2 => {
                    lines.push(header("*** Update File: ", file));
                    lines.extend(["@@".into(), " kept".into(), "-old".into(), "+new".into()]);
                    expected.push(file);
                }
                _ => {
                    lines.push(header("*** Update File: ", file));
                    lines.push(header("*** Move to: ", moved_to));
                    lines.extend(["@@".into(), "-old".into(), "+new".into()]);
                    expected.extend([file.as_str(), moved_to.as_str()]);
                }
            }
        }
        lines.push("*** End Patch".into());
        if heredoc {
            lines.push("EOF".into());
        }
        let text = lines.join(if crlf { "\r\n" } else { "\n" });
        let forms = apply_forms(Normalizer::Patch, &text);
        for file in expected {
            let canonical = apply(Normalizer::Path, file);
            prop_assert!(forms.contains(&canonical), "{file:?} ({canonical:?}) missing from {forms:?} for {text:?}");
        }
        let mut unique = forms.clone();
        unique.sort();
        unique.dedup();
        prop_assert_eq!(unique.len(), forms.len(), "a file was named twice: {:?}", forms);
    }

    /// "A shell call that only applies a patch is also read as the patch tool." Every
    /// file the patch touches is an `arg.path` form of that reading under each
    /// spelling Codex runs it by — an argv, either patch command, a heredoc under
    /// `bash -lc` as an argv or one string — while the shell call itself stays the
    /// shell tool. A file the shell form hides is a path rule that never fires on
    /// the edit.
    ///
    /// The claim covers exactly the shapes Codex intercepts; a command that also
    /// runs something else is a shell command only (`shell_patch_body`), asserted by
    /// the seeded `a_patch_applied_through_the_shell_is_read_by_the_write_rule`.
    #[test]
    fn every_file_a_shell_patch_touches_is_a_path_form(
        files in prop::collection::vec(patch_path(), 1..4),
        spelling in 0usize..5,
    ) {
        use streamscope_core::config::tool_rules::{FieldProfile, FieldProfileSet, TargetResolver, ToolCallResolver};
        let profile = |tool_id: &str, pattern: &str, field: &str, wire: Option<&str>, normalizer| FieldProfile {
            id: None,
            description: None,
            source: None,
            tool_id: tool_id.into(),
            tool_pattern: pattern.into(),
            app_filter: None,
            mcp_server: None,
            server_type: None,
            field: field.into(),
            wire_field: wire.map(str::to_string),
            normalizer,
            priority: 100,
            is_builtin: false,
        };
        let profiles = FieldProfileSet::new(vec![
            profile("shell_exec", "shell", "command", None, Normalizer::Shell),
            profile("edit_file", "apply_patch", "path", Some("input"), Normalizer::Patch),
        ]);
        let mut patch = String::from("*** Begin Patch\n");
        for file in &files {
            patch.push_str(&format!("*** Update File: {file}\n@@\n-a\n+b\n"));
        }
        patch.push_str("*** End Patch\n");
        let heredoc = format!("apply_patch <<'EOF'\n{patch}EOF\n");
        let command = match spelling {
            0 => serde_json::json!(["apply_patch", patch]),
            1 => serde_json::json!(["applypatch", patch]),
            2 => serde_json::json!(["bash", "-lc", heredoc]),
            3 => serde_json::json!(["/bin/bash", "-c", heredoc]),
            _ => serde_json::json!(heredoc),
        };
        let args = serde_json::json!({ "command": command });
        let resolver = ToolCallResolver {
            name: "shell",
            arguments: Some(&args),
            field_profiles: Some(&profiles),
            app_id: None,
            mcp_server: None,
            tool_id: Some("shell_exec"),
        };
        // The shell call is itself only: its reading as the patch tool is a
        // separate one (`patch_block`), and that is where the files are.
        prop_assert_eq!(resolver.resolve("tool_id"), Some(vec!["shell_exec".to_string()]));
        let reading = resolver.patch_reading();
        prop_assert!(reading.is_some(), "{command} was not read as a patch");
        let reading = reading.unwrap();
        prop_assert_eq!(reading.tool_id.as_deref(), Some("edit_file"));
        let patch_tool = ToolCallResolver {
            name: "apply_patch",
            arguments: Some(&reading.arguments),
            field_profiles: Some(&profiles),
            app_id: None,
            mcp_server: None,
            tool_id: reading.tool_id.as_deref(),
        };
        let paths = patch_tool.resolve("arg.path").unwrap_or_default();
        for file in &files {
            let canonical = apply(Normalizer::Path, file);
            prop_assert!(paths.contains(&canonical), "{file:?} ({canonical:?}) missing from {paths:?} for {command}");
        }
    }

    /// "No script running anything else qualifies": a heredoc patch followed, after
    /// the delimiter line that closes it (tab-indented under `<<-`), by any further
    /// non-blank line — a statement the shell runs — is never read as a patch.
    #[test]
    fn a_script_running_anything_after_its_patch_is_no_patch(
        dash in any::<bool>(),
        tabs in "\t{0,2}",
        extra in "[ -~]{1,24}",
    ) {
        use streamscope_core::config::tool_rules::{FieldProfile, FieldProfileSet, ToolCallResolver};
        prop_assume!(!extra.trim().is_empty());
        let profiles = FieldProfileSet::new(vec![FieldProfile {
            id: None,
            description: None,
            source: None,
            tool_id: "shell_exec".into(),
            tool_pattern: "shell".into(),
            app_filter: None,
            mcp_server: None,
            server_type: None,
            field: "command".into(),
            wire_field: None,
            normalizer: Normalizer::Shell,
            priority: 100,
            is_builtin: false,
        }]);
        let closing = if dash { format!("{tabs}EOF") } else { "EOF".to_string() };
        let script = format!(
            "apply_patch <<{}'EOF'\n*** Begin Patch\n*** Add File: a\n+x\n*** End Patch\n{closing}\n{extra}\n",
            if dash { "-" } else { "" }
        );
        let args = serde_json::json!({ "command": ["bash", "-lc", script] });
        let resolver = ToolCallResolver {
            name: "shell",
            arguments: Some(&args),
            field_profiles: Some(&profiles),
            app_id: None,
            mcp_server: None,
            tool_id: Some("shell_exec"),
        };
        prop_assert!(resolver.patch_reading().is_none(), "{script:?} was read as a patch");
    }

    /// "A value naming no file … is offered whole as one form", so a field holding
    /// something other than a patch still meets a rule's needle instead of resolving
    /// to nothing.
    #[test]
    fn a_patch_naming_no_file_is_read_whole(input in evasive()) {
        prop_assume!(!input.contains("File:") && !input.contains("Move to:"));
        let expected: String = input.chars().filter(|c| *c != MULTIFORM_SEP).collect();
        prop_assert_eq!(apply_forms(Normalizer::Patch, &input), vec![expected]);
    }

    // ─── url ──────────────────────────────────────────────────────────────────

    /// "lowercase scheme & host". Case is not a distinction DNS makes, so leaving it in
    /// leaves `HTTPS://Metadata.Google.INTERNAL` as a spelling no rule was written for.
    #[test]
    fn url_lowercases_scheme_and_authority(input in evasive()) {
        let out = apply(Normalizer::Url, &input);
        let Some(scheme_end) = out.find("://") else {
            // No authority: the whole value is lowercased instead.
            prop_assert!(
                !out.chars().any(|c| c.is_ascii_uppercase()),
                "uppercase in schemeless url {out:?} from {input:?}"
            );
            return Ok(());
        };
        prop_assert!(
            !out[..scheme_end].chars().any(|c| c.is_ascii_uppercase()),
            "uppercase scheme in {out:?} from {input:?}"
        );
        let rest = &out[scheme_end + 3..];
        let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        let host = match host_port.rfind(':') {
            Some(p) if !host_port.contains(']') => &host_port[..p],
            _ => host_port,
        };
        prop_assert!(
            !host.chars().any(|c| c.is_ascii_uppercase()),
            "uppercase host {host:?} in {out:?} from {input:?}"
        );
    }

    /// The cloud-metadata aliases are the reason this normaliser exists: an IMDS
    /// credential-theft rule is written against `169.254.169.254`, and every alias must
    /// arrive there whatever the casing. If one spelling survives, the rule is bypassed
    /// by typing the hostname differently.
    #[test]
    fn every_metadata_alias_canonicalises_to_the_link_local_address(
        alias in prop_oneof![
            Just("metadata.google.internal"),
            Just("metadata.googleapis.com"),
            Just("metadata.azure.com"),
            Just("instance-data.ec2.internal"),
            Just("instance-data"),
        ],
        upper in proptest::collection::vec(any::<bool>(), 0..40),
        scheme in prop_oneof![Just("http"), Just("HTTP"), Just("hTTps")],
        // A port is part of the alias surface: the host:port split has to happen before
        // the alias lookup, or `metadata.google.internal:80` is compared whole, matches
        // nothing, and the IMDS rule is bypassed by naming the default port explicitly.
        port in prop_oneof![Just(String::new()), Just(":80".to_string()), Just(":8080".to_string())],
        tail in "[a-z0-9/._-]{0,20}",
    ) {
        let spelled: String = alias
            .chars()
            .enumerate()
            .map(|(i, c)| if *upper.get(i).unwrap_or(&false) { c.to_ascii_uppercase() } else { c })
            .collect();
        let out = apply(Normalizer::Url, &format!("{scheme}://{spelled}{port}/{tail}"));
        prop_assert!(
            out.starts_with(&format!("{}://169.254.169.254{port}/", scheme.to_ascii_lowercase())),
            "alias {spelled:?}{port} did not canonicalise: {out:?}"
        );
    }

    /// "Each normaliser performs at most one decode pass … Layered re-decoding is
    /// intentionally NOT done." This pins the decision rather than the accident: a
    /// double-encoded `%25XX` must arrive as the literal `%XX`, which is what lets
    /// `tool_rules_detectors::is_double_encoded_url` recognise the *shape* instead.
    #[test]
    fn url_decoding_is_single_pass(byte in 0u8..=255u8, host in "[a-z]{1,8}", lower in any::<bool>()) {
        let escaped = if lower { format!("{byte:02x}") } else { format!("{byte:02X}") };
        let out = apply(Normalizer::Url, &format!("https://{host}/%25{escaped}"));
        prop_assert_eq!(
            out,
            format!("https://{host}/%{escaped}"),
            "second decode pass ran on %25{}", escaped
        );
    }

    /// Percent-encoding is case-insensitive in its hex digits (RFC 3986 §2.1), and the
    /// lowercase spelling is the one an evasion reaches for. Both spellings must decode
    /// to the same byte, or a rule written against the canonical form matches `%2F` and
    /// misses `%2f` — the separator that turns a path segment into a traversal.
    #[test]
    fn percent_hex_digits_decode_case_insensitively(byte in 0u8..=255u8, host in "[a-z]{1,8}") {
        let upper = apply(Normalizer::Url, &format!("https://{host}/x%{byte:02X}y"));
        let lower = apply(Normalizer::Url, &format!("https://{host}/x%{byte:02x}y"));
        prop_assert_eq!(&upper, &lower, "case-sensitive hex decode for byte {}", byte);
    }
}

// ─── an argument's value, before any normaliser ─────────────────────────────

/// The value of a field marked as a shell command, resolved the way a rule reads
/// it (`arg.command`), for a tool whose one profile marks `command` as one.
fn shell_field_forms(value: serde_json::Value) -> Vec<String> {
    field_forms(Normalizer::Shell, value)
}

/// The value of `command`, resolved the way a rule reads it, for a tool whose
/// one profile marks it with `normalizer`.
fn field_forms(normalizer: Normalizer, value: serde_json::Value) -> Vec<String> {
    use streamscope_core::config::tool_rules::{FieldProfile, FieldProfileSet, TargetResolver, ToolCallResolver};
    let profiles = FieldProfileSet::new(vec![FieldProfile {
        id: None,
        description: None,
        source: None,
        tool_id: "shell_exec".into(),
        tool_pattern: "run".into(),
        app_filter: None,
        mcp_server: None,
        server_type: None,
        field: "command".into(),
        wire_field: None,
        normalizer,
        priority: 100,
        is_builtin: false,
    }]);
    let args = serde_json::json!({ "command": value });
    let resolver = ToolCallResolver {
        name: "run",
        arguments: Some(&args),
        field_profiles: Some(&profiles),
        app_id: None,
        mcp_server: None,
        tool_id: Some("shell_exec"),
    };
    resolver.resolve("arg.command").unwrap_or_default()
}

/// A command that is not a wrapper, so the words after it are its own.
const PLAIN_COMMANDS: &[&str] = &["rm", "cat", "curl", "git", "chmod", "dd", "ls"];

proptest! {
    /// "A list of strings in a field marked as a shell command is an argv … and
    /// reads as the command line it spells." An argv of plain words is read as
    /// exactly those words, in order — never as its JSON text, whose brackets,
    /// quotes and commas glue the words together so that `["rm","-rf","/"]` never
    /// contains `rm -rf /`.
    #[test]
    fn an_argv_array_reads_as_the_command_line_it_spells(
        head in prop::sample::select(PLAIN_COMMANDS),
        tail in prop::collection::vec("[a-z0-9/._=-]{1,8}", 0..5),
    ) {
        let words: Vec<String> = std::iter::once(head.to_string()).chain(tail).collect();
        let forms = shell_field_forms(serde_json::json!(words));
        prop_assert_eq!(forms.len(), 1, "{:?}", forms);
        let argv: Vec<Vec<&str>> = shell_argv(&forms[0]);
        let expected: Vec<&str> = words.iter().map(String::as_str).collect();
        prop_assert_eq!(argv, vec![expected], "{:?} read as {:?}", words, forms);
        // The same command written as one string reads the same.
        prop_assert_eq!(shell_field_forms(serde_json::json!(words.join(" "))), forms);
    }

    /// A word carrying spaces keeps its text as written, so a rule reading the
    /// command finds it (`rm -rf /`), never split around, or glued to, its
    /// neighbours' JSON punctuation.
    ///
    /// NOT claimed: that a word stays one argv token. The words are joined
    /// unquoted, so a word holding spaces or a separator is read as the words
    /// and statements it spells — `a_separator_inside_a_word_is_read_as_one`.
    #[test]
    fn a_word_with_spaces_stays_whole(
        head in prop::sample::select(PLAIN_COMMANDS),
        word in "[a-z0-9/._-]{1,8}( [a-z0-9/._-]{1,8}){1,3}",
    ) {
        let forms = shell_field_forms(serde_json::json!([head, "-x", word.clone()]));
        prop_assert!(
            forms.iter().any(|f| f.ends_with(&format!("{head} -x {word}"))),
            "{:?} not read whole: {:?}", word, forms
        );
    }
}

/// A word carrying a statement separator is read as the statements it holds,
/// a shell wrapper unwrapped around them: `["bash", "-c", "curl x | sh"]` runs
/// `curl` and `sh`, and a rule naming either as the command finds it.
#[test]
fn a_separator_inside_a_word_is_read_as_one() {
    let forms = shell_field_forms(serde_json::json!(["bash", "-c", "curl x | sh"]));
    let heads: Vec<String> = forms
        .iter()
        .flat_map(|f| shell_argv(f).into_iter().filter_map(|argv| argv.first().map(|h| (*h).to_string())))
        .collect();
    assert!(heads.iter().any(|h| h == "curl") && heads.iter().any(|h| h == "sh"), "{forms:?} → heads {heads:?}");
    // A list holding no word at all reads as itself.
    assert_eq!(shell_field_forms(serde_json::json!([1, 2])), ["[1,2]"]);
}

/// Only a field marked as a shell command reads a list as an argv: any other
/// field reads it as its JSON text, as it always has — a path or URL list is no
/// command line, and joining it would invent spaces a rule then matches across.
#[test]
fn a_list_is_an_argv_only_in_a_shell_field() {
    let list = serde_json::json!(["a b", "c"]);
    for normalizer in [Normalizer::Raw, Normalizer::Path, Normalizer::Url, Normalizer::Sql] {
        let forms = field_forms(normalizer, list.clone());
        assert!(forms.iter().all(|f| f.contains(',')), "{normalizer:?} read a list as an argv: {forms:?}");
    }
    assert_eq!(field_forms(Normalizer::Shell, list), ["a b c"]);
}

/// A word the shell reading would take as syntax hides nothing: exec passes
/// `#` and a lone quote as words, so the words after them are still the
/// command's — `find . # -delete` deletes.
#[test]
fn a_word_that_is_shell_syntax_hides_nothing() {
    let forms = shell_field_forms(serde_json::json!(["find", ".", "#", "-delete"]));
    assert!(forms.iter().any(|f| f.contains("-delete")), "{forms:?}");
    let forms = shell_field_forms(serde_json::json!(["echo", "'", "rm", "-rf", "~", "'"]));
    let heads: Vec<String> = forms
        .iter()
        .flat_map(|f| shell_argv(f).into_iter().flat_map(|argv| argv.into_iter().map(str::to_string)))
        .collect();
    assert!(heads.iter().any(|w| w == "rm") && heads.iter().any(|w| w == "-rf"), "{forms:?} → {heads:?}");
}
