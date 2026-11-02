//! Terminal look: the brand palette, the prompt theme, and the styled output
//! helpers. Every colour the CLI prints comes from here — no inline escapes.
//!
//! Prompts render on stderr (`demand`), command output on stdout; each stream
//! decides colour on its own (`NO_COLOR`, `CLICOLOR`, not a terminal → none),
//! so `--print` piped to a file stays plain while its prompts stay styled.

use std::sync::LazyLock;

use console::{Style, StyledObject};

/// One palette entry: the admin console's token as truecolor, the nearest
/// xterm-256 index, and the stand-in for a 16-colour terminal.
#[derive(Clone, Copy)]
struct Brand {
    rgb: (u8, u8, u8),
    ansi256: u8,
    basic: Tone,
}

/// How many colours the terminal takes.
#[derive(Clone, Copy)]
enum Depth {
    True,
    Ansi256,
    Basic,
}

/// Truecolor when the terminal advertises it (`COLORTERM`, read by
/// `console`), xterm-256 when `TERM` names it, basic ANSI otherwise — the
/// Linux console, a bare `xterm`, a serial line.
fn depth_for(truecolor: bool, term: Option<&str>) -> Depth {
    // Terminals whose TERM does not say `256color` but which take it — and
    // whose `COLORTERM` an SSH hop does not forward.
    const WIDE: [&str; 6] = ["256color", "kitty", "alacritty", "wezterm", "foot", "ghostty"];
    if truecolor {
        Depth::True
    } else if term.is_some_and(|t| WIDE.iter().any(|w| t.contains(w))) {
        Depth::Ansi256
    } else {
        Depth::Basic
    }
}

/// The depth of stderr (prompts, notes) or stdout (results), read once.
fn depth(stderr: bool) -> Depth {
    static STDERR: LazyLock<Depth> = LazyLock::new(|| {
        depth_for(console::true_colors_enabled_stderr(), std::env::var("TERM").ok().as_deref())
    });
    static STDOUT: LazyLock<Depth> = LazyLock::new(|| {
        depth_for(console::true_colors_enabled(), std::env::var("TERM").ok().as_deref())
    });
    if stderr { *STDERR } else { *STDOUT }
}

// Keep in sync with admin-ui/src/app.css. Body text deliberately has no entry:
// it is the terminal's own foreground, because the console's near-white
// `--text-primary` vanishes on a light terminal.
/// `--accent`: prompt titles, cursor, highlighted choice, paths.
const ACCENT: Brand = Brand { rgb: (0x3b, 0x82, 0xf6), ansi256: 69, basic: Tone::Blue };
/// `--success`: ticked boxes, `✓`.
const SUCCESS: Brand = Brand { rgb: (0x22, 0xc5, 0x5e), ansi256: 41, basic: Tone::Green };
/// `--warning`: `!` notes.
const WARNING: Brand = Brand { rgb: (0xea, 0xb3, 0x08), ansi256: 178, basic: Tone::Yellow };
/// `--error`: `✗ error:`.
const ERROR: Brand = Brand { rgb: (0xef, 0x44, 0x44), ansi256: 203, basic: Tone::Red };
/// `--text-tertiary`: hints, descriptions, key help.
const MUTED: Brand = Brand { rgb: (0x64, 0x74, 0x8b), ansi256: 243, basic: Tone::Dim };

/// One palette entry resolved for a depth — the single table both renderers
/// (`console` for output, `termcolor` for `demand`'s prompts) convert from.
/// `Dim` (the muted text) has no colour at basic depth, so it is the faint
/// attribute instead.
#[derive(Clone, Copy)]
enum Tone {
    Rgb(u8, u8, u8),
    Indexed(u8),
    Blue,
    Green,
    Yellow,
    Red,
    Dim,
}

impl Brand {
    fn tone(self, depth: Depth) -> Tone {
        match depth {
            Depth::True => Tone::Rgb(self.rgb.0, self.rgb.1, self.rgb.2),
            Depth::Ansi256 => Tone::Indexed(self.ansi256),
            Depth::Basic => self.basic,
        }
    }

    fn style(self, depth: Depth) -> Style {
        let style = Style::new();
        match self.tone(depth) {
            Tone::Rgb(r, g, b) => style.fg(console::Color::TrueColor(r, g, b)),
            Tone::Indexed(n) => style.fg(console::Color::Color256(n)),
            Tone::Blue => style.blue(),
            Tone::Green => style.green(),
            Tone::Yellow => style.yellow(),
            Tone::Red => style.red(),
            Tone::Dim => style.dim(),
        }
    }

    /// As a foreground; the muted entry is the faint attribute at basic depth.
    fn spec(self, depth: Depth) -> termcolor::ColorSpec {
        let mut spec = termcolor::ColorSpec::new();
        match self.colour(depth) {
            Some(c) => spec.set_fg(Some(c)),
            None => spec.set_dimmed(true),
        };
        spec
    }

    /// As a colour (the focused button's background); `None` for the muted
    /// entry at basic depth, which has no colour of its own.
    fn colour(self, depth: Depth) -> Option<termcolor::Color> {
        use termcolor::Color;
        match self.tone(depth) {
            Tone::Rgb(r, g, b) => Some(Color::Rgb(r, g, b)),
            Tone::Indexed(n) => Some(Color::Ansi256(n)),
            Tone::Blue => Some(Color::Blue),
            Tone::Green => Some(Color::Green),
            Tone::Yellow => Some(Color::Yellow),
            Tone::Red => Some(Color::Red),
            Tone::Dim => None,
        }
    }
}

/// Whether to use the styled prompts. They need a person at a terminal: stdin
/// to read keys from and stderr to draw on (where `demand` renders). Anything
/// else — a pipe, `TERM=dumb`, `STREAMSCOPE_PLAIN` — takes the numbered plain
/// prompts, which read a line from stdin and so also work scripted.
pub fn styled_prompts() -> bool {
    use std::io::IsTerminal;
    styled_prompts_for(
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
        std::env::var("TERM").ok().as_deref(),
        std::env::var("STREAMSCOPE_PLAIN").ok().as_deref(),
    )
}

fn styled_prompts_for(
    stdin_tty: bool,
    stderr_tty: bool,
    term: Option<&str>,
    plain: Option<&str>,
) -> bool {
    let plain_requested = plain.is_some_and(|v| !v.is_empty() && v != "0");
    stdin_tty && stderr_tty && term != Some("dumb") && !plain_requested
}

/// The prompt theme: `demand`'s Charm layout recoloured with the brand
/// palette. Without colour on stderr (`NO_COLOR`, `CLICOLOR=0`) every style
/// is cleared — `demand` writes escapes for whatever its theme names, so its
/// own "plain" theme still colours — and the focused button is bold and
/// underlined instead. The one style kept is the text cursor's black-on-white
/// block, without which an Input shows no cursor at all.
pub fn theme() -> &'static demand::Theme {
    static THEME: LazyLock<demand::Theme> = LazyLock::new(|| {
        let mut t = demand::Theme::charm();
        t.selected_prefix = String::from("[✓]");
        t.unselected_prefix = String::from("[ ]");
        if console::colors_enabled_stderr() {
            brand_colours(&mut t, depth(true));
        } else {
            no_colours(&mut t);
        }
        t
    });
    &THEME
}

fn brand_colours(t: &mut demand::Theme, d: Depth) {
    let mut title = ACCENT.spec(d);
    title.set_bold(true);
    t.title = title;
    t.error_indicator = ERROR.spec(d);
    t.description = MUTED.spec(d);
    t.cursor = ACCENT.spec(d);
    t.selected_prefix_fg = SUCCESS.spec(d);
    t.selected_option = ACCENT.spec(d);
    t.unselected_prefix_fg = MUTED.spec(d);
    t.unselected_option = termcolor::ColorSpec::new();
    t.input_cursor = ACCENT.spec(d);
    t.input_placeholder = MUTED.spec(d);
    t.input_prompt = ACCENT.spec(d);
    t.help_key = MUTED.spec(d);
    t.help_desc = MUTED.spec(d);
    t.help_sep = MUTED.spec(d);
    let mut focused = termcolor::ColorSpec::new();
    focused.set_fg(Some(termcolor::Color::White)).set_bg(ACCENT.colour(d)).set_bold(true);
    t.focused_button = focused;
    t.blurred_button = MUTED.spec(d);
}

fn no_colours(t: &mut demand::Theme) {
    let none = termcolor::ColorSpec::new;
    for spec in [
        &mut t.title,
        &mut t.error_indicator,
        &mut t.description,
        &mut t.cursor,
        &mut t.selected_option,
        &mut t.selected_prefix_fg,
        &mut t.unselected_option,
        &mut t.unselected_prefix_fg,
        &mut t.input_cursor,
        &mut t.input_placeholder,
        &mut t.input_prompt,
        &mut t.help_key,
        &mut t.help_desc,
        &mut t.help_sep,
        &mut t.blurred_button,
        &mut t.breadcrumb_active,
        &mut t.breadcrumb_clickable,
        &mut t.breadcrumb_future,
    ] {
        *spec = none();
    }
    let mut focused = none();
    focused.set_bold(true).set_underline(true);
    t.focused_button = focused;
    let mut cursor = none();
    cursor.set_fg(Some(termcolor::Color::White)).set_bg(Some(termcolor::Color::Black));
    t.cursor_style = cursor;
}

/// A prompt was answered with Esc / Ctrl-C. Nothing has been written at that
/// point, so the command stops (exit 1) with [`crate::Cancelled`].
pub fn aborted(e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::Interrupted {
        // On ^C `demand` returns before showing the cursor it hid, leaving it
        // to its signal thread — which the exit that follows can outrun.
        let _ = console::Term::stderr().show_cursor();
        anyhow::Error::new(crate::Cancelled)
    } else {
        anyhow::Error::new(e).context("prompt failed")
    }
}

/// Run one styled prompt. Ctrl-C at a prompt is a cancel: `console` reads it
/// as a byte and raises SIGINT on itself, and `demand` registers a SIGINT
/// action for the prompt through signal-hook's registry, which installs its
/// OS handler once and assumes it stays — so nothing here may touch SIGINT's
/// disposition directly. Outside a prompt SIGINT must still do what it did
/// before the first prompt (terminate, or nothing if it started ignored),
/// because `demand` leaves only the registry's handler behind: that is the
/// job of the one action [`sigint`] keeps in the same registry. Every styled
/// prompt runs through here.
pub fn prompt<T>(run: impl FnOnce() -> std::io::Result<T>) -> anyhow::Result<T> {
    #[cfg(unix)]
    sigint::prompt_open(true);
    let answer = run();
    #[cfg(unix)]
    sigint::prompt_open(false);
    answer.map_err(aborted)
}

/// The SIGINT action that stands in for the default outside prompts. It is
/// registered on the first prompt, so a command that never prompts (`run`,
/// whose sandbox forwards SIGINT to the confined client through tokio) never
/// carries it; a command that handles SIGINT itself must not prompt first.
#[cfg(unix)]
mod sigint {
    use std::sync::Once;
    use std::sync::atomic::{AtomicBool, Ordering};

    static PROMPT_OPEN: AtomicBool = AtomicBool::new(false);
    static STARTED_IGNORED: AtomicBool = AtomicBool::new(false);
    static REGISTER: Once = Once::new();

    /// Whether SIGINT ends the process: never while a prompt is open (it is
    /// that prompt's cancel), otherwise as it did before the first prompt.
    pub(super) fn terminates(prompt_open: bool, started_ignored: bool) -> bool {
        !prompt_open && !started_ignored
    }

    pub(super) fn prompt_open(open: bool) {
        if open {
            REGISTER.call_once(register);
        }
        PROMPT_OPEN.store(open, Ordering::SeqCst);
    }

    fn register() {
        // SAFETY: a zeroed sigaction is a valid out-parameter; a null new
        // action only reads the current one.
        let ignored = unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGINT, std::ptr::null(), &mut current) == 0
                && current.sa_sigaction == libc::SIG_IGN
        };
        STARTED_IGNORED.store(ignored, Ordering::SeqCst);
        // SAFETY: the action only loads two atomics and calls
        // `emulate_default_handler`, all async-signal-safe.
        let registered = unsafe {
            signal_hook::low_level::register(libc::SIGINT, || {
                if terminates(PROMPT_OPEN.load(Ordering::SeqCst), STARTED_IGNORED.load(Ordering::SeqCst)) {
                    let _ = signal_hook::low_level::emulate_default_handler(libc::SIGINT);
                }
            })
        };
        if let Err(e) = registered {
            super::note("", format_args!("Ctrl-C may not stop this run outside a prompt ({e})"));
        }
    }
}

fn paint<D>(brand: Brand, text: D, stderr: bool) -> StyledObject<D> {
    let style = brand.style(depth(stderr));
    let style = if stderr { style.for_stderr() } else { style };
    style.apply_to(text)
}

/// `✓` in the success colour (stdout).
pub fn check() -> StyledObject<&'static str> {
    paint(SUCCESS, "✓", false)
}

/// A path, URL or command in the accent colour (stdout).
pub fn accent<D>(text: D) -> StyledObject<D> {
    paint(ACCENT, text, false)
}

/// Secondary text: hints, labels (stdout).
pub fn muted<D>(text: D) -> StyledObject<D> {
    paint(MUTED, text, false)
}

// The lines below print themselves, so each mark is coloured for the stream
// it lands on: a mark styled for one stream and printed on the other would
// leak escapes into a pipe. `indent` is the leading spaces of a line nested
// under a client's block.

/// One marked line, coloured for the stream it is printed on.
fn mark_line(stderr: bool, brand: Brand, mark: &str, label: &str, indent: &str, msg: impl std::fmt::Display) {
    let mark = paint(brand, mark, stderr);
    if stderr {
        eprintln!("{indent}{mark} {label}{msg}");
    } else {
        println!("{indent}{mark} {label}{msg}");
    }
}

/// `! warning: …` on stderr.
pub fn warn(indent: &str, msg: impl std::fmt::Display) {
    mark_line(true, WARNING, "!", "warning: ", indent, msg);
}

/// `! warning: …` on stdout, beside the output it qualifies.
pub fn warn_out(indent: &str, msg: impl std::fmt::Display) {
    mark_line(false, WARNING, "!", "warning: ", indent, msg);
}

/// `! note: …` on stderr.
pub fn note(indent: &str, msg: impl std::fmt::Display) {
    mark_line(true, WARNING, "!", "note: ", indent, msg);
}

/// `! …` on stderr — a passing condition, not a warning (the device-login
/// poll riding out an unreachable gateway).
pub fn notice(indent: &str, msg: impl std::fmt::Display) {
    mark_line(true, WARNING, "!", "", indent, msg);
}

/// `✗ error: …` on stderr for a failure that does not end the run.
pub fn error(indent: &str, msg: impl std::fmt::Display) {
    mark_line(true, ERROR, "✗", "error: ", indent, msg);
}

/// The `✗ error:` lead of the fatal error `main` prints (stderr).
pub fn error_mark() -> StyledObject<&'static str> {
    paint(ERROR, "✗ error:", true)
}

#[cfg(test)]
mod tests {
    use super::styled_prompts_for;

    #[test]
    fn styled_only_with_both_terminals_and_nothing_opting_out() {
        assert!(styled_prompts_for(true, true, Some("xterm-256color"), None));
        assert!(styled_prompts_for(true, true, None, None));
        // A pipe on either side: the plain line prompts (scripted answers).
        assert!(!styled_prompts_for(false, true, Some("xterm"), None));
        assert!(!styled_prompts_for(true, false, Some("xterm"), None));
        assert!(!styled_prompts_for(true, true, Some("dumb"), None));
    }

    #[cfg(unix)]
    #[test]
    fn sigint_ends_the_run_only_outside_a_prompt_and_only_if_it_did_before() {
        use super::sigint::terminates;
        assert!(terminates(false, false));
        assert!(!terminates(true, false));
        assert!(!terminates(false, true));
        assert!(!terminates(true, true));
    }

    /// Ctrl-C at the SECOND and later prompts is still a cancel: each prompt
    /// below registers and drops a SIGINT action exactly as `demand` does, and
    /// raises SIGINT inside the prompt as `console` does on a ^C byte. Were
    /// the registry's OS handler gone (SIGINT back at its default), the raise
    /// would kill this test binary.
    #[cfg(unix)]
    #[test]
    fn ctrl_c_is_caught_at_every_prompt_not_only_the_first() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        for round in 1..=3 {
            super::prompt(|| {
                // SAFETY: the action only bumps an atomic.
                let id = unsafe {
                    signal_hook::low_level::register(libc::SIGINT, || {
                        SEEN.fetch_add(1, Ordering::SeqCst);
                    })
                }?;
                // SAFETY: raising a signal whose handler is installed above.
                unsafe { libc::raise(libc::SIGINT) };
                signal_hook::low_level::unregister(id);
                Ok(())
            })
            .expect("the prompt answers");
            assert_eq!(SEEN.load(Ordering::SeqCst), round, "round {round}: the prompt's own action ran");
        }
    }

    #[test]
    fn a_cancelled_prompt_is_a_typed_cancel_and_other_failures_are_not() {
        let cancel = super::aborted(std::io::Error::new(std::io::ErrorKind::Interrupted, "user cancelled"));
        assert!(cancel.downcast_ref::<crate::Cancelled>().is_some());
        let broken = super::aborted(std::io::Error::other("tty gone"));
        assert!(broken.downcast_ref::<crate::Cancelled>().is_none());
    }

    #[test]
    fn colour_depth_steps_down_to_what_the_terminal_names() {
        use super::{Depth, depth_for};
        let named = |truecolor, term| match depth_for(truecolor, term) {
            Depth::True => "truecolor",
            Depth::Ansi256 => "256",
            Depth::Basic => "basic",
        };
        assert_eq!(named(true, Some("xterm")), "truecolor");
        assert_eq!(named(true, None), "truecolor");
        assert_eq!(named(false, Some("xterm-256color")), "256");
        assert_eq!(named(false, Some("tmux-256color")), "256");
        assert_eq!(named(false, Some("xterm-kitty")), "256");
        assert_eq!(named(false, Some("alacritty")), "256");
        assert_eq!(named(false, Some("xterm")), "basic");
        assert_eq!(named(false, Some("linux")), "basic");
        assert_eq!(named(false, None), "basic");
    }

    /// The child half of `sigint_outside_a_prompt_still_ends_the_run`: a no-op
    /// unless that test re-runs this binary with `SIGINT_CHILD` set. It runs
    /// one prompt the way `demand` does, then raises SIGINT inside or outside
    /// a second one, and exits 0 only if it survived.
    #[cfg(unix)]
    #[test]
    fn sigint_child() {
        let Ok(mode) = std::env::var("SIGINT_CHILD") else { return };
        let demand_like = |raise: bool| {
            super::prompt(|| {
                // SAFETY: the action does nothing.
                let id = unsafe { signal_hook::low_level::register(libc::SIGINT, || {}) }?;
                if raise {
                    // SAFETY: raising a signal whose handler is installed.
                    unsafe { libc::raise(libc::SIGINT) };
                }
                signal_hook::low_level::unregister(id);
                Ok(())
            })
        };
        demand_like(false).expect("the first prompt answers");
        match mode.as_str() {
            "outside" => {
                // SAFETY: raising SIGINT; the registry's handler is installed.
                unsafe { libc::raise(libc::SIGINT) };
            }
            _ => demand_like(true).expect("the second prompt answers"),
        }
        std::process::exit(0);
    }

    #[cfg(unix)]
    #[test]
    fn sigint_outside_a_prompt_still_ends_the_run() {
        use std::os::unix::process::ExitStatusExt;
        let run = |mode: &str| {
            std::process::Command::new(std::env::current_exe().expect("test binary path"))
                .args(["--exact", "ui::tests::sigint_child", "--test-threads=1", "--nocapture"])
                .env("SIGINT_CHILD", mode)
                .output()
                .expect("the child runs")
                .status
        };
        // After a prompt, SIGINT outside one ends the process, as by default.
        let outside = run("outside");
        assert_eq!(outside.signal(), Some(libc::SIGINT), "{outside:?}");
        // Positive control: the same SIGINT inside a prompt is that prompt's
        // cancel, and the process lives on.
        let inside = run("inside");
        assert_eq!(inside.code(), Some(0), "{inside:?}");
    }

    #[test]
    fn plain_env_opts_out_unless_empty_or_zero() {
        assert!(!styled_prompts_for(true, true, Some("xterm"), Some("1")));
        assert!(!styled_prompts_for(true, true, Some("xterm"), Some("yes")));
        assert!(styled_prompts_for(true, true, Some("xterm"), Some("")));
        assert!(styled_prompts_for(true, true, Some("xterm"), Some("0")));
    }
}
