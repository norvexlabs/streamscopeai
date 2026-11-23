//! Feedback for a long step — a walk of tens of thousands of files must never
//! look hung. On a terminal one line on stderr is rewritten in place (at most
//! every 100 ms) with the step and a count; elsewhere (a script, a log) a plain
//! line every 5 s; then a summary line that stays. A write that fails is
//! ignored: a closed stderr never stops the work it reports on.
//!
//! The state sits behind a `RefCell`, so the code doing the work holds a
//! shared `&Progress` (an access-list walk's callback among them).
#![cfg_attr(not(windows), allow(dead_code, reason = "its walks are the Windows sandbox's; tested on every host"))]

use std::cell::RefCell;
use std::io::Write;
use std::time::{Duration, Instant};

/// How often a terminal line is redrawn.
const TERMINAL_EVERY: Duration = Duration::from_millis(100);
/// How often a plain line is printed off a terminal.
const PLAIN_EVERY: Duration = Duration::from_secs(5);

pub struct Progress {
    state: RefCell<State>,
}

struct State {
    out: Option<Box<dyn Write>>,
    terminal: bool,
    label: String,
    count: u64,
    total: Option<u64>,
    started: Instant,
    shown: Option<Instant>,
    /// A terminal line is on screen and must be cleared before other output.
    drawn: bool,
}

impl Progress {
    /// Reporting on stderr, in place when it is a terminal.
    pub fn stderr() -> Self {
        use std::io::IsTerminal as _;
        let terminal = std::io::stderr().is_terminal();
        Self::to(Box::new(std::io::stderr()), terminal)
    }

    /// Reporting nothing (a test).
    #[cfg(test)]
    pub fn silent() -> Self {
        Self::new(None, false)
    }

    fn to(out: Box<dyn Write>, terminal: bool) -> Self {
        Self::new(Some(out), terminal)
    }

    fn new(out: Option<Box<dyn Write>>, terminal: bool) -> Self {
        Self {
            state: RefCell::new(State {
                out,
                terminal,
                label: String::new(),
                count: 0,
                total: None,
                started: Instant::now(),
                shown: None,
                drawn: false,
            }),
        }
    }

    /// Start a step: what it does and, when known, how many items it covers.
    /// The count starts again from zero.
    pub fn phase(&self, label: impl Into<String>, total: Option<u64>) {
        let mut s = self.state.borrow_mut();
        s.label = label.into();
        s.total = total;
        s.count = 0;
        s.started = Instant::now();
        s.shown = None;
        Self::draw(&mut s, false);
    }

    /// One more item done.
    pub fn tick(&self) {
        let mut s = self.state.borrow_mut();
        s.count += 1;
        Self::draw(&mut s, false);
    }

    /// The items done in the current step.
    pub fn count(&self) -> u64 {
        self.state.borrow().count
    }

    /// End the step: the in-place line is cleared and `summary` printed, with
    /// how long the step took when it took a second or more.
    pub fn finish(&self, summary: impl std::fmt::Display) {
        let mut s = self.state.borrow_mut();
        let took = s.started.elapsed();
        Self::clear(&mut s);
        let line = if took >= Duration::from_secs(1) {
            format!("{summary} in {} s\n", took.as_secs())
        } else {
            format!("{summary}\n")
        };
        if let Some(out) = s.out.as_mut() {
            let _ = out.write_all(line.as_bytes());
            let _ = out.flush();
        }
    }

    /// Clear the in-place line so other output (a warning, a question) reads
    /// cleanly; the next tick draws it again.
    pub fn pause(&self) {
        Self::clear(&mut self.state.borrow_mut());
    }

    fn clear(s: &mut State) {
        if s.drawn {
            if let Some(out) = s.out.as_mut() {
                let _ = out.write_all(b"\r\x1b[2K");
                let _ = out.flush();
            }
            s.drawn = false;
        }
    }

    fn draw(s: &mut State, force: bool) {
        if s.out.is_none() || s.label.is_empty() {
            return;
        }
        let now = Instant::now();
        let due = match (s.terminal, s.shown) {
            (true, None) => true,
            (true, Some(at)) => now.duration_since(at) >= TERMINAL_EVERY,
            (false, None) => now.duration_since(s.started) >= PLAIN_EVERY,
            (false, Some(at)) => now.duration_since(at) >= PLAIN_EVERY,
        };
        if !(due || force) {
            return;
        }
        let text = line(&s.label, s.count, s.total);
        let bytes = if s.terminal { format!("\r\x1b[2K{text}") } else { format!("{text}\n") };
        if let Some(out) = s.out.as_mut() {
            let _ = out.write_all(bytes.as_bytes());
            let _ = out.flush();
        }
        s.shown = Some(now);
        s.drawn = s.terminal;
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        Self::clear(self.state.get_mut());
    }
}

/// `Checking C:\x … 12,408 items`, or `… 3,120 / 18,756` with a total.
fn line(label: &str, count: u64, total: Option<u64>) -> String {
    match total {
        Some(total) => format!("{label} … {} / {}", grouped(count), grouped(total)),
        None => format!("{label} … {} items", grouped(count)),
    }
}

/// `18756` → `18,756`.
pub fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    /// A writer whose bytes the test reads back.
    #[derive(Clone, Default)]
    struct Sink(Rc<RefCell<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Sink {
        fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).unwrap()
        }
    }

    #[test]
    fn counts_are_grouped_by_thousands() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1000), "1,000");
        assert_eq!(grouped(18_756), "18,756");
        assert_eq!(grouped(1_234_567), "1,234,567");
        assert_eq!(line("Checking", 12_408, None), "Checking … 12,408 items");
        assert_eq!(line("Fixing", 3_120, Some(18_756)), "Fixing … 3,120 / 18,756");
    }

    #[test]
    fn a_terminal_line_is_drawn_at_once_redrawn_at_most_every_tick_and_cleared_for_the_summary() {
        let sink = Sink::default();
        let p = Progress::to(Box::new(sink.clone()), true);
        p.phase("Checking", None);
        // Drawn at once, in place.
        assert_eq!(sink.text(), "\r\x1b[2KChecking … 0 items");
        // An immediate tick is within the redraw interval: not drawn again.
        p.tick();
        assert_eq!(sink.text(), "\r\x1b[2KChecking … 0 items");
        std::thread::sleep(TERMINAL_EVERY + Duration::from_millis(20));
        p.tick();
        assert!(sink.text().ends_with("\r\x1b[2KChecking … 2 items"), "{:?}", sink.text());
        p.finish("✓ 2 items checked");
        assert!(sink.text().ends_with("\r\x1b[2K✓ 2 items checked\n"), "{:?}", sink.text());
    }

    #[test]
    fn off_a_terminal_lines_are_plain_and_spaced_and_the_summary_stays() {
        let sink = Sink::default();
        let p = Progress::to(Box::new(sink.clone()), false);
        p.phase("Checking", Some(3));
        p.tick();
        p.tick();
        // Within the first interval nothing is printed, and nothing in place.
        assert_eq!(sink.text(), "");
        p.finish("✓ done");
        assert_eq!(sink.text(), "✓ done\n");
        assert!(!sink.text().contains('\r'));
    }

    #[test]
    fn a_silent_progress_writes_nothing_and_still_counts() {
        let p = Progress::silent();
        p.phase("Checking", None);
        p.tick();
        assert_eq!(p.count(), 1);
        p.finish("done");
    }
}
