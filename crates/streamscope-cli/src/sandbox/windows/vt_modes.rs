//! The terminal state a client's screen leaves behind. A console-mode run
//! copies the client's screen to the developer's terminal byte for byte, so
//! every mode the client switches on (mouse tracking, bracketed paste, the
//! alternate screen, a keyboard protocol) is switched on in the developer's
//! terminal — and stays on when the client ends without switching it off.
//! [`Modes`] reads the stream as the terminal does and, at the end, writes
//! the inverse of exactly what is still on: a client that cleaned up after
//! itself costs nothing, and a mode the stream never touched is never
//! written, so the developer's own terminal state (their shell's keyboard
//! protocol, the outer console's input mode) is left as it was. A mode the
//! stream did touch is put back to its default, as the client's own exit
//! would: the pseudo-console's win32 input and focus modes are switched off
//! as its own shutdown switches them off.
//!
//! What is tracked: the DEC private modes in [`TRACKED`], the kitty
//! keyboard-protocol stack (per screen, as the protocol keeps one per
//! screen), xterm's modifyOtherKeys, the keypad mode, the scroll region,
//! the cursor style and the text attributes. A full reset
//! (`ESC c`) puts every one back to its default. Sequences are read across
//! chunk boundaries; a sequence longer than [`MAX_PARAMS`] parameter bytes
//! is read to its end and ignored.

use std::collections::BTreeMap;

/// The DEC private modes followed, each with its power-on default (`true`:
/// set). Keep [`RESTORE_ORDER`] listing every one.
pub const TRACKED: &[(u16, bool)] = &[
    (1, false),     // application cursor keys
    (5, false),     // reverse video
    (7, true),      // autowrap
    (9, false),     // X10 mouse
    (25, true),     // cursor visible
    (47, false),    // alternate screen
    (1000, false),  // mouse: buttons
    (1002, false),  // mouse: buttons + drag
    (1003, false),  // mouse: any motion
    (1004, false),  // focus events
    (1005, false),  // mouse: UTF-8 coordinates
    (1006, false),  // mouse: SGR coordinates
    (1015, false),  // mouse: urxvt coordinates
    (1016, false),  // mouse: SGR pixel coordinates
    (1047, false),  // alternate screen
    (1049, false),  // alternate screen, cursor saved
    (2004, false),  // bracketed paste
    (2026, false),  // synchronized output
    (9001, false),  // win32 input mode
];

/// The order modes are put back in: synchronized output first (or nothing
/// after it shows), the inputs next, the alternate screen before the
/// cursor (leaving it restores a saved cursor), win32 input mode last.
const RESTORE_ORDER: &[u16] = &[2026, 9, 1000, 1002, 1003, 1005, 1006, 1015, 1016, 2004, 1004, 1, 1049, 1047, 47, 5, 7, 25, 9001];

const ALT_SCREENS: [u16; 3] = [1049, 1047, 47];

/// The longest parameter string read; a longer sequence is ignored.
pub const MAX_PARAMS: usize = 64;

/// The kitty stack depth followed per screen; pushes past it are not
/// counted (a terminal's own stack is bounded too).
const MAX_DEPTH: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Ground,
    Escape,
    Csi,
}

/// The modes a stream left on; see the module documentation.
#[derive(Debug)]
pub struct Modes {
    state: State,
    params: Vec<u8>,
    overflow: bool,
    /// A tracked mode's value, present only once the stream set or reset it.
    set: BTreeMap<u16, bool>,
    kitty_main: u32,
    kitty_alt: u32,
    modify_other_keys: bool,
    keypad: bool,
    scroll_region: bool,
    cursor_style: bool,
    attributes: bool,
}

impl Default for Modes {
    fn default() -> Self {
        Modes {
            state: State::Ground,
            params: Vec::with_capacity(MAX_PARAMS),
            overflow: false,
            set: BTreeMap::new(),
            kitty_main: 0,
            kitty_alt: 0,
            modify_other_keys: false,
            keypad: false,
            scroll_region: false,
            cursor_style: false,
            attributes: false,
        }
    }
}

impl Modes {
    /// Read the next piece of the stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.step(b);
        }
    }

    fn step(&mut self, b: u8) {
        match self.state {
            State::Ground => {
                if b == 0x1b {
                    self.state = State::Escape;
                }
            }
            State::Escape => match b {
                b'[' => {
                    self.params.clear();
                    self.overflow = false;
                    self.state = State::Csi;
                }
                b'c' => {
                    self.full_reset();
                    self.state = State::Ground;
                }
                // Application and normal keypad.
                b'=' | b'>' => {
                    self.keypad = b == b'=';
                    self.state = State::Ground;
                }
                0x1b => {}
                _ => self.state = State::Ground,
            },
            State::Csi => match b {
                // Parameter and intermediate bytes.
                0x20..=0x3f => {
                    if self.params.len() < MAX_PARAMS {
                        self.params.push(b);
                    } else {
                        self.overflow = true;
                    }
                }
                // The final byte.
                0x40..=0x7e => {
                    if !self.overflow {
                        self.dispatch(b);
                    }
                    self.state = State::Ground;
                }
                // An escape abandons the sequence and starts another.
                0x1b => self.state = State::Escape,
                // Other controls are executed inside a sequence, not part of it.
                _ => {}
            },
        }
    }

    fn full_reset(&mut self) {
        *self = Modes::default();
    }

    fn in_alt_screen(&self) -> bool {
        ALT_SCREENS.iter().any(|m| self.set.get(m) == Some(&true))
    }

    fn dispatch(&mut self, final_byte: u8) {
        let params = std::mem::take(&mut self.params);
        match (params.first(), final_byte) {
            (Some(b'?'), b'h' | b'l') => {
                let on = final_byte == b'h';
                for n in numbers(&params[1..]) {
                    if ALT_SCREENS.contains(&n) && !on {
                        // One alternate screen, whichever mode left it.
                        for m in ALT_SCREENS {
                            self.set.insert(m, false);
                        }
                    } else if TRACKED.iter().any(|(m, _)| *m == n) {
                        self.set.insert(n, on);
                    }
                }
            }
            (Some(b'>'), b'u') => {
                let depth = self.kitty_depth();
                *depth = (*depth + 1).min(MAX_DEPTH);
            }
            (Some(b'<'), b'u') => {
                let n = numbers(&params[1..]).next().filter(|n| *n > 0).unwrap_or(1);
                let depth = self.kitty_depth();
                *depth = depth.saturating_sub(u32::from(n));
            }
            // modifyOtherKeys: `CSI > 4 ; n m`, off at 0 or with no level.
            (Some(b'>'), b'm') => {
                let mut values = numbers(&params[1..]);
                if values.next() == Some(4) {
                    self.modify_other_keys = values.next().is_some_and(|level| level > 0);
                }
            }
            // The scroll region (`CSI top ; bottom r`), the whole screen
            // when given none.
            (None | Some(b'0'..=b'9' | b';'), b'r') => {
                self.scroll_region = !params.is_empty();
            }
            (_, b'q') if params.last() == Some(&b' ') => {
                self.cursor_style = !is_default(&params[..params.len() - 1]);
            }
            (_, b'm') if params.first().is_none_or(|b| b.is_ascii_digit() || *b == b';') => {
                self.attributes = !is_default(&params);
            }
            _ => {}
        }
        self.params = params;
        self.params.clear();
    }

    fn kitty_depth(&mut self) -> &mut u32 {
        if self.in_alt_screen() { &mut self.kitty_alt } else { &mut self.kitty_main }
    }

    /// The bytes that switch off what the stream left on, in
    /// [`RESTORE_ORDER`]; empty when it left nothing.
    pub fn restore(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let off = |mode: u16| -> Option<bool> {
            let default = TRACKED.iter().find(|(m, _)| *m == mode).map(|(_, d)| *d)?;
            self.set.get(&mode).copied().filter(|now| *now != default).map(|_| default)
        };
        let put = |mode: u16, out: &mut Vec<u8>| {
            if let Some(default) = off(mode) {
                out.extend_from_slice(format!("\x1b[?{mode}{}", if default { 'h' } else { 'l' }).as_bytes());
            }
        };
        let pop = |depth: u32, out: &mut Vec<u8>| {
            if depth > 0 {
                out.extend_from_slice(format!("\x1b[<{depth}u").as_bytes());
            }
        };
        for &mode in RESTORE_ORDER {
            if mode == 1049 {
                // The alternate screen's keyboard stack is popped while on
                // it, the main screen's once back.
                if self.in_alt_screen() {
                    pop(self.kitty_alt, &mut out);
                }
            }
            put(mode, &mut out);
            if mode == 47 {
                pop(self.kitty_main, &mut out);
            }
        }
        if self.modify_other_keys {
            out.extend_from_slice(b"\x1b[>4m");
        }
        if self.keypad {
            out.extend_from_slice(b"\x1b>");
        }
        if self.scroll_region {
            out.extend_from_slice(b"\x1b[r");
        }
        if self.cursor_style {
            out.extend_from_slice(b"\x1b[0 q");
        }
        if self.attributes {
            out.extend_from_slice(b"\x1b[0m");
        }
        out
    }
}

/// The numbers of a `;`-separated parameter string; an empty or malformed
/// field is skipped.
fn numbers(params: &[u8]) -> impl Iterator<Item = u16> + '_ {
    params.split(|b| *b == b';').filter_map(|f| std::str::from_utf8(f).ok()?.parse().ok())
}

/// Whether a parameter string selects the default: empty, or zeros only.
fn is_default(params: &[u8]) -> bool {
    params.iter().all(|b| *b == b'0' || *b == b';')
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn after(stream: &[u8]) -> Vec<u8> {
        let mut m = Modes::default();
        m.feed(stream);
        m.restore()
    }

    fn text(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn a_stream_that_cleans_up_after_itself_needs_nothing() {
        assert_eq!(after(b"\x1b[?1000h\x1b[?1006h\x1b[?2004hhello\x1b[?2004l\x1b[?1006l\x1b[?1000l"), b"");
        assert_eq!(after(b"plain text, no sequence"), b"");
    }

    #[test]
    fn what_is_left_on_is_switched_off() {
        // Positive control for the test above: the same modes, left on.
        assert_eq!(text(after(b"\x1b[?1000h\x1b[?1006h\x1b[?2004h")), "\x1b[?1000l\x1b[?1006l\x1b[?2004l");
    }

    #[test]
    fn several_modes_in_one_sequence_are_each_followed() {
        assert_eq!(text(after(b"\x1b[?1000;1002;1006h\x1b[?1002l")), "\x1b[?1000l\x1b[?1006l");
    }

    #[test]
    fn a_mode_on_by_default_is_switched_back_on() {
        assert_eq!(text(after(b"\x1b[?25l\x1b[?7l")), "\x1b[?7h\x1b[?25h");
        assert_eq!(after(b"\x1b[?25l\x1b[?25h"), b"");
    }

    #[test]
    fn a_mode_never_touched_is_never_written() {
        // The win32 input mode and focus belong to the console the run is
        // in: written only to undo what the stream did.
        assert_eq!(after(b"\x1b[?9001l\x1b[?1004l"), b"");
        assert_eq!(text(after(b"\x1b[?1004h\x1b[?9001h")), "\x1b[?1004l\x1b[?9001l");
        // An untracked mode, and an ANSI (non-private) one.
        assert_eq!(after(b"\x1b[?12h\x1b[4h"), b"");
    }

    #[test]
    fn the_alternate_screen_is_left_by_whichever_mode_leaves_it() {
        assert_eq!(after(b"\x1b[?1049h\x1b[?1047l"), b"");
        assert_eq!(after(b"\x1b[?47h\x1b[?1049l"), b"");
        // Back on the main screen, a push is the main screen's.
        assert_eq!(text(after(b"\x1b[?1049h\x1b[?47l\x1b[>1u")), "\x1b[<1u");
    }

    #[test]
    fn synchronized_output_ends_first_and_win32_input_last() {
        let out = text(after(b"\x1b[?9001h\x1b[?1049h\x1b[?2026h\x1b[?25l"));
        assert_eq!(out, "\x1b[?2026l\x1b[?1049l\x1b[?25h\x1b[?9001l");
    }

    #[test]
    fn a_sequence_cut_between_two_pieces_is_read_whole() {
        let mut m = Modes::default();
        for piece in [&b"abc\x1b"[..], b"[?10", b"00", b";2004", b"h tail"] {
            m.feed(piece);
        }
        assert_eq!(text(m.restore()), "\x1b[?1000l\x1b[?2004l");
    }

    #[test]
    fn the_keyboard_stack_is_popped_on_the_screen_it_was_pushed_on() {
        assert_eq!(text(after(b"\x1b[>1u\x1b[>3u")), "\x1b[<2u");
        assert_eq!(after(b"\x1b[>1u\x1b[<u"), b"");
        assert_eq!(after(b"\x1b[>1u\x1b[>1u\x1b[<2u"), b"");
        // More pops than pushes pop nothing of the developer's.
        assert_eq!(after(b"\x1b[<5u"), b"");
        // Pushed on the alternate screen: popped there, before leaving it;
        // the main screen's after.
        let out = text(after(b"\x1b[>1u\x1b[?1049h\x1b[>1u\x1b[>1u"));
        assert_eq!(out, "\x1b[<2u\x1b[?1049l\x1b[<1u");
    }

    #[test]
    fn cursor_style_and_attributes_are_reset_only_when_changed() {
        assert_eq!(text(after(b"\x1b[5 q\x1b[1;31m")), "\x1b[0 q\x1b[0m");
        assert_eq!(after(b"\x1b[5 q\x1b[0 q\x1b[1;31m\x1b[m"), b"");
        // A private `m` is not an attribute.
        assert_eq!(after(b"\x1b[>1;2m"), b"");
    }

    #[test]
    fn keyboard_modes_and_the_scroll_region_are_put_back() {
        assert_eq!(text(after(b"\x1b[>4;2m\x1b=\x1b[2;20r")), "\x1b[>4m\x1b>\x1b[r");
        // Each switched back by the stream: nothing.
        assert_eq!(after(b"\x1b[>4;2m\x1b[>4;0m\x1b=\x1b>\x1b[2;20r\x1b[r"), b"");
        assert_eq!(after(b"\x1b[>4;1m\x1b[>4m"), b"");
        // Another resource's level is not modifyOtherKeys.
        assert_eq!(after(b"\x1b[>1;2m"), b"");
    }

    #[test]
    fn every_tracked_mode_left_on_is_put_back_in_the_restore_order() {
        let mut order: Vec<u16> = RESTORE_ORDER.to_vec();
        let mut tracked: Vec<u16> = TRACKED.iter().map(|(m, _)| *m).collect();
        order.sort_unstable();
        tracked.sort_unstable();
        assert_eq!(order, tracked, "RESTORE_ORDER must list every tracked mode once");
        for &(mode, default) in TRACKED {
            let (away, back) = if default { ('l', 'h') } else { ('h', 'l') };
            let out = text(after(format!("\x1b[?{mode}{away}").as_bytes()));
            assert_eq!(out, format!("\x1b[?{mode}{back}"), "mode {mode}");
        }
    }

    #[test]
    fn the_parameter_cap_reads_a_sequence_up_to_it_and_ignores_one_past_it() {
        // `?`, zeros (mode 0, untracked), then `;1000`: exactly the cap, then one past it.
        let sequence = |zeros: usize| {
            let mut s = b"\x1b[?".to_vec();
            s.extend(std::iter::repeat_n(b'0', zeros));
            s.extend_from_slice(b";1000h");
            s
        };
        let at_cap = MAX_PARAMS - "?;1000".len();
        assert_eq!(text(after(&sequence(at_cap))), "\x1b[?1000l");
        assert_eq!(after(&sequence(at_cap + 1)), b"");
    }

    #[test]
    fn the_keyboard_stack_is_followed_up_to_its_depth() {
        let pushes = |n: u32| b"\x1b[>1u".repeat(n as usize);
        assert_eq!(text(after(&pushes(MAX_DEPTH))), format!("\x1b[<{MAX_DEPTH}u"));
        assert_eq!(text(after(&pushes(MAX_DEPTH + 1))), format!("\x1b[<{MAX_DEPTH}u"));
        assert_eq!(text(after(&pushes(MAX_DEPTH - 1))), format!("\x1b[<{}u", MAX_DEPTH - 1));
    }

    #[test]
    fn a_full_reset_forgets_everything() {
        assert_eq!(after(b"\x1b[?1000h\x1b[>1u\x1b[?25l\x1bc"), b"");
        assert_eq!(text(after(b"\x1bc\x1b[?2004h")), "\x1b[?2004l");
    }

    #[test]
    fn an_overlong_or_abandoned_sequence_is_ignored() {
        let mut long = b"\x1b[?".to_vec();
        long.extend(std::iter::repeat_n(b'1', MAX_PARAMS + 1));
        long.extend_from_slice(b";1000h");
        assert_eq!(after(&long), b"");
        // An escape inside a sequence starts the next one.
        assert_eq!(text(after(b"\x1b[?10\x1b[?2004h")), "\x1b[?2004l");
    }

    proptest! {
        /// However the stream is cut into pieces, what is left on is the same.
        #[test]
        fn cutting_the_stream_never_changes_the_result(
            stream in proptest::collection::vec(prop_oneof![
                Just(b"\x1b[?1000h".to_vec()), Just(b"\x1b[?1049h".to_vec()), Just(b"\x1b[?25l".to_vec()),
                Just(b"\x1b[>1u".to_vec()), Just(b"\x1b[<u".to_vec()), Just(b"\x1b[?2004;1006h".to_vec()),
                Just(b"\x1b[?1049l".to_vec()), Just(b"\x1b[1m".to_vec()), Just(b"\x1bc".to_vec()),
                proptest::collection::vec(any::<u8>(), 0..8),
            ], 0..24).prop_map(|v| v.concat()),
            cuts in proptest::collection::vec(any::<usize>(), 0..8),
        ) {
            let whole = after(&stream);
            let mut points: Vec<usize> = cuts.iter().map(|c| c % (stream.len() + 1)).collect();
            points.sort_unstable();
            let mut m = Modes::default();
            let mut at = 0;
            for p in points {
                m.feed(&stream[at..p]);
                at = p;
            }
            m.feed(&stream[at..]);
            prop_assert_eq!(m.restore(), whole);
        }

        /// What the restore writes leaves every followed mode at its
        /// default: read after the stream, it needs no restore of its own.
        #[test]
        fn the_restore_leaves_nothing_on(
            stream in proptest::collection::vec(prop_oneof![
                Just(b"\x1b[?1000h".to_vec()), Just(b"\x1b[?1049h".to_vec()), Just(b"\x1b[?47h".to_vec()),
                Just(b"\x1b[?25l".to_vec()), Just(b"\x1b[?7l".to_vec()), Just(b"\x1b[>1u".to_vec()),
                Just(b"\x1b[<u".to_vec()), Just(b"\x1b[?9001h".to_vec()), Just(b"\x1b[?2026h".to_vec()),
                Just(b"\x1b[3 q".to_vec()), Just(b"\x1b[31m".to_vec()), Just(b"\x1b[?1049l".to_vec()),
                Just(b"\x1b=".to_vec()), Just(b"\x1b[2;20r".to_vec()), Just(b"\x1b[>4;2m".to_vec()), Just(b"\x1b[?5h".to_vec()),
                proptest::collection::vec(any::<u8>(), 0..8),
            ], 0..24).prop_map(|v| v.concat()),
        ) {
            let mut m = Modes::default();
            m.feed(&stream);
            let reset = m.restore();
            m.feed(&reset);
            prop_assert_eq!(m.restore(), Vec::<u8>::new());
        }
    }
}
