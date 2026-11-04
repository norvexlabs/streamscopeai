//! The pure half of the Windows launcher ([`super::launch`]): the
//! environment the sandbox host starts with, its encoding, and the two
//! streaming text decoders the relays use. Pure, so it is tested on every
//! host.

use std::io;

/// The developer's terminal variables a run carries, each when set: what a
/// TUI reads to choose its colours and keys.
pub const TERMINAL_VARS: [&str; 9] =
    ["TERM", "COLORTERM", "TERM_PROGRAM", "WT_SESSION", "WT_PROFILE_ID", "LANG", "LC_ALL", "NO_COLOR", "FORCE_COLOR"];

/// The host's environment: the account's own `defaults`, then the
/// developer's `PATH` and `PATHEXT` and terminal variables (each read from
/// `developer` when set), then `given`. A later value wins; names compare
/// without case. Nothing else of the developer's is read.
pub fn environment(
    defaults: Vec<(String, String)>,
    developer: &dyn Fn(&str) -> Option<String>,
    given: &[(String, String)],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(defaults.len() + given.len() + 11);
    let mut set = |name: String, value: String| match out.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(&name)) {
        Some(slot) => *slot = (name, value),
        None => out.push((name, value)),
    };
    for (k, v) in defaults {
        set(k, v);
    }
    for name in ["PATH", "PATHEXT"].into_iter().chain(TERMINAL_VARS) {
        if let Some(v) = developer(name) {
            set(name.to_string(), v);
        }
    }
    for (k, v) in given {
        set(k.clone(), v.clone());
    }
    out
}

/// `vars` as a Unicode environment block: `name=value` entries, sorted by
/// name without case as Windows keeps them, each NUL-terminated, then a
/// final NUL. A name that is empty or holds `=`, or a NUL anywhere, cannot
/// be carried: refused, naming the variable.
pub fn block(vars: &[(String, String)]) -> io::Result<Vec<u16>> {
    let mut sorted: Vec<&(String, String)> = vars.iter().collect();
    sorted.sort_by_key(|(k, _)| k.to_uppercase());
    let mut out = Vec::new();
    for (k, v) in sorted {
        if k.is_empty() || k.contains(['=', '\0']) || v.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the environment variable {k:?} cannot be passed to the sandbox (an empty name, `=` in its name, or a NUL)"),
            ));
        }
        out.extend(k.encode_utf16());
        out.push(u16::from(b'='));
        out.extend(v.encode_utf16());
        out.push(0);
    }
    if out.is_empty() {
        out.push(0);
    }
    out.push(0);
    Ok(out)
}

/// The variables `cmd /u /c set` printed: one `name=value` per line. A line
/// without `=`, or with an empty name, is not a variable.
pub fn parse_set(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(k, _)| !k.is_empty())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// UTF-16 read in pieces (console input), to UTF-8: a high surrogate that
/// ends one piece is held for the next; an unpaired one becomes U+FFFD.
#[derive(Default)]
pub struct Utf16Stream {
    pending: Option<u16>,
}

impl Utf16Stream {
    pub fn push(&mut self, units: &[u16]) -> String {
        let mut all: Vec<u16> = self.pending.take().into_iter().chain(units.iter().copied()).collect();
        if let Some(&last) = all.last()
            && (0xD800..0xDC00).contains(&last)
        {
            self.pending = all.pop();
        }
        String::from_utf16_lossy(&all)
    }
}

/// UTF-8 read in pieces (a pipe), to text: a sequence cut at the end of one
/// piece is held for the next; invalid bytes become U+FFFD.
#[derive(Default)]
pub struct Utf8Stream {
    carry: Vec<u8>,
}

impl Utf8Stream {
    pub fn push(&mut self, bytes: &[u8]) -> String {
        let mut all = std::mem::take(&mut self.carry);
        all.extend_from_slice(bytes);
        let mut out = String::with_capacity(all.len());
        let mut rest: &[u8] = &all;
        loop {
            match std::str::from_utf8(rest) {
                Ok(s) => {
                    out.push_str(s);
                    break;
                }
                Err(e) => {
                    let (good, bad) = rest.split_at(e.valid_up_to());
                    // SAFETY: `valid_up_to` bytes are valid UTF-8.
                    out.push_str(unsafe { std::str::from_utf8_unchecked(good) });
                    match e.error_len() {
                        // Cut short at the end: the rest comes with the next piece.
                        None => {
                            self.carry = bad.to_vec();
                            break;
                        }
                        Some(n) => {
                            out.push('\u{FFFD}');
                            rest = &bad[n..];
                        }
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(k, val)| (k.to_string(), val.to_string())).collect()
    }

    #[test]
    fn the_environment_is_the_accounts_then_the_carried_developer_names_then_the_given() {
        let defaults = pairs(&[
            ("USERPROFILE", r"C:\Users\ssai-sbx-1"),
            ("TEMP", r"C:\Users\ssai-sbx-1\AppData\Local\Temp"),
            ("Path", r"C:\Windows"),
        ]);
        let developer = |name: &str| match name {
            "PATH" => Some(r"C:\dev\bin;C:\Windows".to_string()),
            "TERM" => Some("xterm-256color".to_string()),
            "SECRET_TOKEN" | "USERPROFILE" | "TEMP" => Some("developer's".to_string()),
            _ => None,
        };
        let given = pairs(&[("HTTPS_PROXY", "http://127.0.0.1:9"), ("term", "dumb")]);
        let env = environment(defaults, &developer, &given);
        let get = |n: &str| env.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str());
        assert_eq!(get("USERPROFILE"), Some(r"C:\Users\ssai-sbx-1"));
        assert_eq!(get("TEMP"), Some(r"C:\Users\ssai-sbx-1\AppData\Local\Temp"));
        assert_eq!(get("PATH"), Some(r"C:\dev\bin;C:\Windows"));
        // A later value wins, whatever the case of its name.
        assert_eq!(get("TERM"), Some("dumb"));
        assert_eq!(get("HTTPS_PROXY"), Some("http://127.0.0.1:9"));
        // Nothing else of the developer's.
        assert_eq!(get("SECRET_TOKEN"), None);
        assert_eq!(get("PATHEXT"), None);
        // One entry per name.
        assert_eq!(env.iter().filter(|(k, _)| k.eq_ignore_ascii_case("PATH")).count(), 1);
        assert_eq!(env.iter().filter(|(k, _)| k.eq_ignore_ascii_case("TERM")).count(), 1);
    }

    #[test]
    fn the_block_is_sorted_nul_separated_and_double_nul_terminated() {
        let b = block(&pairs(&[("b", "2"), ("A", "1é")])).unwrap();
        let text = String::from_utf16(&b).unwrap();
        assert_eq!(text, "A=1é\0b=2\0\0");
        assert_eq!(block(&[]).unwrap(), vec![0, 0]);
    }

    #[test]
    fn a_variable_the_block_cannot_carry_is_refused() {
        for bad in [("", "x"), ("A=B", "x"), ("A\0", "x"), ("A", "x\0y")] {
            assert!(block(&pairs(&[bad])).is_err(), "{bad:?}");
        }
        assert!(block(&pairs(&[("A", "x=y")])).is_ok());
    }

    #[test]
    fn set_output_reads_back_as_variables() {
        let text = "ALLUSERSPROFILE=C:\\ProgramData\r\nPROMPT=$P$G\r\nX=a=b\r\n\r\nnot a variable\r\n=C:=C:\\\r\n";
        assert_eq!(
            parse_set(text),
            pairs(&[("ALLUSERSPROFILE", r"C:\ProgramData"), ("PROMPT", "$P$G"), ("X", "a=b")])
        );
    }

    #[test]
    fn a_surrogate_pair_split_across_reads_decodes_whole() {
        let units: Vec<u16> = "a😀b".encode_utf16().collect();
        let mut s = Utf16Stream::default();
        let (one, two) = units.split_at(2); // 'a' + high surrogate
        assert_eq!(s.push(one), "a");
        assert_eq!(s.push(two), "😀b");
        // An unpaired low surrogate is replaced, not dropped.
        assert_eq!(s.push(&[0xDC00]), "\u{FFFD}");
    }

    #[test]
    fn a_utf8_sequence_split_across_reads_decodes_whole_and_invalid_bytes_are_marked() {
        let bytes = "é😀".as_bytes();
        let mut s = Utf8Stream::default();
        let mut out = String::new();
        for b in bytes {
            out.push_str(&s.push(std::slice::from_ref(b)));
        }
        assert_eq!(out, "é😀");
        assert_eq!(s.push(b"a\xffb"), "a\u{FFFD}b");
    }

    proptest::proptest! {
        #[test]
        fn any_text_cut_anywhere_decodes_unchanged(text in ".*", cuts in proptest::collection::vec(0usize..64, 0..6)) {
            let bytes = text.as_bytes();
            let units: Vec<u16> = text.encode_utf16().collect();
            let (mut s8, mut s16) = (Utf8Stream::default(), Utf16Stream::default());
            let (mut o8, mut o16) = (String::new(), String::new());
            let (mut a, mut b) = (0usize, 0usize);
            for c in cuts {
                let e8 = (a + c).min(bytes.len());
                o8.push_str(&s8.push(&bytes[a..e8]));
                a = e8;
                let e16 = (b + c).min(units.len());
                o16.push_str(&s16.push(&units[b..e16]));
                b = e16;
            }
            o8.push_str(&s8.push(&bytes[a..]));
            o16.push_str(&s16.push(&units[b..]));
            proptest::prop_assert_eq!(&o8, &text);
            proptest::prop_assert_eq!(&o16, &text);
        }
    }
}
