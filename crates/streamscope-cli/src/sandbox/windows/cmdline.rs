//! Windows command lines: one string a program splits back into its
//! arguments by the rules of the C runtime (`CommandLineToArgvW`). Pure, so
//! it is tested on every host.

// Off Windows this module is compiled for its tests only.
#![cfg_attr(not(windows), allow(dead_code))]

use anyhow::{Result, bail};

/// `arg` quoted so the C runtime reads it back unchanged: as it is when it
/// holds no space, tab, quote or line break and is not empty; else in
/// quotes, a quote escaped and the backslashes before a quote (or the
/// closing one) doubled.
pub fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// The command line that runs `program` (an absolute path) with `args`. A
/// batch file (`.cmd`, `.bat`) runs through `cmd` (`cmd_exe`), which expands
/// `%` inside quotes and cannot carry a quote or a line break in an
/// argument: one holding any of them is refused.
pub fn command_line(cmd_exe: &str, program: &str, args: &[String]) -> Result<String> {
    // A command line ends at its first NUL: what follows would be lost.
    if let Some(bad) = std::iter::once(program).chain(args.iter().map(String::as_str)).find(|a| a.contains('\0')) {
        bail!("an argument holds a NUL character, which a Windows command line cannot carry: {bad:?}");
    }
    let lower = program.to_ascii_lowercase();
    if lower.ends_with(".cmd") || lower.ends_with(".bat") {
        if let Some(bad) = args.iter().find(|a| a.contains(['"', '%', '\r', '\n'])) {
            bail!(
                "{program} is a batch launcher, which cannot be given the argument {bad:?} (a quote, a `%` \
                 or a line break) — pass that text some other way (a file, the tool's own prompt)"
            );
        }
        // Every part quoted, so `&`, `|`, `<`, `>`, `^` and `(` stay text;
        // `/s` removes the outer pair of quotes and leaves the rest as it is.
        // The batch file hands its arguments on (`%*`) to a program that
        // splits them by the C runtime's rules, where backslashes before the
        // closing quote are doubled (`"C:\work\\"`), or they escape it.
        let inner: Vec<String> = std::iter::once(program)
            .chain(args.iter().map(String::as_str))
            .map(|a| {
                let trailing = a.len() - a.trim_end_matches('\\').len();
                format!("\"{a}{}\"", "\\".repeat(trailing))
            })
            .collect();
        return Ok(format!("{} /e:ON /v:OFF /d /s /c \"{}\"", quote(cmd_exe), inner.join(" ")));
    }
    Ok(std::iter::once(program).chain(args.iter().map(String::as_str)).map(quote).collect::<Vec<_>>().join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CommandLineToArgvW`'s rules for an argument after the first: the
    /// reference the quoting is checked against.
    fn split(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                i += 1;
            }
            if i >= chars.len() {
                break;
            }
            let mut arg = String::new();
            let mut quoted = false;
            while i < chars.len() && (quoted || (chars[i] != ' ' && chars[i] != '\t')) {
                if chars[i] == '\\' {
                    let start = i;
                    while i < chars.len() && chars[i] == '\\' {
                        i += 1;
                    }
                    let n = i - start;
                    if i < chars.len() && chars[i] == '"' {
                        arg.extend(std::iter::repeat_n('\\', n / 2));
                        if n % 2 == 1 {
                            arg.push('"');
                            i += 1;
                        }
                    } else {
                        arg.extend(std::iter::repeat_n('\\', n));
                    }
                } else if chars[i] == '"' {
                    if quoted && i + 1 < chars.len() && chars[i + 1] == '"' {
                        arg.push('"');
                        i += 2;
                        continue;
                    }
                    quoted = !quoted;
                    i += 1;
                } else {
                    arg.push(chars[i]);
                    i += 1;
                }
            }
            out.push(arg);
        }
        out
    }

    #[test]
    fn every_argument_reads_back_unchanged() {
        let args: Vec<String> = [
            "plain", "", "two words", "tab\there", r"C:\Program Files\x\", r#"say "hi""#, r#"\"#, r#"a\\"b"#,
            r#"trailing\\"#, "line\nbreak", r#"\\server\share"#, "ünï cødé",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let line = command_line("cmd.exe", r"C:\tools\agent.exe", &args).unwrap();
        let back = split(&line);
        assert_eq!(back[0], r"C:\tools\agent.exe");
        assert_eq!(&back[1..], &args[..]);
    }

    proptest::proptest! {
        #[test]
        fn any_argument_reads_back_unchanged(args in proptest::collection::vec("[^\0]*", 0..6)) {
            let line = command_line("cmd.exe", "agent.exe", &args).unwrap();
            let back = split(&line);
            proptest::prop_assert_eq!(&back[1..], &args[..]);
        }
    }

    #[test]
    fn a_batch_launcher_runs_through_cmd_with_every_part_quoted() {
        let args = vec!["-p".to_string(), "a & b | c".to_string()];
        let line = command_line(r"C:\Windows\System32\cmd.exe", r"C:\Users\me\AppData\Roaming\npm\claude.CMD", &args).unwrap();
        assert_eq!(
            line,
            r#"C:\Windows\System32\cmd.exe /e:ON /v:OFF /d /s /c ""C:\Users\me\AppData\Roaming\npm\claude.CMD" "-p" "a & b | c"""#
        );
    }

    proptest::proptest! {
        /// What cmd hands the batch file (between `/c "` and the last quote)
        /// splits back, by the C runtime's rules, into the arguments.
        #[test]
        fn a_batch_launchers_arguments_read_back_unchanged(args in proptest::collection::vec("[^\"%\r\n\0]*", 0..6)) {
            let line = command_line("cmd.exe", r"C:\x\agent.cmd", &args).unwrap();
            let inner = line.split_once("/c \"").unwrap().1.strip_suffix('"').unwrap();
            let back = split(inner);
            proptest::prop_assert_eq!(&back[1..], &args[..]);
        }
    }

    #[test]
    fn a_batch_launcher_refuses_what_cmd_would_change_and_an_exe_takes_it() {
        for bad in [r#"say "hi""#, "100%", "%PATH%", "a\nb", "a\rb"] {
            let args = vec![bad.to_string()];
            assert!(command_line("cmd.exe", r"C:\x\agent.cmd", &args).is_err(), "{bad:?}");
            assert!(command_line("cmd.exe", r"C:\x\agent.bat", &args).is_err(), "{bad:?}");
            assert!(command_line("cmd.exe", r"C:\x\agent.exe", &args).is_ok(), "{bad:?}");
        }
        let nul = vec!["a\0b".to_string()];
        assert!(command_line("cmd.exe", r"C:\x\agent.exe", &nul).is_err());
        assert!(command_line("cmd.exe", r"C:\x\agent.cmd", &nul).is_err());
    }
}
