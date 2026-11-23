//! `ssai sandbox doctor`: what each platform's sandbox needs on this computer
//! and in a project, checked and reported in one shape — a check is an id, a
//! subject (this computer or a project) and an outcome — so every platform
//! adds its checks without a command of its own. Windows' checks are in
//! `windows/doctor.rs`; a platform whose sandbox keeps nothing on disk has
//! none yet.
#![cfg_attr(not(windows), allow(dead_code, reason = "only Windows has checks yet; the report is tested on every host"))]

use std::path::PathBuf;

use crate::progress::grouped;

/// What `ssai sandbox doctor` prints where no check applies.
#[cfg_attr(windows, allow(dead_code, reason = "Windows has checks"))]
pub const NOTHING_TO_CHECK: &str =
    "The sandbox on this system keeps nothing on disk between runs: `ssai sandbox doctor` has nothing to check here.";

/// How many paths a finding names before it counts the rest.
const SHOWN_PATHS: usize = 5;

/// Which projects to check.
pub enum Target {
    /// One project, by the folder `ssai run` confines to.
    Project(PathBuf),
    /// Every project the sandbox was granted.
    All,
}

pub struct Options {
    /// Repair what was found.
    pub fix: bool,
    /// Repair without asking.
    pub yes: bool,
    /// Name every path found.
    pub verbose: bool,
}

/// One check's result.
pub struct Check {
    /// Stable id, `<platform>.<what>`.
    pub id: &'static str,
    /// What was checked: this computer, or a project's folder.
    pub subject: String,
    pub outcome: Outcome,
}

pub enum Outcome {
    /// Nothing wrong, and what was found.
    Ok(String),
    /// Not a problem, worth knowing (a project not granted yet).
    Note(String),
    /// A problem: what it is, the paths it concerns, and how it is fixed.
    Problem { summary: String, paths: Vec<PathBuf>, fix: Fix },
    /// The check could not run, and why.
    Failed(String),
}

pub enum Fix {
    /// What `--fix` does.
    Auto(String),
    /// What the developer does (a command needing an administrator, a step
    /// only they can take).
    Manual(String),
}

impl Check {
    pub fn problem(&self) -> bool {
        matches!(self.outcome, Outcome::Problem { .. } | Outcome::Failed(_))
    }

    pub fn fixable(&self) -> bool {
        matches!(self.outcome, Outcome::Problem { fix: Fix::Auto(_), .. })
    }
}

/// The report: the checks grouped by subject in the order given, each one
/// line, a problem followed by its paths (the first few unless `verbose`)
/// and its fix.
pub fn render(checks: &[Check], verbose: bool) -> String {
    let mut out = String::new();
    let mut subject: Option<&str> = None;
    for check in checks {
        if subject != Some(check.subject.as_str()) {
            if subject.is_some() {
                out.push('\n');
            }
            out.push_str(&check.subject);
            out.push('\n');
            subject = Some(&check.subject);
        }
        match &check.outcome {
            Outcome::Ok(text) => out.push_str(&format!("  ✓ {} — {text}\n", check.id)),
            Outcome::Note(text) => out.push_str(&format!("  · {} — {text}\n", check.id)),
            Outcome::Failed(why) => out.push_str(&format!("  ✗ {} — could not check: {why}\n", check.id)),
            Outcome::Problem { summary, paths, fix } => {
                out.push_str(&format!("  ! {} — {summary}\n", check.id));
                let shown = if verbose { paths.len() } else { paths.len().min(SHOWN_PATHS) };
                for path in &paths[..shown] {
                    out.push_str(&format!("      {}\n", path.display()));
                }
                if paths.len() > shown {
                    out.push_str(&format!("      … and {} more (--verbose lists them)\n", grouped((paths.len() - shown) as u64)));
                }
                match fix {
                    Fix::Auto(what) => out.push_str(&format!("    --fix: {what}\n")),
                    Fix::Manual(what) => out.push_str(&format!("    to fix: {what}\n")),
                }
            }
        }
    }
    out
}

/// The run's end: `Ok` when nothing is wrong, else an error counting the
/// problems and what `--fix` repairs of them (the command exits 1).
pub fn verdict(checks: &[Check], fixed_already: bool) -> anyhow::Result<()> {
    let problems = checks.iter().filter(|c| c.problem()).count();
    if problems == 0 {
        return Ok(());
    }
    let fixable = checks.iter().filter(|c| c.fixable()).count();
    let hint = match (fixable, fixed_already) {
        (0, _) => " (each says how to fix it)".to_string(),
        (_, true) => " — named above, not repaired".to_string(),
        (n, false) if n == problems => " — `ssai sandbox doctor --fix` repairs them".to_string(),
        (n, false) => format!(" — `ssai sandbox doctor --fix` repairs {n} of them"),
    };
    anyhow::bail!("{problems} problem(s) found{hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &'static str, subject: &str, outcome: Outcome) -> Check {
        Check { id, subject: subject.to_string(), outcome }
    }

    #[test]
    fn the_report_groups_by_subject_and_names_the_first_paths_of_a_problem() {
        let paths: Vec<PathBuf> = (0..8).map(|i| PathBuf::from(format!("/p/f{i}"))).collect();
        let checks = vec![
            check("windows.account", "This computer", Outcome::Ok("ready".into())),
            check("windows.grant", "Project /p", Outcome::Note("not granted yet".into())),
            check(
                "windows.inheritance",
                "Project /p",
                Outcome::Problem { summary: "8 items inherit nothing".into(), paths: paths.clone(), fix: Fix::Auto("turn it back on".into()) },
            ),
            check("windows.stale", "Project /p", Outcome::Failed("denied".into())),
        ];
        let text = render(&checks, false);
        assert_eq!(
            text,
            "This computer\n  ✓ windows.account — ready\n\nProject /p\n  · windows.grant — not granted yet\n  \
             ! windows.inheritance — 8 items inherit nothing\n      /p/f0\n      /p/f1\n      /p/f2\n      /p/f3\n      \
             /p/f4\n      … and 3 more (--verbose lists them)\n    --fix: turn it back on\n  ✗ windows.stale — could not \
             check: denied\n"
        );
        let all = render(&checks, true);
        assert!(all.contains("/p/f7") && !all.contains("more"), "{all}");
    }

    #[test]
    fn the_verdict_counts_problems_and_what_fix_repairs() {
        let ok = vec![check("a", "s", Outcome::Ok("fine".into())), check("b", "s", Outcome::Note("fyi".into()))];
        assert!(verdict(&ok, false).is_ok());
        let auto = || Outcome::Problem { summary: "x".into(), paths: vec![], fix: Fix::Auto("y".into()) };
        let manual = || Outcome::Problem { summary: "x".into(), paths: vec![], fix: Fix::Manual("y".into()) };
        let both = vec![check("a", "s", auto()), check("b", "s", manual())];
        assert_eq!(verdict(&both, false).unwrap_err().to_string(), "2 problem(s) found — `ssai sandbox doctor --fix` repairs 1 of them");
        let fixable = vec![check("a", "s", auto())];
        assert_eq!(verdict(&fixable, false).unwrap_err().to_string(), "1 problem(s) found — `ssai sandbox doctor --fix` repairs them");
        assert_eq!(verdict(&fixable, true).unwrap_err().to_string(), "1 problem(s) found — named above, not repaired");
        let failed = vec![check("a", "s", Outcome::Failed("no".into()))];
        assert_eq!(verdict(&failed, false).unwrap_err().to_string(), "1 problem(s) found (each says how to fix it)");
    }
}
