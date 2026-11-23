//! The Windows sandbox's doctor checks: the sandbox account on this computer,
//! and per project its private root, its grant, and the items the grant does
//! not reach (an item that inherits nothing, one whose list was written
//! before the grant). `--fix` repairs a project after listing what it will
//! do and asking: the private-root takeover (`run::ensure_private_root`),
//! inheritance turned back on, a stale grant taken back, and one by-name
//! rewrite of each granted tree so every item below gets what it inherits.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::grants::Kind;
use super::{acl, run, setup};
use crate::progress::{Progress, grouped};
use crate::sandbox::doctor::{Check, Fix, Options, Outcome, Target, render, verdict};

const MACHINE: &str = "This computer";

/// What `--fix` would do in one project, gathered by its checks.
#[derive(Default)]
struct Repair {
    /// The folders to make the developer's alone (a private root, and a
    /// granted folder every account may still write), in order, each with
    /// the items the report listed for it.
    take_over: Vec<(PathBuf, Vec<PathBuf>)>,
    /// Protected items to turn inheritance back on for.
    protected: Vec<PathBuf>,
    /// The record says granted but the root's own list lost the entry: the
    /// grant is taken back, and the next run grants afresh.
    stale_grant: bool,
    /// Items missing the account's entry under a granted root: a rewrite of
    /// the granted trees reaches them.
    stale_items: bool,
    /// A private root of the project could not be checked or listed: no
    /// protected item is opened, since it would inherit from a folder every
    /// account may still open.
    root_unchecked: bool,
}

impl Repair {
    fn any(&self) -> bool {
        !self.take_over.is_empty() || !self.protected.is_empty() || self.stale_grant || self.stale_items
    }
}

pub fn run(target: Target, options: Options) -> Result<()> {
    let record = acl::record_path()?;
    let progress = Progress::stderr();
    let profile = run::profile_dir()?;
    let mut checks = Vec::new();
    let account = match setup::probe() {
        Ok(ready) => {
            checks.push(Check {
                id: "windows.account",
                subject: MACHINE.into(),
                outcome: Outcome::Ok(format!(
                    "the sandbox account {} is set up, its network blocked but for loopback",
                    ready.record.account
                )),
            });
            Some(ready.record.account_sid)
        }
        Err(reason) => {
            checks.push(Check {
                id: "windows.account",
                subject: MACHINE.into(),
                outcome: Outcome::Problem {
                    summary: reason,
                    paths: Vec::new(),
                    fix: Fix::Manual("run `ssai sandbox setup` (it asks for an administrator once)".into()),
                },
            });
            None
        }
    };
    let projects = match target {
        Target::Project(root) => vec![root],
        Target::All => acl::granted_projects(&record)?,
    };
    if projects.is_empty() {
        checks.push(Check {
            id: "windows.grant",
            subject: MACHINE.into(),
            outcome: Outcome::Note("no project is granted to the sandbox account yet".into()),
        });
    }
    let mut repairs = Vec::new();
    let mut scans = Scans::default();
    for root in &projects {
        let (found, repair) = check_project(&record, root, &profile, account.as_deref(), &mut scans, &progress);
        checks.extend(found);
        repairs.push((root.clone(), repair));
    }
    progress.pause();
    print!("{}", render(&checks, options.verbose));
    if !options.fix || !repairs.iter().any(|(_, r)| r.any()) {
        return verdict(&checks, false);
    }
    let Some(account) = account else {
        bail!("set the sandbox up first (`ssai sandbox setup`): a repair grants its account");
    };
    let mut after = checks.into_iter().filter(|c| c.subject == MACHINE).collect::<Vec<_>>();
    for (root, repair) in repairs {
        // One project's failed repair is named; the next is still repaired.
        if repair.any()
            && confirm(&root, options.yes)?
            && let Err(e) = fix_project(&record, &root, &account, repair, &progress)
        {
            progress.pause();
            crate::ui::error("", format_args!("{}: {e:#}", root.display()));
        }
        after.extend(check_project(&record, &root, &profile, Some(&account), &mut Scans::default(), &progress).0);
    }
    progress.pause();
    println!("\nAfter the repair:\n");
    print!("{}", render(&after, options.verbose));
    verdict(&after, true)
}

/// Ask before repairing `root` — `yes` answers for the developer; with no
/// terminal to ask at, the repair needs it.
fn confirm(root: &Path, yes: bool) -> Result<bool> {
    use std::io::IsTerminal as _;
    if yes {
        return Ok(true);
    }
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        bail!("nothing was repaired: there is no terminal to ask at — pass --yes to repair as listed");
    }
    crate::commands::session::confirm_no(&format!("Repair {} as listed above?", root.display()))
}

/// The checks of the project at `root`, and what `--fix` would do there.
/// The protected items of each folder a takeover would change, and the
/// folders under it whose project's record cannot be read — one walk per
/// folder in a doctor run (projects of `--all` share a private root).
#[derive(Default)]
struct Scans(std::collections::HashMap<String, Listed>);

/// A folder's protected items and its unreadable projects, or why it could
/// not be walked.
type Listed = std::result::Result<(Vec<PathBuf>, Vec<PathBuf>), String>;

impl Scans {
    fn protected(&mut self, root: &Path, progress: &Progress) -> Listed {
        self.0
            .entry(root.to_string_lossy().to_lowercase())
            .or_insert_with(|| {
                acl::scan(root, None, progress)
                    .map(|found| {
                        let items = found.protected.into_iter().chain(found.broad).collect();
                        (items, found.skipped.into_iter().map(|(d, _)| d).collect())
                    })
                    .map_err(|e| format!("{e:#}"))
            })
            .clone()
    }
}

/// Why `private` is not private, for the report.
fn not_private(private: &Path, state: acl::RootState) -> String {
    let why = match state {
        acl::RootState::Open(names) => format!(
            "its access list gives {} access — every account on this computer, or whoever creates a file there",
            names.join(", ")
        ),
        _ => "making it private to you was started and did not finish".into(),
    };
    format!("{} is not private to you: {why}", private.display())
}

fn check_project(record: &Path, root: &Path, profile: &Path, account: Option<&str>, scans: &mut Scans, progress: &Progress) -> (Vec<Check>, Repair) {
    let subject = format!("Project {}", root.display());
    let mut checks = Vec::new();
    let mut repair = Repair::default();
    let mut push = |id: &'static str, outcome: Outcome| checks.push(Check { id, subject: subject.clone(), outcome });

    // A folder `ssai run` refuses (a drive's root, a network share, the
    // profile or above) is no project: nothing in it is checked or changed.
    if let Some(why) = super::grants::refused_root(&root.to_string_lossy(), &profile.to_string_lossy()) {
        push("windows.project", Outcome::Problem { summary: format!("not a folder the sandbox runs in: {why}"), paths: Vec::new(), fix: Fix::Manual("run the doctor in a project folder".into()) });
        return (checks, repair);
    }

    // The folders that must be private, as `ssai run` decides them: the
    // private root of a project outside the profile (`run::run_roots`), and
    // the project folder itself when every account may still write it or
    // its own takeover was cut short.
    let mut takeovers: Vec<(PathBuf, String)> = Vec::new();
    let project = crate::sandbox::protect::resolve(root);
    let granted = run::granted_dirs(root, &project, profile);
    match run::run_roots(&granted, profile, record) {
        Ok(roots) => {
            for (dir, private) in &roots.alone {
                // One takeover of a root covers each folder left alone under it.
                if let Some((_, summary)) = takeovers.iter_mut().find(|(t, _)| run::within(t, private) && run::within(private, t)) {
                    summary.push_str(&format!("; so was {}", dir.display()));
                    continue;
                }
                takeovers.push((
                    private.clone(),
                    format!(
                        "{} was made private on its own and every account may still read it; the agent can change \
                         who may open the files it creates there",
                        dir.display()
                    ),
                ));
            }
            for private in &roots.roots {
                match acl::root_state(record, private) {
                    Ok(acl::RootState::Private) => {
                        push("windows.private-root", Outcome::Ok(format!("{} is private to you", private.display())))
                    }
                    Ok(state) => takeovers.push((private.clone(), not_private(private, state))),
                    Err(e) => {
                        repair.root_unchecked = true;
                        push("windows.private-root", Outcome::Failed(format!("{e:#}")));
                    }
                }
            }
        }
        Err(e) => {
            repair.root_unchecked = true;
            push("windows.private-root", Outcome::Failed(format!("{e:#}")));
        }
    }
    // A granted folder every account may still write, or whose own takeover
    // was cut short — as `ssai run` checks after its private roots; one under
    // a takeover listed above is covered by it.
    for dir in &granted {
        if takeovers.iter().any(|(t, _)| run::within(dir, t)) {
            continue;
        }
        let own = match acl::root_state(record, dir) {
            Ok(acl::RootState::Pending) => Some("making it private to you was started and did not finish".to_string()),
            _ => match (acl::broad_writers(dir), acl::names_own_broad(dir)) {
                (Ok(names), _) if !names.is_empty() => {
                    Some(format!("{} — every account on this computer — may write it", names.join(", ")))
                }
                (_, Ok(true)) => Some(
                    "an entry of its own gives every account access, or whoever creates a file there full control"
                        .to_string(),
                ),
                _ => None,
            },
        };
        if let Some(why) = own {
            takeovers.push((dir.to_path_buf(), format!("{} is not private to you: {why}", dir.display())));
        }
    }
    for (private, summary) in takeovers {
        // What the takeover changes besides the folder's own list, listed
        // here: every item in it that inherits nothing.
        let outcome = match scans.protected(&private, progress) {
            Ok((protected, skipped)) => {
                let mut fix = format!("make {} private to you, as your home folder is (every project in it at once)", private.display());
                if !protected.is_empty() {
                    fix.push_str(&format!(
                        "; the {} folder(s) and file(s) listed — inheriting nothing, or giving every account access by \
                         an entry of their own — keep their own entries but every account's, and inherit",
                        grouped(protected.len() as u64)
                    ));
                }
                for dir in skipped {
                    fix.push_str(&format!("; under {} (its project's record cannot be read) none of them is changed", dir.display()));
                }
                repair.take_over.push((private, protected.clone()));
                Outcome::Problem { summary, paths: protected, fix: Fix::Auto(fix) }
            }
            Err(e) => {
                repair.root_unchecked = true;
                Outcome::Failed(format!("{} cannot be listed, so it is not changed: {e}", private.display()))
            }
        };
        push("windows.private-root", outcome);
    }

    let trees = acl::granted_trees(record, root).unwrap_or_default();
    let granted = match (account, trees.is_empty()) {
        (_, true) => {
            push("windows.grant", Outcome::Note("not granted yet: the next `ssai run --sandbox native` here grants it".into()));
            false
        }
        (None, false) => {
            push("windows.grant", Outcome::Failed("the sandbox account is not set up, so its grant cannot be read".into()));
            false
        }
        (Some(account), false) => match acl::holds(root, account, Kind::Modify) {
            Ok(true) => {
                push("windows.grant", Outcome::Ok("granted to the sandbox account".into()));
                true
            }
            Ok(false) => {
                push(
                    "windows.grant",
                    Outcome::Problem {
                        summary: "recorded as granted, but the project's own list lost the sandbox's entry".into(),
                        paths: Vec::new(),
                        fix: Fix::Auto("take the stale grant back; the next `ssai run` grants it again".into()),
                    },
                );
                repair.stale_grant = true;
                false
            }
            Err(e) => {
                push("windows.grant", Outcome::Failed(format!("{e:#}")));
                false
            }
        },
    };

    match acl::scan(root, if granted { account } else { None }, progress) {
        Ok(mut found) => {
            // A held tree the account must not write is left as `ssai run`
            // leaves it: not reported, not opened.
            found.protected = super::grants::walled_to_report(found.protected, &crate::sandbox::protect::resolve(root));
            if found.protected.is_empty() {
                push(
                    "windows.inheritance",
                    Outcome::Ok(format!("every one of {} items inherits what the project grants", grouped(found.items))),
                );
            } else {
                push(
                    "windows.inheritance",
                    Outcome::Problem {
                        summary: format!(
                            "{} folder(s) and file(s) inherit nothing, so no grant reaches them (nor what is in them)",
                            grouped(found.protected.len() as u64)
                        ),
                        paths: found.protected.clone(),
                        fix: Fix::Auto(
                            "turn their inheritance back on, keeping their own entries but every account's, then \
                             re-apply what the project grants"
                                .into(),
                        ),
                    },
                );
                repair.protected = found.protected;
            }
            // Under a root already private, an item giving every account
            // access (or a creator's entry) by an entry of its own: no
            // takeover above removes it. Under a takeover listed above, that
            // takeover lists and removes it.
            let taken_over = repair.take_over.iter().any(|(private, _)| run::within(root, private));
            if !found.broad.is_empty() && !taken_over {
                push(
                    "windows.broad",
                    Outcome::Problem {
                        summary: format!(
                            "{} folder(s) and file(s) give every account access (or whoever creates a file there full \
                             control) by an entry of their own",
                            grouped(found.broad.len() as u64)
                        ),
                        paths: found.broad.clone(),
                        fix: Fix::Auto("remove those entries, keeping the rest of their own".into()),
                    },
                );
                repair.protected.extend(found.broad);
            }
            if granted {
                if found.stale.is_empty() {
                    push("windows.stale", Outcome::Ok("every item that inherits holds the sandbox's entry".into()));
                } else {
                    push(
                        "windows.stale",
                        Outcome::Problem {
                            summary: format!(
                                "{} item(s) kept a list written before the grant (moved in afterwards, or a link to \
                                 a file elsewhere)",
                                grouped(found.stale.len() as u64)
                            ),
                            paths: found.stale,
                            fix: Fix::Auto("re-apply what the project grants".into()),
                        },
                    );
                    repair.stale_items = true;
                }
            }
            if !found.skipped.is_empty() {
                push(
                    "windows.manifest",
                    Outcome::Problem {
                        summary: format!(
                            "a project's record cannot be read ({}), so its key files cannot be told apart and nothing \
                             in it is checked",
                            found.skipped[0].1
                        ),
                        paths: found.skipped.into_iter().map(|(p, _)| p).collect(),
                        fix: Fix::Manual("run `ssai provision` again in that project".into()),
                    },
                );
            }
            if !found.unreadable.is_empty() {
                push(
                    "windows.unreadable",
                    Outcome::Problem {
                        summary: format!("{} item(s) whose access list you may not read", grouped(found.unreadable.len() as u64)),
                        paths: found.unreadable,
                        fix: Fix::Manual("check your own access to them (their owner or an administrator can)".into()),
                    },
                );
            }
        }
        Err(e) => push("windows.inheritance", Outcome::Failed(format!("{e:#}"))),
    }
    (checks, repair)
}

/// Repair the project at `root` as `repair` lists.
fn fix_project(record: &Path, root: &Path, account: &str, repair: Repair, progress: &Progress) -> Result<()> {
    let mut refused: Vec<(PathBuf, String)> = Vec::new();
    // The takeover turns inheritance back on for every protected item under
    // the private root, the project's among them, and walks it all once.
    for (private, listed) in &repair.take_over {
        run::ensure_private_root(record, private, run::Consent::Listed(listed), account, progress)?;
    }
    // A takeover whose walk covers the project repaired it too; one of
    // another granted folder (a worktree's main checkout elsewhere) did not.
    let covered = repair.take_over.iter().any(|(private, _)| run::within(root, private));
    if !covered && !repair.protected.is_empty() {
        if repair.root_unchecked {
            // Opened, they would inherit from a folder every account may
            // still open.
            let why = "its private root could not be checked, so it keeps its own list";
            refused.extend(repair.protected.iter().map(|p| (p.clone(), why.to_string())));
        } else {
            refused.extend(acl::unprotect(&repair.protected, &crate::win_acl::current_user_sid()?, progress)?);
        }
    }
    if repair.stale_grant {
        acl::revoke(record, account, Some(root), progress)?;
    } else if !covered {
        // (A takeover's walk already gave every item below what it inherits.)
        let trees = acl::granted_trees(record, root)?;
        // Not granted: the project's own list is rewritten, so what it gives
        // (the developer's, the private root's) reaches the items opened.
        let trees = if trees.is_empty() { vec![root.to_path_buf()] } else { trees };
        for tree in trees {
            if let Err(e) = acl::rewrite(&tree, progress) {
                refused.push((tree, format!("{e:#}")));
            }
        }
    }
    progress.finish(format!("✓ {} repaired", root.display()));
    if !refused.is_empty() {
        let names: Vec<PathBuf> = refused.iter().map(|(p, _)| p.clone()).collect();
        crate::ui::warn(
            "",
            format_args!(
                "{} item(s) could not be changed (the first: {}): {}",
                grouped(refused.len() as u64),
                refused[0].1,
                run::shown(&names)
            ),
        );
    }
    Ok(())
}
