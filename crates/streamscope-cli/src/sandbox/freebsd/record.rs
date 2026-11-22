//! A run's record: every step the daemon takes to build a jail, written
//! BEFORE the step is taken, so whatever a crash leaves behind is named in a
//! root-owned file the next sweep reads. Teardown undoes the record in exact
//! reverse order — never a sort by path — after removing the jail (whose
//! processes would hold its mounts busy), and unmounts by filesystem id, only
//! while the id still names the exact mount recorded (type and mount point as
//! the kernel reported them), never by a path an agent could have redirected,
//! and never by force: a forced unmount over stacked nullfs can wedge the
//! host. A busy unmount stops the teardown with the record kept, for a later
//! sweep. A record from an earlier boot (`kern.boot_id`, which a clock step
//! never changes) names nothing still mounted: only its folder is removed.
//!
//! Claim (locked by `any_crash_is_undone_by_the_next_sweep`): whatever prefix
//! of a build ran before a crash, the sweep leaves no mount, jail or folder of
//! the run, and removes the record; a sweep stopped by a busy mount finishes
//! on a later sweep.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One build step, recorded before it is taken.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum Step {
    /// A folder the daemon creates (the jail's root mount point).
    Dir { path: PathBuf },
    /// A mount at `target`: host-absolute, or — `in_jail` — as seen from
    /// inside the jail root, where a file mount's kernel name is that
    /// jail-relative path. Followed by a [`Line::Mounted`] once made.
    Mount { target: PathBuf, in_jail: bool },
    /// The jail itself, by name.
    Jail { name: String },
}

/// A line of the record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(tag = "line", rename_all = "snake_case")]
pub enum Line {
    /// The first line: whose run it is, and the boot it was made in
    /// (`kern.boot_id`, hex; empty where the kernel has none).
    Owner { uid: u32, boot: String },
    /// About to take this step.
    Begin(Step),
    /// The last [`Step::Mount`] was made: its filesystem id, type and the
    /// name the kernel gives its mount point (`statfs`'s `f_mntonname`).
    Mounted { fsid: [i32; 2], fstype: String, on: String },
    /// The jail is built: processes may be started in it.
    Ready,
    /// Its teardown has begun: nothing new starts in it.
    Ending,
    /// A teardown is about to unmount this mount, written BEFORE it does: no
    /// later sweep acts on it again (its id may be reused, and a file mount's
    /// name is the same for every run of one project) — unless a [`Line::Kept`]
    /// follows. A teardown killed in between leaves the mount behind, never
    /// another run's unmounted.
    Unmounted { fsid: [i32; 2], fstype: String, on: String },
    /// The unmount just announced failed: the mount is still the run's.
    Kept { fsid: [i32; 2], fstype: String, on: String },
}

/// A mounted filesystem, as `getfsstat` lists it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct MountEntry {
    pub fsid: [i32; 2],
    pub fstype: String,
    pub on: String,
}

/// What the teardown does to the host.
pub trait Host {
    /// Every mounted filesystem.
    fn mounts(&mut self) -> Vec<MountEntry>;
    /// What is mounted at `target` as seen from inside the jail root `root`
    /// (`statfs` there), for a mount made in the jail whose line was never
    /// written.
    fn mounted_in(&mut self, root: &std::path::Path, target: &std::path::Path) -> Option<MountEntry>;
    /// Unmount by filesystem id; `Err(true)` when busy, `Err(false)` on any
    /// other failure.
    fn unmount(&mut self, fsid: [i32; 2]) -> Result<(), bool>;
    /// Remove the jail named `name`, killing its processes; absent is fine.
    fn remove_jail(&mut self, name: &str) -> Result<(), String>;
    /// Remove an (empty) folder; absent is fine.
    fn remove_dir(&mut self, path: &std::path::Path) -> Result<(), String>;
}

/// Read a record's lines; a torn last line (a crash mid-write) is dropped.
pub fn parse(text: &str) -> Vec<Line> {
    text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// Whether the record says the jail is built and not being removed.
pub fn ready(lines: &[Line]) -> bool {
    lines.contains(&Line::Ready) && !lines.contains(&Line::Ending)
}

/// The owner a record names, if its first line is one.
pub fn owner(lines: &[Line]) -> Option<u32> {
    match lines.first() {
        Some(Line::Owner { uid, .. }) => Some(*uid),
        _ => None,
    }
}

/// Undo `lines`: the jail first, then each mount in reverse, then the
/// folders. `boot` is this boot's `kern.boot_id` (empty where the kernel has
/// none: every record is then taken as this boot's). Each mount is handed to
/// `note` before it is unmounted (`true`: the caller writes
/// [`Line::Unmounted`]) and again when that fails (`false`: [`Line::Kept`]).
/// `Ok` when nothing of the run is left (the caller removes the record);
/// `Err` names what stopped it, the record kept.
pub fn teardown(host: &mut impl Host, lines: &[Line], boot: &str, note: &mut dyn FnMut(&MountEntry, bool)) -> Result<(), String> {
    let this_boot = match lines.first() {
        Some(Line::Owner { boot: b, .. }) => b.is_empty() || boot.is_empty() || b == boot,
        _ => true,
    };
    // Each step with what is known of its outcome.
    let mut steps: Vec<(Step, Option<MountEntry>)> = Vec::new();
    let mut gone: Vec<MountEntry> = Vec::new();
    for line in lines {
        match line {
            Line::Owner { .. } | Line::Ready | Line::Ending => {}
            Line::Unmounted { fsid, fstype, on } => gone.push(MountEntry { fsid: *fsid, fstype: fstype.clone(), on: on.clone() }),
            Line::Kept { fsid, fstype, on } => {
                let kept = MountEntry { fsid: *fsid, fstype: fstype.clone(), on: on.clone() };
                gone.retain(|g| *g != kept);
            }
            Line::Begin(step) => steps.push((step.clone(), None)),
            Line::Mounted { fsid, fstype, on } => {
                if let Some((Step::Mount { .. }, made @ None)) = steps.last_mut() {
                    *made = Some(MountEntry { fsid: *fsid, fstype: fstype.clone(), on: on.clone() });
                }
            }
        }
    }
    let root = steps.iter().find_map(|(s, _)| match s {
        Step::Dir { path } => Some(path.clone()),
        _ => None,
    });
    if this_boot {
        for (step, _) in &steps {
            if let Step::Jail { name } = step {
                host.remove_jail(name)?;
            }
        }
        // The mount table read once, kept current as mounts go.
        let mut table = host.mounts();
        for (step, made) in steps.iter().rev() {
            let Step::Mount { target, in_jail } = step else { continue };
            if made.as_ref().is_some_and(|m| gone.contains(m)) {
                continue;
            }
            let found = match made {
                // The id recorded, only while it still names the very mount
                // recorded: an id is reused once its mount is gone.
                Some(m) => table.iter().find(|e| *e == m).cloned(),
                // No line (a crash between the mount and its line): where the
                // mount was made. In the jail, `statfs` there — reverse order
                // makes ours the top mount at that path.
                // The kernel names a folder mount made in the jail by its
                // host path, a file mount by the jail's: either is ours.
                None if *in_jail => match &root {
                    Some(root) => host.mounted_in(root, target).filter(|e| {
                        let on = Path::new(&e.on);
                        e.fstype == "nullfs" && (on == target || on == root.join(target.strip_prefix("/").unwrap_or(target)))
                    }),
                    None => None,
                },
                None => table.iter().find(|e| Path::new(&e.on) == target).cloned(),
            };
            if let Some(entry) = found {
                note(&entry, true);
                match host.unmount(entry.fsid) {
                    Ok(()) => table.retain(|e| *e != entry),
                    Err(busy) => {
                        note(&entry, false);
                        return Err(if busy {
                            format!("{} is busy", target.display())
                        } else {
                            format!("could not unmount {}", target.display())
                        });
                    }
                }
            }
        }
    }
    for (step, _) in steps.iter().rev() {
        if let Step::Dir { path } = step {
            host.remove_dir(path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    const ROOT: &str = "/var/run/ssai/jails/r1";
    const BOOT: &str = "8f699941f7ef60cf948907a38def093b";

    /// A fake host: what is mounted (in mount order), the jails, the folders,
    /// and the mounts that refuse to unmount while `busy` holds them. A mount
    /// made in the jail is named as the jail sees it (the kernel's name for a
    /// file mount made in a chroot).
    #[derive(Default)]
    struct FakeHost {
        mounts: Vec<MountEntry>,
        jails: BTreeSet<String>,
        dirs: BTreeSet<PathBuf>,
        busy: BTreeSet<[i32; 2]>,
        next: i32,
    }

    impl FakeHost {
        fn mount(&mut self, on: String) -> MountEntry {
            self.next += 1;
            let m = MountEntry { fsid: [self.next, 7], fstype: "nullfs".into(), on };
            self.mounts.push(m.clone());
            m
        }
    }

    impl Host for FakeHost {
        fn mounts(&mut self) -> Vec<MountEntry> {
            self.mounts.clone()
        }
        fn mounted_in(&mut self, root: &Path, target: &Path) -> Option<MountEntry> {
            let host = root.join(target.strip_prefix("/").unwrap());
            self.mounts.iter().rev().find(|m| Path::new(&m.on) == target || Path::new(&m.on) == host).cloned()
        }
        fn unmount(&mut self, fsid: [i32; 2]) -> Result<(), bool> {
            if self.busy.contains(&fsid) || !self.jails.is_empty() {
                return Err(true);
            }
            let at = self.mounts.iter().position(|m| m.fsid == fsid).ok_or(false)?;
            // A mount with a later one on top of it (or under it) is busy.
            let on = self.mounts[at].on.clone();
            if self.mounts[at + 1..].iter().any(|m| m.on.starts_with(&format!("{on}/"))) {
                return Err(true);
            }
            self.mounts.remove(at);
            Ok(())
        }
        fn remove_jail(&mut self, name: &str) -> Result<(), String> {
            self.jails.remove(name);
            Ok(())
        }
        fn remove_dir(&mut self, path: &Path) -> Result<(), String> {
            if self.mounts.iter().any(|m| Path::new(&m.on).starts_with(path)) {
                return Err("busy".into());
            }
            self.dirs.remove(path);
            Ok(())
        }
    }

    /// One event of a build: a record line, or an act on the host.
    enum Event {
        Write(Line),
        MakeDir(PathBuf),
        /// A mount, named as the kernel names it.
        Mount(String),
        RecordMount,
        MakeJail(String),
    }

    /// The build a daemon runs: the root folder and its tmpfs, `system`
    /// mounts under it, the jail, then `user` mounts made in the jail (every
    /// other one a file, named jail-relative).
    fn build(system: usize, user: usize) -> Vec<Event> {
        let root = PathBuf::from(ROOT);
        let mut ev = vec![Event::Write(Line::Owner { uid: 1001, boot: BOOT.into() })];
        ev.push(Event::Write(Line::Begin(Step::Dir { path: root.clone() })));
        ev.push(Event::MakeDir(root.clone()));
        let host_targets = std::iter::once(root.clone()).chain((0..system).map(|i| root.join(format!("s{i}"))));
        for t in host_targets {
            ev.push(Event::Write(Line::Begin(Step::Mount { target: t.clone(), in_jail: false })));
            ev.push(Event::Mount(t.to_string_lossy().into_owned()));
            ev.push(Event::RecordMount);
        }
        ev.push(Event::Write(Line::Begin(Step::Jail { name: "ssai-r1".into() })));
        ev.push(Event::MakeJail("ssai-r1".into()));
        for i in 0..user {
            let t = PathBuf::from(format!("/home/u/f{i}"));
            ev.push(Event::Write(Line::Begin(Step::Mount { target: t.clone(), in_jail: true })));
            // A file mount made in the jail is named as the jail sees it, a
            // folder mount by its host path: every other one of each.
            let on = if i % 2 == 0 { t.to_string_lossy().into_owned() } else { format!("{ROOT}{}", t.display()) };
            ev.push(Event::Mount(on));
            ev.push(Event::RecordMount);
        }
        ev
    }

    /// Run the first `k` events; the record is what was written.
    fn crash_after(host: &mut FakeHost, events: &[Event], k: usize) -> Vec<Line> {
        let mut record = Vec::new();
        let mut last = None;
        for e in &events[..k] {
            match e {
                Event::Write(l) => record.push(l.clone()),
                Event::MakeDir(p) => {
                    host.dirs.insert(p.clone());
                }
                Event::Mount(on) => last = Some(host.mount(on.clone())),
                Event::RecordMount => {
                    let m: MountEntry = last.take().unwrap();
                    record.push(Line::Mounted { fsid: m.fsid, fstype: m.fstype, on: m.on });
                }
                Event::MakeJail(name) => {
                    host.jails.insert(name.clone());
                }
            }
        }
        record
    }

    /// The host's own mounts, which no sweep may touch — among them one
    /// named like a user mount (a host path such as `/home/u/f0` is also
    /// what a file mount made in the jail is called).
    fn foreign() -> Vec<MountEntry> {
        vec![
            MountEntry { fsid: [900, 1], fstype: "zfs".into(), on: "/home".into() },
            MountEntry { fsid: [901, 1], fstype: "zfs".into(), on: "/home/u/f0".into() },
        ]
    }

    proptest! {
        #[test]
        fn any_crash_is_undone_by_the_next_sweep(
            system in 0usize..4,
            user in 0usize..4,
            cut in 0usize..64,
            busy_at in proptest::option::of(0usize..8),
        ) {
            let events = build(system, user);
            let k = cut % (events.len() + 1);
            let mut host = FakeHost { mounts: foreign(), ..FakeHost::default() };
            let record = crash_after(&mut host, &events, k);
            // The record round-trips through its text form.
            let text: String = record.iter().map(|l| serde_json::to_string(l).unwrap() + "\n").collect();
            let mut lines = parse(&text);
            prop_assert_eq!(&lines, &record);
            if let Some(i) = busy_at
                && let Some(m) = host.mounts.iter().filter(|m| m.fsid[0] < 900).nth(i)
            {
                let fsid = m.fsid;
                host.busy.insert(fsid);
                let mut written = Vec::new();
                prop_assert!(
                    teardown(&mut host, &lines, BOOT, &mut |m, before| {
                        written.push(if before {
                            Line::Unmounted { fsid: m.fsid, fstype: m.fstype.clone(), on: m.on.clone() }
                        } else {
                            Line::Kept { fsid: m.fsid, fstype: m.fstype.clone(), on: m.on.clone() }
                        })
                    })
                    .is_err(),
                    "a busy mount must stop the sweep"
                );
                host.busy.clear();
                // What the stopped sweep wrote is in the record now.
                lines.extend(written);
            }
            prop_assert_eq!(teardown(&mut host, &lines, BOOT, &mut |_, _| {}), Ok(()));
            prop_assert_eq!(&host.mounts, &foreign());
            prop_assert!(host.jails.is_empty() && host.dirs.is_empty());
        }
    }

    #[test]
    fn a_reused_id_naming_another_mount_is_not_unmounted() {
        let mut host = FakeHost { mounts: foreign(), ..FakeHost::default() };
        // The record's mount is gone; its id now names a host filesystem.
        let lines = vec![
            Line::Owner { uid: 1, boot: BOOT.into() },
            Line::Begin(Step::Mount { target: "/home/u/f0".into(), in_jail: true }),
            Line::Mounted { fsid: [901, 1], fstype: "nullfs".into(), on: "/home/u/f0".into() },
        ];
        assert_eq!(teardown(&mut host, &lines, BOOT, &mut |_, _| {}), Ok(()));
        assert_eq!(host.mounts, foreign(), "a host filesystem was unmounted");
        assert_eq!(owner(&lines), Some(1));
    }

    #[test]
    fn a_mount_written_as_unmounted_is_never_acted_on_again() {
        // Run A's teardown unmounted its file mount; the id is now another
        // run's mount of the same jail-relative name.
        let mut host = FakeHost::default();
        let theirs = MountEntry { fsid: [5, 7], fstype: "nullfs".into(), on: "/home/u/p/.git/config".into() };
        host.mounts.push(theirs.clone());
        let lines = vec![
            Line::Owner { uid: 1, boot: BOOT.into() },
            Line::Begin(Step::Mount { target: "/home/u/p/.git/config".into(), in_jail: true }),
            Line::Mounted { fsid: [5, 7], fstype: "nullfs".into(), on: "/home/u/p/.git/config".into() },
            Line::Unmounted { fsid: [5, 7], fstype: "nullfs".into(), on: "/home/u/p/.git/config".into() },
        ];
        assert_eq!(teardown(&mut host, &lines, BOOT, &mut |_, _| panic!("unmounted again")), Ok(()));
        assert_eq!(host.mounts, std::slice::from_ref(&theirs));
        // A failed unmount's line is cancelled by its `Kept`: the mount is
        // still ours, and goes on the next sweep.
        let mut kept = lines.clone();
        kept.push(Line::Kept { fsid: [5, 7], fstype: "nullfs".into(), on: "/home/u/p/.git/config".into() });
        assert_eq!(teardown(&mut host, &kept, BOOT, &mut |_, _| {}), Ok(()));
        assert!(host.mounts.is_empty());
    }

    #[test]
    fn a_record_from_an_earlier_boot_unmounts_nothing() {
        let mut host = FakeHost { mounts: foreign(), ..FakeHost::default() };
        host.dirs.insert(ROOT.into());
        let lines = vec![
            Line::Owner { uid: 1, boot: "0123456789abcdef0123456789abcdef".into() },
            Line::Begin(Step::Dir { path: ROOT.into() }),
            Line::Begin(Step::Mount { target: "/home/u/f0".into(), in_jail: false }),
        ];
        assert_eq!(teardown(&mut host, &lines, BOOT, &mut |_, _| {}), Ok(()));
        assert_eq!(host.mounts, foreign());
        assert!(host.dirs.is_empty());
    }

    #[test]
    fn a_run_is_ready_only_once_its_line_is_written() {
        let mut lines = vec![Line::Owner { uid: 1, boot: BOOT.into() }, Line::Begin(Step::Jail { name: "ssai-r".into() })];
        assert!(!ready(&lines), "ready before the build ended");
        lines.push(Line::Ready);
        assert!(ready(&lines));
        lines.push(Line::Ending);
        assert!(!ready(&lines), "ready while it is being removed");
    }

    #[test]
    fn a_torn_last_line_is_dropped() {
        let text = "{\"line\":\"owner\",\"uid\":3,\"boot\":\"ab\"}\n{\"line\":\"begin\",\"step\":\"dir\",\"pa";
        assert_eq!(parse(text), vec![Line::Owner { uid: 3, boot: "ab".into() }]);
    }
}
