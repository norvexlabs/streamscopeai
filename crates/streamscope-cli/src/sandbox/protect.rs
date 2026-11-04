//! What a confined agent may write in its project and what it must not: the
//! one resolver every backend reads (Linux, macOS, the docker tier, Windows).
//!
//! The agent writes the project, `.git` included — it commits. But some files
//! there run as the developer, or steer what runs as them, the next time the
//! developer works in the project outside the sandbox: git's hooks, git's
//! config (`core.hooksPath`, `core.fsmonitor`, aliases, filters), the pointer
//! files that say where a worktree's git dir is, and `ssai`'s own project
//! state (`.streamscopeai/`, which `ssai sync` / `forget` / `restore` act on).
//! Those are protected. A linked worktree keeps its git dirs outside the
//! project; the agent needs to write them to commit, so they are granted.
//!
//! The resolver reads the layout only — never git's index or objects — and
//! never follows a symlink out of what it names. A repository nested inside
//! the project that is neither the project's own nor one of its submodules
//! (a vendored checkout) is not found: a documented residual.

use std::path::{Component, Path, PathBuf};

/// How a protected path is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// A folder nothing may be created in, changed in or removed from, and
    /// which may not itself be removed or renamed (a hooks folder). Created
    /// empty by [`ProjectGrants::prepare`] when absent, so it can be held.
    Tree,
    /// A file that may be read but not changed, replaced or removed. Held only
    /// when it exists.
    File,
    /// A folder whose contents stay writable but which may not itself be
    /// removed or renamed: replacing a git dir wholesale would bring a hooks
    /// folder of the agent's.
    Node,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protected {
    pub path: PathBuf,
    pub guard: Guard,
}

/// The project's grants beyond the project root itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectGrants {
    /// Folders outside the project the agent writes: a linked worktree's
    /// common git dir (its own git dir is inside it).
    pub extra_rw: Vec<PathBuf>,
    /// Folders the agent may look at (their attributes) but not list: a
    /// linked worktree's main checkout, which git stats. Only Windows needs
    /// the grant: the other backends let every path be stat'ed.
    pub stat_only: Vec<PathBuf>,
    /// What the agent must not change, inside the project or `extra_rw`.
    pub protected: Vec<Protected>,
}

impl ProjectGrants {
    /// Create each absent [`Guard::Tree`] folder (empty), so a backend can
    /// hold it: an absent hooks folder the agent could create would be as
    /// good as a writable one. Run as the developer, before the launch.
    pub fn prepare(&self) -> std::io::Result<()> {
        for p in &self.protected {
            if p.guard == Guard::Tree && std::fs::symlink_metadata(&p.path).is_err() {
                std::fs::create_dir_all(&p.path)?;
            }
        }
        Ok(())
    }

    /// The protected paths a backend can hold now: every Tree and Node, and
    /// the Files that exist.
    #[cfg_attr(target_os = "macos", allow(dead_code, reason = "macOS holds every protected path, an absent file included"))]
    pub fn held(&self) -> impl Iterator<Item = &Protected> {
        self.protected.iter().filter(|p| p.guard != Guard::File || p.path.is_file())
    }
}

/// `ssai`'s own project state folder.
pub const PROJECT_STATE_DIR: &str = ".streamscopeai";
/// How many folders deep under `modules/` the walk looks for submodule git
/// dirs (a submodule's name's segments and nesting both count).
const MAX_MODULE_DEPTH: usize = 8;

/// Resolve the grants for the project at `root` (absolute).
pub fn resolve(root: &Path) -> ProjectGrants {
    let mut out = ProjectGrants::default();
    // Held only where it exists: created in a folder that is not a project
    // (a globally provisioned client run from anywhere), it would make that
    // folder a project for every later command below it.
    let state = root.join(PROJECT_STATE_DIR);
    if std::fs::symlink_metadata(&state).is_ok() {
        out.protected.push(Protected { path: state, guard: Guard::Tree });
    }
    let dotgit = root.join(".git");
    let Ok(meta) = std::fs::symlink_metadata(&dotgit) else { return out };
    let gitdir = if meta.is_dir() {
        dotgit.clone()
    } else if meta.is_file() {
        let Some(target) = std::fs::read_to_string(&dotgit).ok().and_then(|t| gitdir_pointer(&t)) else {
            return out;
        };
        // The pointer itself: rewritten, it would send the developer's git to
        // a git dir of the agent's making.
        out.protected.push(Protected { path: dotgit.clone(), guard: Guard::File });
        absolute(root, &target)
    } else {
        // A symlinked `.git` is the developer's arrangement: nothing is
        // granted through it, and nothing it names is held.
        return out;
    };
    let mut common = match std::fs::read_to_string(gitdir.join("commondir")) {
        Ok(text) if !text.trim().is_empty() => {
            out.protected.push(Protected { path: gitdir.join("commondir"), guard: Guard::File });
            absolute(&gitdir, text.trim())
        }
        _ => gitdir.clone(),
    };
    if !common.starts_with(root) {
        // Granted only when the layout is git's own for a linked worktree,
        // which the agent cannot forge: it writes the project, so a pointer
        // there may be its own, aimed at any folder (the whole profile).
        if meta.is_file() && is_linked_worktree(root, &gitdir, &common) {
            out.extra_rw.push(common.clone());
            if common.file_name().is_some_and(|n| n == ".git")
                && let Some(main) = common.parent()
            {
                out.stat_only.push(main.to_path_buf());
            }
        } else if meta.is_dir() {
            // A `commondir` in the project's own `.git` sends git elsewhere:
            // nothing there is granted, and the git dir is held as itself.
            common = gitdir.clone();
        } else {
            return out;
        }
    }
    out.protected.push(Protected { path: gitdir.clone(), guard: Guard::Node });
    if common != gitdir {
        out.protected.push(Protected { path: common.clone(), guard: Guard::Node });
        out.protected.push(Protected { path: gitdir.join("config.worktree"), guard: Guard::File });
    }
    hold_git_dir(&common, &mut out);
    for dir in [&gitdir, &common] {
        for hooks in hooks_paths(dir, root) {
            push_unique(&mut out.protected, Protected { path: hooks, guard: Guard::Tree });
        }
    }
    hold_modules(&common.join("modules"), 0, &mut out);
    // Nothing is held outside what the agent may write: a path read from a
    // file it can write (a submodule's `core.worktree`, a `core.hooksPath`)
    // may name any folder, which a backend would then create or change.
    let reach: Vec<PathBuf> = std::iter::once(root.to_path_buf()).chain(out.extra_rw.iter().cloned()).collect();
    out.protected.retain(|p| reach.iter().any(|r| p.path.starts_with(r)));
    // A link is not held: holding it would hold (or, by name, write to) what
    // it points at, and renaming it would not move the folder git uses.
    out.protected.retain(|p| !std::fs::symlink_metadata(&p.path).is_ok_and(|m| m.file_type().is_symlink()));
    // A held folder or file deeper than one level (a `core.hooksPath` of
    // `scripts/hooks`, a submodule checkout's `.git`) could be replaced by
    // renaming a folder above it: each folder between it and the root (or
    // `extra_rw`) is held against that.
    let mut above = Vec::new();
    // (A file only where it exists: a backend holds a `Node` that is there.)
    for held in out.protected.iter().filter(|p| p.guard == Guard::Tree || (p.guard == Guard::File && p.path.is_file())) {
        let Some(base) = reach.iter().find(|r| held.path.starts_with(r)) else { continue };
        let mut at = held.path.parent();
        while let Some(dir) = at.filter(|d| *d != base.as_path() && d.starts_with(base)) {
            above.push(Protected { path: dir.to_path_buf(), guard: Guard::Node });
            at = dir.parent();
        }
    }
    for p in above {
        push_unique(&mut out.protected, p);
    }
    out
}

/// Whether `gitdir` (outside the project at `root`) is a linked worktree's
/// git dir in `common` as git lays it out: `<common>/worktrees/<name>`, its
/// `gitdir` file naming this project's `.git` back, `common` a repository
/// (a `HEAD` and `objects/`). Every file it reads is outside the project.
fn is_linked_worktree(root: &Path, gitdir: &Path, common: &Path) -> bool {
    let laid_out = gitdir.parent().is_some_and(|w| w.file_name().is_some_and(|n| n == "worktrees") && w.parent() == Some(common));
    let back = std::fs::read_to_string(gitdir.join("gitdir"))
        .ok()
        .map(|t| absolute(gitdir, t.trim()))
        .is_some_and(|b| b == root.join(".git") || dunce::canonicalize(root.join(".git")).is_ok_and(|g| g == b));
    laid_out && back && common.join("HEAD").is_file() && common.join("objects").is_dir() && !gitdir.starts_with(root)
}

/// A git dir's hooks folder, config and worktree config.
/// Also its `commondir`, and its linked worktrees' git dirs: the
/// `worktrees` folder and each one in it may not be renamed (a replaced one
/// would bring the agent's `commondir`), and their link files are held.
fn hold_git_dir(dir: &Path, out: &mut ProjectGrants) {
    push_unique(&mut out.protected, Protected { path: dir.join("hooks"), guard: Guard::Tree });
    for file in ["config", "config.worktree", "commondir"] {
        push_unique(&mut out.protected, Protected { path: dir.join(file), guard: Guard::File });
    }
    let worktrees = dir.join("worktrees");
    let Ok(entries) = std::fs::read_dir(&worktrees) else { return };
    push_unique(&mut out.protected, Protected { path: worktrees, guard: Guard::Node });
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let wt = entry.path();
        for file in ["commondir", "gitdir", "config.worktree"] {
            push_unique(&mut out.protected, Protected { path: wt.join(file), guard: Guard::File });
        }
        push_unique(&mut out.protected, Protected { path: wt, guard: Guard::Node });
    }
}

/// Each submodule's git dir under `modules` (they nest: `modules/a/modules/b`),
/// held like the project's, and the `.git` pointer of its checkout.
fn hold_modules(modules: &Path, depth: usize, out: &mut ProjectGrants) {
    if depth >= MAX_MODULE_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(modules) else { return };
    // Each folder on the way to a submodule's git dir, and the git dir, may
    // not be renamed: one put in its place would hold the agent's hooks.
    push_unique(&mut out.protected, Protected { path: modules.to_path_buf(), guard: Guard::Node });
    for entry in entries.flatten() {
        let dir = entry.path();
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        // A git dir has a HEAD; a folder without one is a submodule name's
        // path segment (`modules/libs/a`).
        if !dir.join("HEAD").is_file() {
            hold_modules(&dir, depth + 1, out);
            continue;
        }
        let config = std::fs::read_to_string(dir.join("config")).unwrap_or_default();
        let work_tree = config_value(&config, "core", "worktree").map(|w| absolute(&dir, &w));
        hold_git_dir(&dir, out);
        push_unique(&mut out.protected, Protected { path: dir.clone(), guard: Guard::Node });
        if let Some(tree) = &work_tree {
            push_unique(&mut out.protected, Protected { path: tree.join(".git"), guard: Guard::File });
            for hooks in hooks_paths(&dir, tree) {
                push_unique(&mut out.protected, Protected { path: hooks, guard: Guard::Tree });
            }
        }
        hold_modules(&dir.join("modules"), depth + 1, out);
    }
}

/// The folders a git dir's `config` and `config.worktree` name as
/// `core.hooksPath` (relative to `work_tree`, where git resolves them).
fn hooks_paths(dir: &Path, work_tree: &Path) -> Vec<PathBuf> {
    // Each value either file names is held: which one git uses depends on
    // `extensions.worktreeConfig`, and a `config.worktree` the agent wrote
    // must not hide the folder `config` names.
    ["config.worktree", "config"]
        .iter()
        .filter_map(|f| {
            let text = std::fs::read_to_string(dir.join(f)).ok()?;
            let value = config_value(&text, "core", "hookspath")?;
            let value = match value.strip_prefix("~/") {
                Some(rest) => crate::state::home_dir().ok()?.join(rest),
                None => PathBuf::from(value),
            };
            Some(absolute(work_tree, &value.to_string_lossy()))
        })
        .collect()
}

/// The path a `.git` file points at (`gitdir: <path>`).
fn gitdir_pointer(text: &str) -> Option<String> {
    let line = text.lines().next()?.trim();
    let path = line.strip_prefix("gitdir:")?.trim();
    (!path.is_empty()).then(|| path.to_string())
}

/// The last value of `key` in `[section]` of a git config text (keys and
/// section names compare case-insensitively; a subsection such as
/// `[core "x"]` is not the section). Best effort: quotes around the value are
/// dropped, escapes and `include` are not followed.
fn config_value(text: &str, section: &str, key: &str) -> Option<String> {
    let mut current = String::new();
    let mut found = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        let mut line = line;
        if let Some(rest) = line.strip_prefix('[') {
            let (header, after) = rest.split_once(']').unwrap_or((rest, ""));
            current = header.trim().to_ascii_lowercase();
            // A variable may follow the header on its line (`[core] a = b`).
            line = after.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
        }
        if current != section {
            continue;
        }
        let (k, v) = line.split_once('=').map_or((line, ""), |(k, v)| (k.trim(), v.trim()));
        if k.eq_ignore_ascii_case(key) {
            let v = v.split([';', '#']).next().unwrap_or("").trim();
            found = Some(v.trim_matches('"').to_string());
        }
    }
    found.filter(|v| !v.is_empty())
}

/// `rel` against `base` when relative, then made canonical where it exists
/// (the backends match real paths) and lexically clean where it does not.
fn absolute(base: &Path, rel: &str) -> PathBuf {
    let joined = base.join(rel);
    dunce::canonicalize(&joined).unwrap_or_else(|_| lexical(&joined))
}

fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn push_unique(list: &mut Vec<Protected>, item: Protected) {
    if !list.iter().any(|p| p.path == item.path) {
        list.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh folder under the temp dir, canonical (macOS's `/var` is a link).
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ssai-protect-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dunce::canonicalize(&dir).unwrap()
    }

    fn git_dir(dir: &Path) {
        std::fs::create_dir_all(dir.join("hooks")).unwrap();
        std::fs::create_dir_all(dir.join("objects")).unwrap();
        std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(dir.join("config"), "[core]\n\tbare = false\n").unwrap();
    }

    fn guard_of(g: &ProjectGrants, path: &Path) -> Option<Guard> {
        g.protected.iter().find(|p| p.path == path).map(|p| p.guard)
    }

    #[test]
    fn a_plain_checkout_holds_hooks_config_and_the_git_dir() {
        let root = scratch("plain");
        git_dir(&root.join(".git"));
        std::fs::create_dir_all(root.join(PROJECT_STATE_DIR)).unwrap();
        std::fs::create_dir_all(root.join(".git/worktrees/other")).unwrap();
        let g = resolve(&root);
        // The other worktrees' git dirs may not be renamed, nor their links changed.
        assert_eq!(guard_of(&g, &root.join(".git/worktrees")), Some(Guard::Node));
        assert_eq!(guard_of(&g, &root.join(".git/worktrees/other")), Some(Guard::Node));
        assert_eq!(guard_of(&g, &root.join(".git/worktrees/other/commondir")), Some(Guard::File));
        assert_eq!(guard_of(&g, &root.join(".git/commondir")), Some(Guard::File));
        assert_eq!(guard_of(&g, &root.join(".git/hooks")), Some(Guard::Tree));
        assert_eq!(guard_of(&g, &root.join(".git/config")), Some(Guard::File));
        assert_eq!(guard_of(&g, &root.join(".git")), Some(Guard::Node));
        assert_eq!(guard_of(&g, &root.join(PROJECT_STATE_DIR)), Some(Guard::Tree));
        assert!(g.extra_rw.is_empty() && g.stat_only.is_empty(), "{g:?}");
        // config.worktree is listed but held only once it exists.
        assert!(!g.held().any(|p| p.path.ends_with("config.worktree")));
        std::fs::write(root.join(".git/config.worktree"), "").unwrap();
        assert!(g.held().any(|p| p.path.ends_with("config.worktree")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_project_without_git_holds_only_its_state_folder() {
        let root = scratch("nogit");
        // Absent, it is not held (nor created): the folder is no project.
        assert!(resolve(&root).protected.is_empty());
        assert!(!root.join(PROJECT_STATE_DIR).exists());
        std::fs::create_dir_all(root.join(PROJECT_STATE_DIR)).unwrap();
        let g = resolve(&root);
        assert_eq!(g.protected, vec![Protected { path: root.join(PROJECT_STATE_DIR), guard: Guard::Tree }]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_linked_worktree_grants_the_common_git_dir_and_holds_its_pointers() {
        let base = scratch("worktree");
        let main = base.join("main");
        let common = main.join(".git");
        git_dir(&common);
        let wt_git = common.join("worktrees/feature");
        std::fs::create_dir_all(&wt_git).unwrap();
        std::fs::write(wt_git.join("commondir"), "../..\n").unwrap();
        std::fs::write(wt_git.join("HEAD"), "ref: refs/heads/feature\n").unwrap();
        let root = base.join("feature");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".git"), format!("gitdir: {}\n", wt_git.display())).unwrap();
        std::fs::write(wt_git.join("gitdir"), format!("{}\n", root.join(".git").display())).unwrap();

        let g = resolve(&root);
        assert_eq!(g.extra_rw, vec![common.clone()]);
        assert_eq!(g.stat_only, vec![main.clone()]);
        assert_eq!(guard_of(&g, &root.join(".git")), Some(Guard::File));
        assert_eq!(guard_of(&g, &wt_git.join("commondir")), Some(Guard::File));
        assert_eq!(guard_of(&g, &wt_git), Some(Guard::Node));
        assert_eq!(guard_of(&g, &common), Some(Guard::Node));
        assert_eq!(guard_of(&g, &common.join("hooks")), Some(Guard::Tree));
        assert_eq!(guard_of(&g, &common.join("config")), Some(Guard::File));
        assert_eq!(guard_of(&g, &wt_git.join("config.worktree")), Some(Guard::File));
        // A relative pointer resolves against the worktree.
        std::fs::write(root.join(".git"), "gitdir: ../main/.git/worktrees/feature\n").unwrap();
        assert_eq!(resolve(&root).extra_rw, vec![common]);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A pointer the agent could have written grants nothing outside the
    /// project: a `.git` file aimed at a folder that is not a worktree git dir
    /// naming this project back, a `commondir` in a plain `.git`, a hooks path
    /// or submodule work tree elsewhere. The real layout (the test above) is
    /// the positive control.
    #[test]
    fn a_forged_link_grants_and_holds_nothing_outside_the_project() {
        let base = scratch("forged");
        let outside = base.join("profile");
        std::fs::create_dir_all(outside.join("worktrees/x")).unwrap();
        let root = base.join("app");
        std::fs::create_dir_all(&root).unwrap();
        // A `.git` file aimed straight at the folder, and one at a
        // worktree-shaped folder with no repository and no back pointer.
        for target in [outside.clone(), outside.join("worktrees/x")] {
            std::fs::write(root.join(".git"), format!("gitdir: {}\n", target.display())).unwrap();
            let g = resolve(&root);
            assert!(g.extra_rw.is_empty() && g.stat_only.is_empty(), "{target:?}: {g:?}");
            assert!(g.protected.iter().all(|p| p.path.starts_with(&root)), "{g:?}");
        }
        // The worktree shape, but its back pointer names another checkout.
        git_dir(&outside);
        std::fs::write(outside.join("worktrees/x/commondir"), "../..\n").unwrap();
        std::fs::write(outside.join("worktrees/x/gitdir"), "/elsewhere/.git\n").unwrap();
        assert!(resolve(&root).extra_rw.is_empty());

        // A plain `.git` with a `commondir` out, a hooks path and a submodule
        // work tree out: the git dir is held as itself, nothing outside.
        std::fs::remove_file(root.join(".git")).unwrap();
        git_dir(&root.join(".git"));
        std::fs::write(root.join(".git/commondir"), format!("{}\n", outside.display())).unwrap();
        std::fs::write(root.join(".git/config"), format!("[core]\n\thooksPath = {}\n", outside.join("h").display())).unwrap();
        let module = root.join(".git/modules/m");
        git_dir(&module);
        std::fs::write(module.join("config"), format!("[core]\n\tworktree = {}\n", outside.display())).unwrap();
        let g = resolve(&root);
        assert!(g.extra_rw.is_empty(), "{g:?}");
        assert_eq!(guard_of(&g, &root.join(".git/hooks")), Some(Guard::Tree));
        assert_eq!(guard_of(&g, &module.join("hooks")), Some(Guard::Tree));
        assert!(g.protected.iter().all(|p| p.path.starts_with(&root)), "{g:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_hooks_path_in_the_work_tree_is_held_too() {
        let root = scratch("hookspath");
        git_dir(&root.join(".git"));
        std::fs::write(root.join(".git/config"), "[core]\n\tbare = false\n\thooksPath = .husky\n[core \"x\"]\n\thooksPath = elsewhere\n").unwrap();
        let g = resolve(&root);
        assert_eq!(guard_of(&g, &root.join(".husky")), Some(Guard::Tree));
        // A deeper hooks path: the folders above it cannot be renamed.
        std::fs::write(root.join(".git/config"), "[core]\n\thooksPath = scripts/git/hooks\n").unwrap();
        let deep = resolve(&root);
        assert_eq!(guard_of(&deep, &root.join("scripts/git/hooks")), Some(Guard::Tree));
        assert_eq!(guard_of(&deep, &root.join("scripts/git")), Some(Guard::Node));
        assert_eq!(guard_of(&deep, &root.join("scripts")), Some(Guard::Node));
        assert_eq!(guard_of(&deep, &root), None);
        std::fs::write(root.join(".git/config"), "[core]\n\tbare = false\n\thooksPath = .husky\n[core \"x\"]\n\thooksPath = elsewhere\n").unwrap();
        assert_eq!(guard_of(&g, &root.join("elsewhere")), None);
        // Absent, it is created empty so a backend can hold it.
        assert!(!root.join(".husky").exists());
        g.prepare().unwrap();
        assert!(root.join(".husky").is_dir() && root.join(".git/hooks").is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn submodules_are_held_with_their_checkout_pointers() {
        let root = scratch("submodules");
        git_dir(&root.join(".git"));
        let module = root.join(".git/modules/libs/a");
        git_dir(&module);
        std::fs::write(module.join("config"), "[core]\n\tworktree = ../../../../libs/a\n").unwrap();
        std::fs::create_dir_all(root.join("libs/a")).unwrap();
        std::fs::write(root.join("libs/a/.git"), "gitdir: ../../.git/modules/libs/a\n").unwrap();
        let nested = module.join("modules/b");
        git_dir(&nested);

        let g = resolve(&root);
        assert_eq!(guard_of(&g, &module.join("hooks")), Some(Guard::Tree));
        assert_eq!(guard_of(&g, &module.join("config")), Some(Guard::File));
        assert_eq!(guard_of(&g, &root.join("libs/a/.git")), Some(Guard::File));
        // The checkout's pointer cannot be swapped by renaming a folder above it.
        assert_eq!(guard_of(&g, &root.join("libs/a")), Some(Guard::Node));
        assert_eq!(guard_of(&g, &root.join("libs")), Some(Guard::Node));
        assert_eq!(guard_of(&g, &nested.join("hooks")), Some(Guard::Tree));
        // Every folder on the way to a submodule's git dir, and the git dir, is held against a rename.
        for node in [root.join(".git/modules"), root.join(".git/modules/libs"), module.clone(), module.join("modules"), nested.clone()] {
            assert_eq!(guard_of(&g, &node), Some(Guard::Node), "{node:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn config_values_are_read_like_git_reads_the_common_forms() {
        assert_eq!(config_value("[core] hooksPath = .githooks\n", "core", "hookspath").as_deref(), Some(".githooks"));
        let text = "# c\n[Core]\n  HooksPath = \"a b\" ; note\n[core \"sub\"]\nhookspath = no\n[other]\nhookspath = no\n";
        assert_eq!(config_value(text, "core", "hookspath").as_deref(), Some("a b"));
        assert_eq!(config_value("[core]\nhooksPath = x\nhooksPath = y\n", "core", "hookspath").as_deref(), Some("y"));
        assert_eq!(config_value("[core]\nhooksPath =\n", "core", "hookspath"), None);
        assert_eq!(gitdir_pointer("gitdir: /x/y\n").as_deref(), Some("/x/y"));
        assert_eq!(gitdir_pointer("nonsense"), None);
    }
}
