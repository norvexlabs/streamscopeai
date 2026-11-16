//! The docker tier's images and volumes on this machine, as the projects'
//! records name them: what each project's last run used, `ssai sandbox
//! status`, and `ssai sandbox prune [--project]`.
//!
//! Invariants to keep:
//! - A run removes no image: disk is freed on the developer's request only.
//!   A removal while other runs pull, build or start races them.
//! - Removal is `podman rmi` WITHOUT force, always: podman itself then keeps
//!   an image a container uses.
//! - Only an image the sandbox made is named for removal, and a named one only
//!   by our own names (`localhost/ssai-base:`, `localhost/ssai-agent-`): an
//!   image the developer builds from one inherits its [`BASE_LABEL`], so the
//!   label alone never names one. By id: an image so labelled left without a
//!   name, and a registry image the sandbox's own pull added ([`mark_pulled`])
//!   that carries one name only (the one it was pulled under; podman deletes
//!   a single-named image by id, and refuses a multi-named one).
//! - A record that cannot be read stops a prune, naming its file: an
//!   unanswered question is never read as "no project needs it".

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

use sha2::{Digest, Sha256};

use super::prepare::BASE_LABEL;

/// What a project's last run used.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Record {
    /// `image:<reference>`, or a build's `localhost/ssai-base:<hash>` tag.
    pub source: String,
    /// The run had an engine inside.
    pub engine: bool,
    /// The project's root; `None` when the record does not say.
    pub project: Option<PathBuf>,
}

impl Record {
    /// Line by line: the source, `engine`|`no-engine`, then the project's
    /// root (the rest of the file, whatever it holds).
    fn parse(bytes: &[u8]) -> Self {
        use std::os::unix::ffi::OsStrExt;
        let mut parts = bytes.splitn(3, |b| *b == b'\n');
        let mut line = || parts.next().map(|l| String::from_utf8_lossy(l).trim().to_string());
        let source = line().unwrap_or_default();
        let engine = line().is_some_and(|l| l == "engine");
        let project = parts.next().filter(|p| !p.is_empty()).map(|p| PathBuf::from(std::ffi::OsStr::from_bytes(p)));
        Self { source, engine, project }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!("{}\n{}\n", self.source, if self.engine { "engine" } else { "no-engine" }).into_bytes();
        if let Some(p) = &self.project {
            out.extend_from_slice(p.as_os_str().as_encoded_bytes());
        }
        out
    }

    /// The image's name: the reference, or the build's tag.
    pub fn reference(&self) -> &str {
        self.source.strip_prefix("image:").unwrap_or(&self.source)
    }
}

fn records_dir() -> Result<PathBuf> {
    Ok(crate::state::cache_dir()?.join("sandbox-builds"))
}

fn record_path(root: &Path) -> Result<PathBuf> {
    let mut h = Sha256::new();
    h.update(root.as_os_str().as_encoded_bytes());
    Ok(records_dir()?.join(hex::encode(&h.finalize()[..12])))
}

/// The project's record, `None` when there is none; an unreadable record is
/// an error, never "none" (it is what a changed image is compared with).
pub fn read(root: &Path) -> Result<Option<Record>> {
    let path = record_path(root)?;
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(Record::parse(&bytes))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Fails closed: a record that cannot be written stops the run, rather than
/// leaving every later build unasked. Written whole (a temporary file renamed
/// over it): a reader never sees half of one.
pub fn write(root: &Path, record: &Record) -> Result<()> {
    let path = record_path(root)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).context("create the sandbox's build records")?;
    let record = Record { project: Some(root.to_path_buf()), ..record.clone() };
    let part = dir.join(format!(".part-{}-{}", std::process::id(), hex::encode(rand::random::<[u8; 4]>())));
    std::fs::write(&part, record.to_bytes())
        .and_then(|()| std::fs::rename(&part, &path))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&part);
        })
        .with_context(|| format!("record the project's image in {}", path.display()))
}

/// Every project's record, with its file. Fails closed: a records folder or
/// a record that cannot be read is an error, never "no project".
fn all() -> Result<Vec<(PathBuf, Record)>> {
    let dir = records_dir()?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.with_context(|| format!("read {}", dir.display()))?.path();
        if path.file_name().is_some_and(|n| n.as_encoded_bytes().starts_with(b".part-")) {
            continue;
        }
        match std::fs::read(&path) {
            Ok(bytes) => out.push((path, Record::parse(&bytes))),
            // Removed since it was listed.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        }
    }
    Ok(out)
}

fn pulled_dir() -> Result<PathBuf> {
    Ok(crate::state::cache_dir()?.join("sandbox-pulled"))
}

/// Mark `id` as added to this machine by the sandbox's own pull: one empty
/// file per id, created whole, so concurrent runs never lose one another's.
/// Best effort: an image left unmarked is only ever kept.
pub fn mark_pulled(id: &str) {
    let id = id.trim_start_matches("sha256:");
    if let Ok(dir) = pulled_dir()
        && !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_hexdigit())
        && std::fs::create_dir_all(&dir).is_ok()
    {
        let _ = std::fs::File::create(dir.join(id));
    }
}

/// Whether the sandbox's pull added `id`.
pub fn pulled_by_sandbox(id: &str) -> bool {
    pulled_dir().is_ok_and(|d| d.join(id.trim_start_matches("sha256:")).is_file())
}

fn marked() -> BTreeSet<String> {
    let Ok(dir) = pulled_dir().and_then(|d| Ok(std::fs::read_dir(d)?)) else { return BTreeSet::new() };
    dir.flatten().filter_map(|e| e.file_name().into_string().ok()).collect()
}

/// One image as `podman images --format json` lists it.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Image {
    id: String,
    #[serde(default)]
    names: Option<Vec<String>>,
    #[serde(default)]
    labels: Option<BTreeMap<String, String>>,
    #[serde(default)]
    size: u64,
}

impl Image {
    fn names(&self) -> &[String] {
        self.names.as_deref().unwrap_or_default()
    }

    /// The base an agent layer names (`project` on a build's own base).
    fn base_label(&self) -> Option<&str> {
        self.labels.as_ref()?.get(BASE_LABEL).map(|b| b.trim_start_matches("sha256:"))
    }
}

fn images() -> Result<Vec<Image>> {
    let out = Command::new("podman")
        .args(["images", "--format", "json"])
        .stdin(Stdio::null())
        .output()
        .context("run podman images")?;
    if !out.status.success() {
        bail!("list podman images: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    serde_json::from_slice(&out.stdout).context("read podman's image list")
}

/// `podman rmi` without force (see the module's invariants): whether it went.
fn rmi(name: &str) -> bool {
    Command::new("podman")
        .args(["rmi", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The id `reference` names on this machine, as podman resolves it (a short
/// name included); `None` when it names none; an error when podman did not
/// answer.
fn resolve(reference: &str) -> Result<Option<String>> {
    let exists = Command::new("podman")
        .args(["image", "exists", reference])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("run podman image exists")?;
    match exists.code() {
        Some(0) => {}
        Some(1) => return Ok(None),
        _ => bail!("podman could not say whether {reference} exists ({exists})"),
    }
    let out = Command::new("podman")
        .args(["image", "inspect", "--format", "{{.Id}}", reference])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("run podman image inspect")?;
    let id = String::from_utf8_lossy(&out.stdout).trim().trim_start_matches("sha256:").to_string();
    if !out.status.success() || id.is_empty() {
        bail!("podman could not inspect {reference}");
    }
    Ok(Some(id))
}

/// The ids the records' images resolve to now. A record naming nothing, or
/// one of a project whose folder is gone, keeps nothing; one podman cannot
/// answer for is an error naming its file.
fn kept(records: &[(PathBuf, Record)]) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for (file, r) in records {
        if !in_use(r) {
            continue;
        }
        ids.extend(resolve(r.reference()).with_context(|| format!("the sandbox's record {}", file.display()))?);
    }
    Ok(ids)
}

/// Whether `r` still names a project's image: it names one, and its project
/// is not gone.
fn in_use(r: &Record) -> bool {
    !r.reference().is_empty() && !project_gone(r)
}

/// Whether `r`'s project folder was deleted. A record that does not say its
/// folder is not: nothing proves it gone. `status` lists a record unless this
/// holds, and `kept` keeps none for which it does.
fn project_gone(r: &Record) -> bool {
    r.project.as_ref().is_some_and(|p| matches!(std::fs::symlink_metadata(p), Err(e) if e.kind() == std::io::ErrorKind::NotFound))
}

/// The name every agent layer is tagged under.
pub const LAYER_PREFIX: &str = "localhost/ssai-agent-";
/// The name every build of a project's image is tagged under.
pub const BUILD_PREFIX: &str = "localhost/ssai-base:";

/// Our names of `image` under `prefix`.
fn ours(image: &Image, prefix: &str) -> Vec<String> {
    image.names().iter().filter(|n| n.starts_with(prefix)).cloned().collect()
}

/// What to remove for a base `base_id` going away: its agent layers, by our
/// names, or by id when left without one.
fn layers_on(list: &[Image], base_id: &str) -> Vec<String> {
    let base_id = base_id.trim_start_matches("sha256:");
    list.iter()
        .filter(|i| i.base_label() == Some(base_id))
        .flat_map(|i| if i.names().is_empty() { vec![i.id.clone()] } else { ours(i, LAYER_PREFIX) })
        .collect()
}

/// What `ssai sandbox prune` removes, layers first: every image under our
/// names, every image carrying [`BASE_LABEL`] left without a name, and the
/// registry images the sandbox's pulls added (`pulled`) that carry one name
/// at most, by id.
fn sandbox_made(list: &[Image], pulled: &BTreeSet<String>) -> Vec<String> {
    let (mut layers, mut rest) = (Vec::new(), Vec::new());
    for image in list {
        let named_layers = ours(image, LAYER_PREFIX);
        let named_builds = ours(image, BUILD_PREFIX);
        if image.names().is_empty() && image.base_label().is_some() {
            if image.base_label() == Some("project") { &mut rest } else { &mut layers }.push(image.id.clone());
        } else if !named_layers.is_empty() {
            layers.extend(named_layers);
        } else if !named_builds.is_empty() {
            rest.extend(named_builds);
        } else if pulled.contains(&image.id) && image.names().len() <= 1 {
            rest.push(image.id.clone());
        }
    }
    layers.extend(rest);
    layers
}

/// Drop the pull marks of images no longer on this machine.
fn forget_pulls_gone(pulled: &BTreeSet<String>) {
    let (Ok(list), Ok(dir)) = (images(), pulled_dir()) else { return };
    let present: BTreeSet<&str> = list.iter().map(|i| i.id.as_str()).collect();
    for id in pulled.iter().filter(|id| !present.contains(id.as_str())) {
        let _ = std::fs::remove_file(dir.join(id));
    }
}

/// The sandbox's volumes of `root` among `all`: every client's home and the
/// engine's cache (their names lead with the project's key).
fn project_volumes(root: &Path, all: &[String]) -> Vec<String> {
    let home = format!("{}-", super::home_volume_prefix(root));
    let engine = super::engine_volume(root);
    all.iter().filter(|v| v.starts_with(&home) || **v == engine).cloned().collect()
}

fn volume_names() -> Result<Vec<String>> {
    let out = Command::new("podman")
        .args(["volume", "ls", "--format", "{{.Name}}"])
        .stdin(Stdio::null())
        .output()
        .context("run podman volume ls")?;
    if !out.status.success() {
        bail!("list podman volumes: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect())
}

/// `podman system df -v`'s volume sizes, in bytes, for the sandbox's volumes.
fn volume_sizes() -> Result<BTreeMap<String, u64>> {
    let out = Command::new("podman")
        .args(["system", "df", "-v"])
        .stdin(Stdio::null())
        .output()
        .context("run podman system df")?;
    if !out.status.success() {
        bail!("podman system df: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(parse_volume_sizes(&String::from_utf8_lossy(&out.stdout)))
}

/// The `Local Volumes` section's `NAME LINKS SIZE` rows of the sandbox's
/// volumes (`ssai-home-`, `ssai-engine-`).
fn parse_volume_sizes(text: &str) -> BTreeMap<String, u64> {
    text.lines()
        .skip_while(|l| !l.starts_with("Local Volumes"))
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let [name, _links, size] = f[..] else { return None };
            (name.starts_with("ssai-home-") || name.starts_with("ssai-engine-")).then(|| Some((name.to_string(), parse_size(size)?)))?
        })
        .collect()
}

/// podman's sizes (`0B`, `3MB`, `1.2GB`, `512kB`): decimal units.
fn parse_size(text: &str) -> Option<u64> {
    let split = text.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let (n, unit) = text.split_at(split);
    let mult = match unit.to_ascii_lowercase().as_str() {
        "b" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        _ => return None,
    };
    Some((n.parse::<f64>().ok()? * mult) as u64)
}

fn human(bytes: u64) -> String {
    let b = bytes as f64;
    match bytes {
        0..1_000_000 => format!("{:.0} kB", b / 1e3),
        1_000_000..1_000_000_000 => format!("{:.0} MB", b / 1e6),
        _ => format!("{:.1} GB", b / 1e9),
    }
}

/// `ssai sandbox status`: each project's image, agent layers and volumes,
/// with their sizes (a layer by what it adds to its base), and the total of
/// what `ssai sandbox prune` would remove (an image of the developer's is
/// shown, not counted).
pub fn status() -> Result<()> {
    forget_pulls_gone(&marked());
    let list = images()?;
    let pulled = marked();
    // What the sandbox made, by id: what the total counts.
    let made: BTreeSet<String> = {
        let names = sandbox_made(&list, &pulled);
        list.iter().filter(|i| names.contains(&i.id) || i.names().iter().any(|n| names.contains(n))).map(|i| i.id.clone()).collect()
    };
    let volumes = volume_sizes()?;
    let volume_list: Vec<String> = volumes.keys().cloned().collect();
    // A project whose folder was deleted is not listed: what its record
    // names shows under "Not used by a project".
    let records: Vec<(PathBuf, Record)> = all()?.into_iter().filter(|(_, r)| !project_gone(r)).collect();
    let by_id: BTreeMap<&str, &Image> = list.iter().map(|i| (i.id.as_str(), i)).collect();
    let (mut seen_images, mut seen_volumes) = (BTreeSet::new(), BTreeSet::new());
    let mut total = 0u64;
    let mut count = |id: &str, bytes: u64, seen: &mut BTreeSet<String>| {
        if seen.insert(id.to_string()) {
            total += bytes;
        }
    };
    if records.is_empty() {
        println!("No project on this machine uses the docker sandbox.");
    }
    for (_, record) in &records {
        let project = record.project.as_ref().map_or("(a project the record does not name)".into(), |p| p.display().to_string());
        println!("{project}");
        let name = record.reference();
        let resolved = if name.is_empty() { None } else { resolve(name).ok().flatten() };
        match resolved.and_then(|id| by_id.get(id.as_str()).copied()) {
            Some(image) => {
                let how = if !record.source.starts_with("image:") {
                    "built here"
                } else if pulled_by_sandbox(&image.id) {
                    "pulled by the sandbox"
                } else {
                    "yours, not counted"
                };
                println!("  image   {name} ({how}) — {}", human(image.size));
                if made.contains(&image.id) {
                    count(&image.id, image.size, &mut seen_images);
                } else {
                    seen_images.insert(image.id.clone());
                }
                for layer in list.iter().filter(|i| i.base_label() == Some(image.id.as_str()) && made.contains(&i.id)) {
                    let adds = layer.size.saturating_sub(image.size);
                    let names = if layer.names().is_empty() { "(unnamed)".to_string() } else { layer.names().join(", ") };
                    println!("  layer   {names} — adds {}", human(adds));
                    count(&layer.id, adds, &mut seen_images);
                }
            }
            None => println!("  image   {name} — not on this machine"),
        }
        if let Some(root) = &record.project {
            for volume in project_volumes(root, &volume_list) {
                let size = volumes.get(&volume).copied().unwrap_or_default();
                println!("  volume  {volume} — {}", human(size));
                count(&volume, size, &mut seen_volumes);
            }
        }
    }
    let other_images: Vec<&Image> = list.iter().filter(|i| made.contains(&i.id) && !seen_images.contains(&i.id)).collect();
    let other_volumes: Vec<(&String, &u64)> = volumes.iter().filter(|(v, _)| !seen_volumes.contains(*v)).collect();
    if !other_images.is_empty() || !other_volumes.is_empty() {
        println!("Not used by a project:");
        for image in other_images {
            let base = image.base_label().and_then(|b| by_id.get(b)).map_or(0, |b| b.size);
            let adds = image.size.saturating_sub(base);
            let id = image.id.get(..12).unwrap_or(&image.id);
            let names = if image.names().is_empty() { id.to_string() } else { image.names().join(", ") };
            println!("  image   {names} — {}", human(adds));
            count(&image.id, adds, &mut seen_images);
        }
        for (volume, size) in other_volumes {
            println!("  volume  {volume} — {}", human(*size));
            count(volume, *size, &mut seen_volumes);
        }
    }
    println!(
        "Total: about {} — `ssai sandbox prune --project [<dir>]` removes one project's, `ssai sandbox prune` all of them.",
        human(total)
    );
    Ok(())
}

/// `ssai sandbox prune --project`: the project's image when the sandbox
/// made it (its build, or a registry image its pull added) and no other
/// project's record names it, the agent layers on it, and the project's
/// volumes. Its record stays: it is what a changed image is compared with.
pub fn prune_project(root: &Path) -> Result<()> {
    let mine = record_path(root)?;
    let records = all()?;
    let record = records.iter().find(|(p, _)| *p == mine).map(|(_, r)| r.clone());
    let others: Vec<(PathBuf, Record)> = records.into_iter().filter(|(p, _)| *p != mine).collect();
    let list = images()?;
    let mut names = Vec::new();
    if let Some(record) = &record
        && let Some(id) = resolve(record.reference())?
        && !kept(&others)?.contains(&id)
    {
        names.extend(layers_on(&list, &id));
        if record.reference().starts_with(BUILD_PREFIX) {
            names.push(record.reference().to_string());
        } else if pulled_by_sandbox(&id) && list.iter().any(|i| i.id == id && i.names().len() <= 1) {
            names.push(id);
        }
    }
    let mut failed = Vec::new();
    let mut images = 0;
    for name in names {
        if rmi(&name) {
            images += 1;
        } else {
            failed.push(name);
        }
    }
    forget_pulls_gone(&marked());
    let mut volumes = 0;
    for volume in project_volumes(root, &volume_names()?) {
        let ok = Command::new("podman")
            .args(["volume", "rm", &volume])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            volumes += 1;
        } else {
            failed.push(volume);
        }
    }
    eprintln!("ssai: removed {images} image(s) and {volumes} volume(s) of {}", root.display());
    if !failed.is_empty() {
        bail!("could not remove (in use, or named by you too): {}", failed.join(", "));
    }
    Ok(())
}

/// `ssai sandbox prune`'s images: everything the sandbox made
/// ([`sandbox_made`]; the caller refuses while a run is live).
/// How many went, and how many stayed (in use, or named by the developer too).
pub fn prune_all() -> Result<(usize, usize)> {
    let pulled = marked();
    let names = sandbox_made(&images()?, &pulled);
    let gone = names.iter().filter(|n| rmi(n)).count();
    forget_pulls_gone(&pulled);
    Ok((gone, names.len() - gone))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(id: &str, names: &[&str], base: Option<&str>, size: u64) -> Image {
        Image {
            id: id.into(),
            names: Some(names.iter().map(|n| n.to_string()).collect()),
            labels: base.map(|b| BTreeMap::from([(BASE_LABEL.to_string(), b.to_string())])),
            size,
        }
    }

    #[test]
    fn a_record_round_trips_with_its_project() {
        let r = Record { source: "image:ubuntu".into(), engine: true, project: Some("/p/with\nnewline".into()) };
        assert_eq!(Record::parse(&r.to_bytes()), r);
        let bare = Record::parse(b"localhost/ssai-base:abc\nno-engine");
        assert_eq!(bare, Record { source: "localhost/ssai-base:abc".into(), ..Record::default() });
        assert_eq!(bare.reference(), "localhost/ssai-base:abc");
        assert_eq!(Record::parse(b"image:docker.io/x:1\n").reference(), "docker.io/x:1");
    }

    #[test]
    fn a_record_is_in_use_while_it_names_an_image_and_its_folder_is_there() {
        let dir = std::env::temp_dir().join(format!("ssai-in-use-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let record = |source: &str, project: Option<PathBuf>| Record { source: source.into(), engine: false, project };
        assert!(in_use(&record("image:ubuntu", Some(dir.clone()))));
        // A record that does not say its folder: nothing proves it gone.
        assert!(in_use(&record("image:ubuntu", None)));
        assert!(!in_use(&record("", Some(dir.clone()))));
        assert!(!project_gone(&record("", Some(dir.clone()))));
        std::fs::remove_dir(&dir).unwrap();
        assert!(!in_use(&record("image:ubuntu", Some(dir.clone()))));
        assert!(project_gone(&record("image:ubuntu", Some(dir))));
    }

    fn list() -> Vec<Image> {
        vec![
            image("aaa", &["docker.io/library/ubuntu:24.04"], None, 100),
            image("old", &["localhost/ssai-base:old"], Some("project"), 200),
            image("new", &["localhost/ssai-base:new"], Some("project"), 200),
            image("l1", &["localhost/ssai-agent-claude:old-1"], Some("sha256:old"), 250),
            image("l2", &["localhost/ssai-agent-claude:new-1"], Some("new"), 250),
            image("l3", &[], Some("old"), 250),
            image("b0", &[], Some("project"), 200),
            // A registry image a pull of the sandbox's added.
            image("ppp", &["docker.io/library/debian:12"], None, 80),
            // The developer's own images built from a layer and from a build:
            // each inherits the label.
            image("mine", &["localhost/my-tools:1"], Some("old"), 300),
            image("app", &["localhost/my-app:1"], Some("project"), 300),
        ]
    }

    #[test]
    fn a_bases_layers_are_named_by_our_names_or_by_id_when_unnamed() {
        assert_eq!(
            layers_on(&list(), "sha256:old"),
            ["localhost/ssai-agent-claude:old-1", "l3"],
            "never the developer's image built from it, nor another base's layer"
        );
        assert!(layers_on(&list(), "zzz").is_empty());
    }

    #[test]
    fn prune_takes_what_the_sandbox_made_and_never_the_developers() {
        let gone = sandbox_made(&list(), &BTreeSet::from(["ppp".to_string()]));
        assert_eq!(
            gone,
            [
                "localhost/ssai-agent-claude:old-1",
                "localhost/ssai-agent-claude:new-1",
                "l3",
                "localhost/ssai-base:old",
                "localhost/ssai-base:new",
                "b0",
                "ppp"
            ]
        );
        for theirs in ["aaa", "docker.io/library/ubuntu:24.04", "mine", "localhost/my-tools:1", "app", "localhost/my-app:1"] {
            assert!(!gone.contains(&theirs.to_string()), "{theirs}: {gone:?}");
        }
        // A pulled image the developer named too stays (removed by id it would go whole).
        let tagged = vec![image("ppp", &["docker.io/library/debian:12", "localhost/mine:1"], None, 1)];
        assert!(sandbox_made(&tagged, &BTreeSet::from(["ppp".to_string()])).is_empty());
        // An unlabelled image under our name (a build an earlier `ssai` made) goes too.
        let old = vec![image("x", &["localhost/ssai-base:unlabelled"], None, 1)];
        assert_eq!(sandbox_made(&old, &BTreeSet::new()), ["localhost/ssai-base:unlabelled"]);
    }

    #[test]
    fn volume_sizes_are_read_from_podmans_table() {
        let text = "Images space usage:\n\nREPOSITORY TAG\nssai-home-zz 1 9GB\n\nLocal Volumes space usage:\n\n\
                    VOLUME NAME  LINKS       SIZE\nssai-home-ab  0           3MB\nssai-engine-cd  1  1.5GB\nother 0 2GB\nssai-home-x 0 0B\n";
        let sizes = parse_volume_sizes(text);
        assert_eq!(
            sizes,
            BTreeMap::from([("ssai-home-ab".into(), 3_000_000), ("ssai-engine-cd".into(), 1_500_000_000), ("ssai-home-x".into(), 0)])
        );
        assert_eq!(parse_size("512kB"), Some(512_000));
        assert_eq!(parse_size("12"), None);
        assert_eq!(parse_size("3XB"), None);
    }

    #[test]
    fn a_projects_volumes_are_found_by_its_key_and_no_other_projects() {
        let (a, b) = (Path::new("/w/a"), Path::new("/w/ab"));
        let all = vec![
            super::super::home_volume(a, "claude"),
            super::super::home_volume(a, "my-custom-tool"),
            super::super::engine_volume(a),
            super::super::home_volume(b, "claude"),
            super::super::engine_volume(b),
            "ssai-home-unrelated".to_string(),
        ];
        assert_eq!(project_volumes(a, &all), all[..3].to_vec());
        assert_eq!(project_volumes(b, &all), all[3..5].to_vec());
    }
}
