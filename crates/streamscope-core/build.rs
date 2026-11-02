//! Extract the current version from `CHANGELOG.md` and expose it as
//! `STREAMSCOPE_VERSION` at compile time.  This is the single source of truth
//! for the application version — no manual Cargo.toml bumps required.

use std::fs;
use std::path::Path;

fn main() {
    let changelog = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../CHANGELOG.md");

    println!("cargo:rerun-if-changed={}", changelog.display());

    let content = fs::read_to_string(&changelog)
        .expect("failed to read CHANGELOG.md");

    // First `## [X.Y.Z]` heading is the current version.
    let version = content
        .lines()
        .find_map(|line| {
            let line = line.trim();
            if line.starts_with("## [") {
                line.strip_prefix("## [")
                    .and_then(|s| s.split(']').next())
            } else {
                None
            }
        })
        .expect("no version found in CHANGELOG.md");

    println!("cargo:rustc-env=STREAMSCOPE_VERSION={version}");
}
