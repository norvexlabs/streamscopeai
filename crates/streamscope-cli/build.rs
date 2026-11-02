//! Extract the current version from `CHANGELOG.md` and expose it as
//! `STREAMSCOPE_VERSION` at compile time — same contract as
//! `streamscope-core/build.rs` (kept separate so the CLI tree stays free of
//! the server crates).

use std::fs;
use std::path::Path;

fn main() {
    let changelog = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../CHANGELOG.md");

    println!("cargo:rerun-if-changed={}", changelog.display());

    let content = fs::read_to_string(&changelog).expect("failed to read CHANGELOG.md");

    // First `## [X.Y.Z]` heading is the current version.
    let version = content
        .lines()
        .find_map(|line| {
            let line = line.trim();
            if line.starts_with("## [") {
                line.strip_prefix("## [").and_then(|s| s.split(']').next())
            } else {
                None
            }
        })
        .expect("no version found in CHANGELOG.md");

    println!("cargo:rustc-env=STREAMSCOPE_VERSION={version}");

    // The third-party licence list `ssai licenses` prints: the file
    // SSAI_THIRD_PARTY_LICENSES names (a release build generates it with
    // cargo-about), else a note that this build was made without one.
    println!("cargo:rerun-if-env-changed=SSAI_THIRD_PARTY_LICENSES");
    let text = match std::env::var("SSAI_THIRD_PARTY_LICENSES") {
        Ok(path) => {
            println!("cargo:rerun-if-changed={path}");
            fs::read_to_string(&path).expect("failed to read SSAI_THIRD_PARTY_LICENSES")
        }
        Err(_) => "This build of ssai was made without its third-party licence list.\n".to_string(),
    };
    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("THIRD_PARTY_LICENSES");
    fs::write(out, text).expect("failed to write the third-party licence list");
}
