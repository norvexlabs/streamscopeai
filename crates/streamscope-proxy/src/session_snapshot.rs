//! Session detector state persistence for crash recovery.
//!
//! Periodically saves the detector's recorded turns to disk so session
//! detection resumes after a proxy restart without losing continuity. The
//! file is written a line at a time ([`SessionExport::write_to`]) to a `.tmp`
//! beside it, then renamed over it, so a crash mid-write leaves the last one.

use std::io::BufWriter;

use streamscope_core::proxy::session_detector::{RestoreCounts, SessionDetector, SessionExport};

/// The snapshot's file name under the data directory.
const FILE: &str = "session_state.json";

/// Write `export` to `{data_dir}/session_state.json`, one JSON line at a time. Blocking I/O: run it
/// off the runtime's workers.
pub fn save_snapshot(data_dir: &str, mut export: SessionExport) -> Result<RestoreCounts, anyhow::Error> {
    let path = format!("{data_dir}/{FILE}");
    let tmp_path = format!("{path}.tmp");
    let written = std::fs::File::create(&tmp_path).map_err(anyhow::Error::from).and_then(|file| {
        let counts = export.write_to(BufWriter::new(&file))?;
        file.sync_all()?;
        Ok(counts)
    });
    let counts = match written {
        Ok(counts) => counts,
        Err(e) => {
            // A part-written file is of no use to a restore.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
    };
    std::fs::rename(&tmp_path, &path)?;
    // The rename itself survives a power loss only once the directory is
    // synced; a filesystem that cannot sync a directory still has the file.
    if let Err(e) = std::fs::File::open(data_dir).and_then(|dir| dir.sync_all()) {
        tracing::debug!(error = %e, "could not sync the session snapshot's directory");
    }
    tracing::debug!(path = %path, users = counts.users, turns = counts.turns, "saved session snapshot to disk");
    Ok(counts)
}

/// Restore the detector from `{data_dir}/session_state.json`. `None` when no
/// snapshot exists; an error when it exists but does not read, the detector
/// then left empty.
pub fn load_snapshot(data_dir: &str, detector: &SessionDetector) -> Result<Option<RestoreCounts>, anyhow::Error> {
    match std::fs::File::open(format!("{data_dir}/{FILE}")) {
        Ok(file) => Ok(Some(detector.import_from(std::io::BufReader::new(file))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamscope_core::proxy::session_detector::{LinkHash, SessionInfo};
    use uuid::Uuid;

    fn data_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("streamscope_sess_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn detector() -> SessionDetector {
        SessionDetector::new(50, std::time::Duration::from_secs(3600))
    }

    #[test]
    fn roundtrip_snapshot() {
        let dir = data_dir();
        let data_dir = dir.to_str().unwrap();
        let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
        let source = detector();
        let hashes = [LinkHash::of("h1"), LinkHash::of("h2")];
        let info = source.detect(user, key, Uuid::nil(), &hashes, hashes.first().copied(), Some("cs1"));
        let request = Uuid::new_v4();
        source.record(user, key, request, &info, &hashes, Some("cs1"));

        assert_eq!(save_snapshot(data_dir, source.export()).unwrap(), RestoreCounts { users: 1, turns: 1 });
        let restored = detector();
        assert_eq!(load_snapshot(data_dir, &restored).unwrap(), Some(RestoreCounts { users: 1, turns: 1 }));
        assert_eq!(restored.held_bytes(), source.held_bytes());
        // The restored turn is the one the next turn continues.
        let next: SessionInfo =
            restored.detect(user, key, Uuid::nil(), &[hashes[0], hashes[1], LinkHash::of("h3")], Some(hashes[0]), Some("cs1"));
        assert_eq!((next.session_id, next.parent_request_id, next.turn_number, next.is_baseline), (info.session_id, Some(request), 1, false));
    }

    #[test]
    fn load_missing_returns_none() {
        let dir = data_dir();
        assert!(load_snapshot(dir.to_str().unwrap(), &detector()).unwrap().is_none());
    }

    #[test]
    fn corrupt_file_returns_error() {
        let dir = data_dir();
        std::fs::write(dir.join(FILE), "not valid json\n").unwrap();
        let restored = detector();
        assert!(load_snapshot(dir.to_str().unwrap(), &restored).is_err());
        assert_eq!(restored.entries(), 0);
    }
}
