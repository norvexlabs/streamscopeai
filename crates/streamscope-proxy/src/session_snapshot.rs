//! Session detector state persistence for crash recovery.
//!
//! Periodically saves the per-user session turn history to disk so session
//! detection can resume after a proxy restart without losing continuity.
//! Uses atomic write (`.tmp` + rename) to prevent corruption.
//!
//! The DashMap key is `(user_id, key_id)` — a tuple that cannot be used as
//! a JSON object key directly. We serialize as a Vec of `SnapshotEntry`
//! structs instead.

use streamscope_core::proxy::content::{SessionSnapshot, TurnEntry};
use uuid::Uuid;

/// Serializable entry for the session snapshot file.
#[derive(serde::Serialize, serde::Deserialize)]
struct SnapshotEntry {
    user_id: Uuid,
    key_id: Uuid,
    turns: Vec<TurnEntry>,
}

/// Save session state snapshot to `{data_dir}/session_state.json`.
///
/// Uses atomic write (write to .tmp, then rename) to avoid corruption.
pub fn save_snapshot(
    data_dir: &str,
    entries: &SessionSnapshot,
) -> Result<(), anyhow::Error> {
    let path = format!("{data_dir}/session_state.json");
    let tmp_path = format!("{path}.tmp");
    let snapshot: Vec<SnapshotEntry> = entries
        .iter()
        .map(|((user_id, key_id), turns)| SnapshotEntry {
            user_id: *user_id,
            key_id: *key_id,
            turns: turns.clone(),
        })
        .collect();
    let json = serde_json::to_string(&snapshot)?;
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, &path)?;
    tracing::debug!(path = %path, shards = entries.len(), "saved session snapshot to disk");
    Ok(())
}

/// Load session state snapshot from disk. Returns `None` if no snapshot file exists.
/// Returns an error if the file exists but cannot be deserialized.
pub fn load_snapshot(
    data_dir: &str,
) -> Result<Option<SessionSnapshot>, anyhow::Error> {
    let path = format!("{data_dir}/session_state.json");
    match std::fs::read_to_string(&path) {
        Ok(json) => {
            let snapshot: Vec<SnapshotEntry> = serde_json::from_str(&json)?;
            let entries: SessionSnapshot = snapshot
                .into_iter()
                .map(|e| ((e.user_id, e.key_id), e.turns))
                .collect();
            Ok(Some(entries))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_snapshot() {
        let dir = std::env::temp_dir().join(format!("streamscope_sess_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let data_dir = dir.to_str().unwrap();

        let user_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();
        let mut entries = SessionSnapshot::new();
        entries.insert(
            (user_id, key_id),
            vec![TurnEntry {
                request_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                turn_number: 3,
                message_hashes: vec!["h1".into(), "h2".into()],
                client_session_id: Some("cs1".into()),
                recorded_at: std::time::Instant::now(),
            }],
        );

        save_snapshot(data_dir, &entries).unwrap();
        let loaded = load_snapshot(data_dir).unwrap().unwrap();
        assert_eq!(loaded.len(), 1);
        let turns = loaded.get(&(user_id, key_id)).unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].turn_number, 3);
        assert_eq!(turns[0].message_hashes, vec!["h1", "h2"]);
        assert_eq!(turns[0].client_session_id.as_deref(), Some("cs1"));
    }

    #[test]
    fn load_missing_returns_none() {
        let dir = std::env::temp_dir().join(format!("streamscope_sess_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = load_snapshot(dir.to_str().unwrap()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn corrupt_file_returns_error() {
        let dir = std::env::temp_dir().join(format!("streamscope_sess_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session_state.json"), "not valid json").unwrap();
        let result = load_snapshot(dir.to_str().unwrap());
        assert!(result.is_err());
    }

}
