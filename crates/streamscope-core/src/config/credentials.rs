//! A tenant's stored upstream credentials, opened once per configuration.
//!
//! They are decrypted when the configuration is built and travel inside it, so
//! a request reads its key, its routes and the credential each route presents
//! from one published value — never from a second store that a config change
//! updates at another moment.

use std::collections::HashMap;

/// Why an upstream credential could not be produced.
///
/// A caller that repeats on a timer reports the consequence rather than the
/// attempt, and needs to say which of these it hit: a credential the
/// configuration does not carry and one the process cannot decrypt are
/// different operator problems with the same symptom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMiss {
    /// The configuration carries no credential for that server.
    Absent,
    /// Stored encrypted, and this process has no key to open it.
    NoEncryptionKey,
    /// Stored encrypted, and decryption failed.
    Undecryptable,
}

impl CredentialMiss {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "not in this replica's configuration",
            Self::NoEncryptionKey => "no ENCRYPTION_KEY to open it with",
            Self::Undecryptable => "could not be decrypted",
        }
    }
}

/// Each upstream server's stored credential, by server id, opened.
///
/// `Debug` names the servers and never a plaintext.
#[derive(Clone, Default)]
pub struct ServerCredentials(HashMap<String, Result<String, CredentialMiss>>);

impl ServerCredentials {
    /// Open each `(server id, ciphertext)` with `key`. One that does not open
    /// is kept as the reason, so a request routed to it reports why.
    pub fn open<'a>(
        stored: impl IntoIterator<Item = (String, &'a str)>,
        key: Option<&[u8; 32]>,
    ) -> Self {
        Self(
            stored
                .into_iter()
                .map(|(server, ciphertext)| {
                    let opened = match key {
                        None => Err(CredentialMiss::NoEncryptionKey),
                        Some(key) => crate::crypto::decrypt(ciphertext, key).map_err(|e| {
                            tracing::warn!(server = %server, "upstream credential did not decrypt: {e}");
                            CredentialMiss::Undecryptable
                        }),
                    };
                    (server, opened)
                })
                .collect(),
        )
    }

    /// The credential server `server_id` presents.
    pub fn get(&self, server_id: &str) -> Result<&str, CredentialMiss> {
        match self.0.get(server_id) {
            Some(Ok(plaintext)) => Ok(plaintext),
            Some(Err(miss)) => Err(*miss),
            None => Err(CredentialMiss::Absent),
        }
    }
}

impl std::fmt::Debug for ServerCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_opens_once_and_debug_never_shows_it() {
        let key = [7u8; 32];
        let sealed = crate::crypto::encrypt("sk-upstream-secret", &key).unwrap();
        let creds = ServerCredentials::open([("s1".to_string(), sealed.as_str())], Some(&key));
        assert_eq!(creds.get("s1"), Ok("sk-upstream-secret"));
        assert_eq!(creds.get("s2"), Err(CredentialMiss::Absent));
        assert!(!format!("{creds:?}").contains("secret"));
    }

    #[test]
    fn a_credential_that_does_not_open_says_why() {
        let sealed = crate::crypto::encrypt("x", &[7u8; 32]).unwrap();
        let wrong = ServerCredentials::open([("s1".to_string(), sealed.as_str())], Some(&[8u8; 32]));
        assert_eq!(wrong.get("s1"), Err(CredentialMiss::Undecryptable));
        let keyless = ServerCredentials::open([("s1".to_string(), sealed.as_str())], None);
        assert_eq!(keyless.get("s1"), Err(CredentialMiss::NoEncryptionKey));
    }
}
