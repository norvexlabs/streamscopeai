//! The Windows sandbox account, platform-neutral: its name, the record
//! `ssai sandbox setup` keeps, the elevated helper's hand-off, and the check
//! that the egress rule Windows stored is the one setup wrote. Pure, so it is
//! tested on every host; the Win32 side is `setup.rs`.

// Off Windows this module is compiled for its tests only.
#![cfg_attr(not(windows), allow(dead_code))]

use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The account's full name, shown in the Windows user list.
pub const FULL_NAME: &str = "Streamscope AI sandbox";

/// The remote ranges the egress rule blocks: every address but loopback
/// (`127.0.0.0/8`, `::1`), which the per-run guard listens on. A block rule
/// always beats an allow rule, so loopback is carved out by the ranges.
pub const BLOCKED_V4: [&str; 2] = ["0.0.0.0-126.255.255.255", "128.0.0.0-255.255.255.255"];
pub const BLOCKED_V6: [&str; 2] = ["::", "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

/// The sandbox account of the owner whose SID string is `owner_sid`:
/// `ssai-sbx-` + the first 6 hex characters of SHA-256 over the SID string —
/// 15 characters, under the 20 a local account name may hold, and the same on
/// every run, so a second owner on the machine gets an account of their own.
pub fn account_name(owner_sid: &str) -> String {
    let digest = Sha256::digest(owner_sid.as_bytes());
    format!("ssai-sbx-{}", &hex::encode(digest)[..6])
}

/// Whether `name` is a name [`account_name`] makes — the only names the
/// elevated helper creates or deletes.
pub fn is_account_name(name: &str) -> bool {
    name.strip_prefix("ssai-sbx-")
        .is_some_and(|hex| hex.len() == 6 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// Whether `sid` is a local or domain account's SID string (`S-1-5-21-…`),
/// the only shape spliced into the rule's script and its SDDL.
pub fn is_account_sid(sid: &str) -> bool {
    sid.strip_prefix("S-1-5-21-")
        .is_some_and(|rest| !rest.is_empty() && rest.split('-').all(|n| !n.is_empty() && n.len() <= 10 && n.bytes().all(|b| b.is_ascii_digit())))
}

/// The account's description: whose sandbox it is.
pub fn description(owner_name: &str) -> String {
    // A local account name holds at most 20 characters; the description field
    // holds 48 (as `New-LocalUser` enforces it).
    let owner: String = owner_name.chars().take(31).collect();
    format!("ssai sandbox for {owner}")
}

/// The egress rule's name (its key in the firewall's rule store) and display name.
pub fn rule_name(account: &str) -> String {
    format!("{account}-egress")
}
pub fn rule_display_name(account: &str) -> String {
    format!("Streamscope AI sandbox egress ({account})")
}

/// The PowerShell that (re)creates the egress rule: one outbound block for the
/// account's SID on every profile and protocol, every remote address but
/// loopback. `account` and `sid` must pass [`is_account_name`] /
/// [`is_account_sid`]; they are the only values spliced in.
pub fn add_rule_script(account: &str, sid: &str) -> String {
    debug_assert!(is_account_name(account) && is_account_sid(sid));
    let ranges: Vec<&str> = BLOCKED_V4.iter().chain(BLOCKED_V6.iter()).copied().collect();
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $old = Get-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue; if ($old) {{ $old | Remove-NetFirewallRule }}; \
         New-NetFirewallRule -Name '{name}' -DisplayName '{display}' -Direction Outbound -Action Block \
         -Protocol Any -Profile Any -Enabled True -LocalUser 'D:(A;;CC;;;{sid})' -RemoteAddress {ranges} | Out-Null; exit 0",
        name = rule_name(account),
        display = rule_display_name(account),
        ranges = ranges.join(","),
    )
}

/// The PowerShell that removes the egress rule, if present. A real failure
/// stops the script (non-zero exit); an absent rule is not one — the lookup's
/// own "not found" would otherwise leave the exit code at 1.
pub fn remove_rule_script(account: &str) -> String {
    debug_assert!(is_account_name(account));
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $old = Get-NetFirewallRule -Name '{}' -ErrorAction SilentlyContinue; if ($old) {{ $old | Remove-NetFirewallRule }}; exit 0",
        rule_name(account)
    )
}

/// Whether `stored` — the rule as the firewall keeps it in its rule store
/// (`v2.33|Action=Block|Active=TRUE|Dir=Out|RA4=…|LUAuth=…|`) — is the rule
/// [`add_rule_script`] writes for `sid`, and if not, what differs. Strict: a
/// field that could narrow the rule (a protocol, a port, a program, a
/// profile, a local address) is a difference, so a rule edited down to
/// nothing reads as missing, never as present.
pub fn check_stored_rule(stored: &str, sid: &str) -> Result<(), String> {
    let mut fields = stored.trim_end_matches('|').split('|');
    match fields.next() {
        Some(v) if v.starts_with("v2.") => {}
        _ => return Err("the firewall rule is in an unknown format".into()),
    }
    let (mut action, mut active, mut dir, mut user) = (None, None, None, None);
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for field in fields {
        let Some((key, value)) = field.split_once('=') else {
            return Err(format!("the firewall rule has an unknown field {field:?}"));
        };
        match key {
            "Action" => action = Some(value),
            "Active" => active = Some(value),
            "Dir" => dir = Some(value),
            "LUAuth" => user = Some(value),
            "RA4" => v4.push(value),
            "RA6" => v6.push(value),
            "Name" | "Desc" | "EmbedCtxt" => {}
            other => return Err(format!("the firewall rule is narrowed by {other}={value}")),
        }
    }
    if action != Some("Block") || dir != Some("Out") {
        return Err("the firewall rule is not an outbound block".into());
    }
    if active != Some("TRUE") {
        return Err("the firewall rule is disabled".into());
    }
    if user != Some(format!("D:(A;;CC;;;{sid})").as_str()) {
        return Err("the firewall rule does not name the sandbox account".into());
    }
    let same = |got: &mut Vec<&str>, want: &[&str]| {
        got.sort_unstable();
        let mut want = want.to_vec();
        want.sort_unstable();
        *got == want
    };
    if !same(&mut v4, &BLOCKED_V4) || !same(&mut v6, &BLOCKED_V6) {
        return Err("the firewall rule does not block every remote address but loopback".into());
    }
    Ok(())
}

/// What a firewall profile's settings say about whether a local rule applies:
/// the firewall must be on (`EnableFirewall`, local or by policy) and a policy
/// must not stop local rules from merging (`AllowLocalPolicyMerge = 0`). Each
/// value is `None` when absent.
pub fn check_profile(name: &str, local_enabled: Option<u32>, policy_enabled: Option<u32>, policy_merge: Option<u32>) -> Result<(), String> {
    let enabled = policy_enabled.or(local_enabled).unwrap_or(1);
    if enabled == 0 {
        return Err(format!("Windows Firewall is off for the {name} profile"));
    }
    if policy_merge == Some(0) {
        return Err(format!("a group policy ignores local firewall rules on the {name} profile"));
    }
    Ok(())
}

/// A generated password: 32 characters with an upper-case letter, a
/// lower-case letter, a digit and a symbol, so a password-complexity policy
/// accepts it. Nobody types it: setup keeps it protected for the owner.
pub fn generate_password(rng: &mut impl rand::Rng) -> String {
    const CLASSES: [&[u8]; 4] = [b"ABCDEFGHJKLMNPQRSTUVWXYZ", b"abcdefghijkmnopqrstuvwxyz", b"23456789", b"-_.~!#%+="];
    let all: Vec<u8> = CLASSES.concat();
    let mut out: Vec<u8> = CLASSES.iter().map(|class| class[rng.random_range(0..class.len())]).collect();
    out.extend((out.len()..32).map(|_| all[rng.random_range(0..all.len())]));
    // Shuffle so the four guaranteed characters are not always first.
    for i in (1..out.len()).rev() {
        out.swap(i, rng.random_range(0..=i));
    }
    String::from_utf8(out).unwrap_or_default()
}

/// What `ssai sandbox setup` records for the owner (in their own config
/// folder): the account, and its password protected for the owner alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupRecord {
    pub account: String,
    pub account_sid: String,
    pub owner_sid: String,
    /// The password, protected with the owner's Windows data protection
    /// (DPAPI), base64. Set once: an administrator's reset of the password
    /// would lose the secrets the account keeps protected under it.
    pub password: String,
}

/// What the developer's process asks the elevated helper to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HelperRequest {
    /// Create the account (or repair it) for `owner_sid`. `password` is set
    /// when the account is created, or when it must be reset because the
    /// recorded one no longer signs in; `None` keeps the account's own.
    Setup { owner_sid: String, owner_name: String, account: String, password: Option<String> },
    /// Remove the account, its profile and its egress rule.
    Uninstall { account: String },
}

/// The elevated helper's answer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HelperResponse {
    /// The account's SID, once it exists.
    pub account_sid: Option<String>,
    /// One line per step taken, for the developer.
    pub done: Vec<String>,
    /// Why it stopped, when it did.
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    const SID: &str = "S-1-5-21-3829567528-106784536-1568828441-1002";

    /// The VM's owner `lab` (`…-1000`) maps to the account the lab created.
    #[test]
    fn the_account_name_is_a_hash_of_the_owner_sid() {
        let name = account_name("S-1-5-21-3829567528-106784536-1568828441-1000");
        assert_eq!(name, "ssai-sbx-e9a8bb");
        assert!(name.len() <= 20);
        assert!(is_account_name(&name));
        assert_ne!(account_name(SID), name);
    }

    #[test]
    fn only_generated_names_and_account_sids_are_accepted() {
        for good in ["ssai-sbx-000000", "ssai-sbx-abcdef"] {
            assert!(is_account_name(good), "{good}");
        }
        for bad in ["ssai-sbx-ABCDEF", "ssai-sbx-abcde", "ssai-sbx-abcdefa", "ssai-sbx-abcdeg", "lab", "ssai-sbx-ab'cd;", ""] {
            assert!(!is_account_name(bad), "{bad}");
        }
        assert!(is_account_sid(SID));
        for bad in ["S-1-5-21-", "S-1-5-32-544", "S-1-5-21-1-", "S-1-5-21-1--2", "S-1-5-21-1)(A;;GA;;;WD", "S-1-5-21-12345678901"] {
            assert!(!is_account_sid(bad), "{bad}");
        }
    }

    #[test]
    fn the_description_fits_the_field() {
        assert_eq!(description("lab"), "ssai sandbox for lab");
        assert!(description(&"x".repeat(100)).chars().count() <= 48);
    }

    #[test]
    fn the_script_carries_only_the_validated_values() {
        let script = add_rule_script("ssai-sbx-e9a8bb", SID);
        assert!(script.contains("-Name 'ssai-sbx-e9a8bb-egress'"), "{script}");
        assert!(script.contains(&format!("-LocalUser 'D:(A;;CC;;;{SID})'")), "{script}");
        assert!(script.contains("-RemoteAddress 0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::,::2-ffff:"), "{script}");
        assert!(script.contains("-Direction Outbound -Action Block -Protocol Any -Profile Any"), "{script}");
        assert!(remove_rule_script("ssai-sbx-e9a8bb").contains("-Name 'ssai-sbx-e9a8bb-egress'"));
    }

    /// The rule exactly as Windows 11 stored the script's rule (win-dev, 2026-11-03).
    fn stored() -> String {
        format!(
            "v2.33|Action=Block|Active=TRUE|Dir=Out|RA4=0.0.0.0-126.255.255.255|RA4=128.0.0.0-255.255.255.255|RA6=::|\
             RA6=::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff|Name=Streamscope AI sandbox egress (ssai-sbx-e9a8bb)|\
             LUAuth=D:(A;;CC;;;{SID})|"
        )
    }

    #[test]
    fn the_stored_rule_setup_writes_passes() {
        assert_eq!(check_stored_rule(&stored(), SID), Ok(()));
    }

    #[test]
    fn a_rule_edited_down_or_aside_fails() {
        let cases: [(&str, String); 9] = [
            ("allow", stored().replace("Action=Block", "Action=Allow")),
            ("inbound", stored().replace("Dir=Out", "Dir=In")),
            ("disabled", stored().replace("Active=TRUE", "Active=FALSE")),
            ("another user", stored().replace(SID, "S-1-5-21-1-2-3-4")),
            ("tcp only", stored().replace("|Dir=Out|", "|Dir=Out|Protocol=6|")),
            ("one profile", stored().replace("|Dir=Out|", "|Dir=Out|Profile=Public|")),
            ("one port", stored().replace("|Dir=Out|", "|Dir=Out|RPort=443|")),
            ("a range dropped", stored().replace("RA4=128.0.0.0-255.255.255.255|", "")),
            ("v6 widened to loopback", stored().replace("RA6=::|", "RA6=::1|")),
        ];
        for (what, rule) in cases {
            assert!(check_stored_rule(&rule, SID).is_err(), "{what}: {rule}");
        }
        assert!(check_stored_rule("", SID).is_err());
        assert!(check_stored_rule("v1|Action=Block", SID).is_err());
    }

    #[test]
    fn a_profile_applies_local_rules_only_when_on_and_merged() {
        assert_eq!(check_profile("Public", Some(1), None, None), Ok(()));
        assert_eq!(check_profile("Public", None, None, None), Ok(()));
        assert_eq!(check_profile("Public", Some(0), Some(1), Some(1)), Ok(()));
        assert!(check_profile("Public", Some(0), None, None).is_err());
        assert!(check_profile("Public", Some(1), Some(0), None).is_err());
        assert!(check_profile("Public", Some(1), None, Some(0)).is_err());
    }

    #[test]
    fn a_generated_password_has_every_class() {
        let mut rng = rand::rng();
        for _ in 0..200 {
            let pw = generate_password(&mut rng);
            assert_eq!(pw.len(), 32);
            assert!(pw.bytes().any(|b| b.is_ascii_uppercase()), "{pw}");
            assert!(pw.bytes().any(|b| b.is_ascii_lowercase()), "{pw}");
            assert!(pw.bytes().any(|b| b.is_ascii_digit()), "{pw}");
            assert!(pw.bytes().any(|b| !b.is_ascii_alphanumeric()), "{pw}");
        }
    }

    #[test]
    fn the_hand_off_round_trips() {
        let req = HelperRequest::Setup { owner_sid: SID.into(), owner_name: "lab".into(), account: "ssai-sbx-e9a8bb".into(), password: None };
        let text = serde_json::to_string(&req).unwrap();
        assert!(text.contains(r#""action":"setup""#), "{text}");
        let back: HelperRequest = serde_json::from_str(&text).unwrap();
        assert_matches!(back, HelperRequest::Setup { password: None, .. });
    }
}
