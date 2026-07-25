//! Enumerate named AWS profiles.
//!
//! **Names and regions only.** This scans for INI section headers and the single
//! `region` key. It never reads `aws_access_key_id`, `aws_secret_access_key`, or
//! `aws_session_token` — the SDK resolves those itself at call time, so no secret
//! value ever becomes a field in TrailInspector, crosses IPC, or reaches the
//! frontend. That is enforced here by construction, not by convention.
//!
//! Not feature-gated: this is plain std with no SDK types, so the picker works in
//! the default offline build too.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A profile as shown in the picker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileInfo {
    pub name: String,
    /// The profile's configured region, used to default the region dropdown.
    pub region: Option<String>,
}

/// Resolve the config file path, honoring `AWS_CONFIG_FILE`.
fn config_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("AWS_CONFIG_FILE") {
        return Some(PathBuf::from(p));
    }
    home_dir().map(|h| h.join(".aws").join("config"))
}

/// Resolve the credentials file path, honoring `AWS_SHARED_CREDENTIALS_FILE`.
fn credentials_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("AWS_SHARED_CREDENTIALS_FILE") {
        return Some(PathBuf::from(p));
    }
    home_dir().map(|h| h.join(".aws").join("credentials"))
}

/// `USERPROFILE` on Windows, `HOME` elsewhere; each falls back to the other so a
/// Git-Bash / MSYS environment (which sets `HOME`) still resolves.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

/// Strip an inline `#`/`;` comment. Only treated as a comment when preceded by
/// whitespace, so a value like `arn:...#frag` survives.
fn strip_comment(s: &str) -> &str {
    let mut cut = s.len();
    for (i, c) in s.char_indices() {
        if (c == '#' || c == ';') && (i == 0 || s[..i].ends_with(char::is_whitespace)) {
            cut = i;
            break;
        }
    }
    s[..cut].trim_end()
}

/// Scan one INI file for `[section]` headers and each section's `region` key.
///
/// `strip_profile_prefix` handles the asymmetry between the two AWS files:
/// `~/.aws/config` writes `[profile foo]` (but bare `[default]`), while
/// `~/.aws/credentials` writes `[foo]`.
fn scan_ini(text: &str, strip_profile_prefix: bool) -> BTreeMap<String, Option<String>> {
    let mut out: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut current: Option<String> = None;

    for raw in text.lines() {
        let line = strip_comment(raw.trim());
        if line.is_empty() {
            continue;
        }

        if let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let name = inner.trim();
            let name = if strip_profile_prefix {
                name.strip_prefix("profile ").map(str::trim).unwrap_or(name)
            } else {
                name
            };
            if name.is_empty() {
                current = None;
                continue;
            }
            current = Some(name.to_string());
            out.entry(name.to_string()).or_insert(None);
            continue;
        }

        // Only `region` is of interest. Nested sub-sections (`sso_session`,
        // indented keys) are ignored along with everything else.
        let Some(sec) = current.as_deref() else { continue };
        if let Some((k, v)) = line.split_once('=') {
            if k.trim().eq_ignore_ascii_case("region") {
                let v = v.trim();
                if !v.is_empty() {
                    out.insert(sec.to_string(), Some(v.to_string()));
                }
            }
        }
    }

    out
}

/// List profiles from the standard config/credentials files.
///
/// Returns an empty vec (not an error) when no config files exist — a machine with
/// no `~/.aws` is a normal state, not a failure, and the UI renders that as
/// "no profiles found, run `aws configure`".
pub fn list_profiles() -> Vec<ProfileInfo> {
    let mut merged: BTreeMap<String, Option<String>> = BTreeMap::new();

    // credentials first, then config — config wins on region, matching the AWS
    // precedence where `~/.aws/config` is where `region` actually belongs.
    if let Some(p) = credentials_path() {
        if let Ok(text) = std::fs::read_to_string(&p) {
            merged.extend(scan_ini(&text, false));
        }
    }
    if let Some(p) = config_path() {
        if let Ok(text) = std::fs::read_to_string(&p) {
            for (name, region) in scan_ini(&text, true) {
                match merged.get_mut(&name) {
                    Some(slot) => {
                        if region.is_some() {
                            *slot = region;
                        }
                    }
                    None => {
                        merged.insert(name, region);
                    }
                }
            }
        }
    }

    let mut out: Vec<ProfileInfo> = merged
        .into_iter()
        .map(|(name, region)| ProfileInfo { name, region })
        .collect();

    // `default` first, then alphabetical — the picker should open on the profile
    // most people mean.
    out.sort_by(|a, b| match (a.name == "default", b.name == "default") {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.cmp(&b.name),
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_info_serializes_camel_case() {
        let p = ProfileInfo { name: "ctf".into(), region: Some("us-east-1".into()) };
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, r#"{"name":"ctf","region":"us-east-1"}"#);
    }

    #[test]
    fn config_file_strips_profile_prefix_but_not_default() {
        let text = "[default]\nregion = us-east-1\n\n[profile ctf]\nregion = eu-west-1\n";
        let got = scan_ini(text, true);
        assert_eq!(got.get("default"), Some(&Some("us-east-1".to_string())));
        assert_eq!(got.get("ctf"), Some(&Some("eu-west-1".to_string())));
        assert!(!got.contains_key("profile ctf"));
    }

    #[test]
    fn credentials_file_keeps_bare_section_names() {
        let text = "[ctf]\naws_access_key_id = AKIAEXAMPLE\n";
        let got = scan_ini(text, false);
        assert_eq!(got.get("ctf"), Some(&None));
    }

    /// The point of the module: secret keys must never be captured.
    #[test]
    fn secret_keys_are_never_captured() {
        let text = "[ctf]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = s3cr3t\naws_session_token = tok\nregion = us-east-2\n";
        let got = scan_ini(text, false);
        assert_eq!(got.get("ctf"), Some(&Some("us-east-2".to_string())));
        // Only region survives; nothing else is retained anywhere in the map.
        let serialized = format!("{got:?}");
        assert!(!serialized.contains("s3cr3t"), "secret leaked: {serialized}");
        assert!(!serialized.contains("AKIAEXAMPLE"), "key id leaked: {serialized}");
        assert!(!serialized.contains("tok"), "token leaked: {serialized}");
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let text = "# top comment\n[ctf]  ; trailing\nregion = us-east-1 # inline\n\n";
        let got = scan_ini(text, false);
        assert_eq!(got.get("ctf"), Some(&Some("us-east-1".to_string())));
    }

    #[test]
    fn section_without_region_yields_none() {
        let got = scan_ini("[nore]\noutput = json\n", false);
        assert_eq!(got.get("nore"), Some(&None));
    }
}
