use std::path::PathBuf;
use std::sync::{RwLock, RwLockReadGuard};
use trail_inspector_core::store::Store;
use trail_inspector_core::session::SessionIndex;
use trail_inspector_core::geoip::GeoIpEngine;
use trail_inspector_core::detection::custom_rules::CustomRule;
use trail_inspector_core::fetch::AwsCredentials;

pub struct AppState {
    pub store: RwLock<Option<Store>>,
    pub session_index: RwLock<Option<SessionIndex>>,
    pub geoip: RwLock<Option<GeoIpEngine>>,
    pub custom_rules: RwLock<Vec<CustomRule>>,
    pub custom_rule_errors: RwLock<Vec<String>>,
    /// Resolved path to the user's rules.yaml in the app config directory.
    pub rules_path: PathBuf,
    /// Credentials typed into the AWS fetch panel.
    ///
    /// **Memory only.** Never written to disk, never to `~/.aws`, never returned to
    /// the frontend. Held so Check and the subsequent Pull share one entry; dropped
    /// when the app exits or the user clears it.
    pub aws_credentials: RwLock<Option<AwsCredentials>>,
    /// A completed Check, waiting to be pulled into the store.
    pub aws_staged: RwLock<Option<StagedFetch>>,
}

/// Logs already downloaded by a Check, staged on disk pending a Pull.
///
/// Check pages through the whole result set, so re-downloading at Pull time would
/// pay the LookupEvents rate limit twice. Pull just ingests this directory.
pub struct StagedFetch {
    pub dir: PathBuf,
}

impl AppState {
    pub fn new(rules_path: PathBuf, rules: Vec<CustomRule>, errors: Vec<String>) -> Self {
        AppState {
            store: RwLock::new(None),
            session_index: RwLock::new(None),
            geoip: RwLock::new(None),
            custom_rules: RwLock::new(rules),
            custom_rule_errors: RwLock::new(errors),
            rules_path,
            aws_credentials: RwLock::new(None),
            aws_staged: RwLock::new(None),
        }
    }

    // ── Lock-read helpers ────────────────────────────────────────────────────
    // Every command repeated `.read().map_err(|e| format!("Lock error: {e}"))?`;
    // these centralize the poison→String mapping.

    pub fn store_read(&self) -> Result<RwLockReadGuard<'_, Option<Store>>, String> {
        self.store.read().map_err(|e| format!("Lock error: {e}"))
    }

    pub fn geoip_read(&self) -> Result<RwLockReadGuard<'_, Option<GeoIpEngine>>, String> {
        self.geoip.read().map_err(|e| format!("Lock error: {e}"))
    }

    pub fn custom_rules_read(&self) -> Result<RwLockReadGuard<'_, Vec<CustomRule>>, String> {
        self.custom_rules.read().map_err(|e| format!("Lock error: {e}"))
    }

    pub fn session_index_read(&self) -> Result<RwLockReadGuard<'_, Option<SessionIndex>>, String> {
        self.session_index.read().map_err(|e| format!("Lock error: {e}"))
    }

    /// Run `f` with a borrowed `&Store`, or fail with "No dataset loaded".
    /// Collapses the read-lock + None-check that every store command repeated.
    pub fn with_store<T>(&self, f: impl FnOnce(&Store) -> Result<T, String>) -> Result<T, String> {
        let guard = self.store_read()?;
        let store = guard.as_ref().ok_or("No dataset loaded")?;
        f(store)
    }

    /// Build the SessionIndex on first use (lazy). No-op once built.
    /// Shared by every session command that needs the index present.
    pub fn ensure_session_index(&self) -> Result<(), String> {
        if self.session_index_read()?.is_some() {
            return Ok(());
        }
        let index = self.with_store(|store| Ok(SessionIndex::build(store)))?;
        let mut sidx = self.session_index.write().map_err(|e| format!("Lock error: {e}"))?;
        // Another thread may have built it between our check and the write lock;
        // only install if still empty.
        if sidx.is_none() {
            *sidx = Some(index);
        }
        Ok(())
    }
}
