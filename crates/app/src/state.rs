use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{RwLock, RwLockReadGuard};
use trail_inspector_core::store::Store;
use trail_inspector_core::session::SessionIndex;
use trail_inspector_core::geoip::GeoIpEngine;
use trail_inspector_core::detection::custom_rules::{run_custom_rules, CustomRule};
use trail_inspector_core::detection::{run_all_rules, run_geo_rules, Alert};
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
    /// Every alert (built-in, geo and custom rules) for the loaded dataset, before the time filter
    /// and the per-alert id cap. Running all rules over a large dataset takes seconds, and the
    /// Detections tab, session alerts and alert-to-session lookups all need the same result.
    /// Cleared whenever the dataset, the custom rules, or the GeoIP database changes.
    alerts_cache: RwLock<Option<Vec<Alert>>>,
    /// Bumped on every invalidation. A computation that started before an invalidation must not
    /// install its (now stale) result afterwards.
    alerts_gen: AtomicU64,
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
            alerts_cache: RwLock::new(None),
            alerts_gen: AtomicU64::new(0),
        }
    }

    /// Forget cached alerts. Call after anything that can change what the rules produce: a new
    /// dataset, reloaded custom rules, a different GeoIP database.
    pub fn invalidate_alerts(&self) {
        self.alerts_gen.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut cache) = self.alerts_cache.write() {
            *cache = None;
        }
    }

    /// All alerts for the loaded dataset, uncapped and unfiltered. Served from the cache when
    /// present; otherwise every rule runs once and the result is cached. Callers apply the time
    /// filter and the IPC id cap with `finalize_alerts`. Heavy on a miss: call from a blocking task.
    pub fn all_alerts(&self) -> Result<Vec<Alert>, String> {
        if let Some(cached) = self.alerts_cache.read().map_err(|e| format!("Lock error: {e}"))?.as_ref() {
            return Ok(cached.clone());
        }

        let generation = self.alerts_gen.load(Ordering::SeqCst);
        let alerts = self.with_store(|store| {
            let mut alerts = run_all_rules(store);
            if let Some(geoip) = self.geoip_read()?.as_ref() {
                alerts.extend(run_geo_rules(store, geoip));
            }
            alerts.extend(run_custom_rules(&self.custom_rules_read()?, store));
            Ok(alerts)
        })?;

        // Install only if nothing was invalidated while the rules ran.
        let mut cache = self.alerts_cache.write().map_err(|e| format!("Lock error: {e}"))?;
        if self.alerts_gen.load(Ordering::SeqCst) == generation {
            *cache = Some(alerts.clone());
        }
        Ok(alerts)
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

#[cfg(test)]
mod tests {
    use super::*;
    use trail_inspector_core::detection::custom_rules::{
        CustomRule, FilterExpr, MatchSpec, Threshold,
    };
    use trail_inspector_core::detection::Severity;

    /// A store with two `CreateUser` events from IAM, loaded the way the app loads one.
    fn state_with_dataset() -> (AppState, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ti-state-test-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let rec = |i: u32| format!(
            r#"{{"eventTime":"2024-01-15T10:00:0{i}Z","eventSource":"iam.amazonaws.com","eventName":"CreateUser","awsRegion":"us-east-1","userIdentity":{{"type":"IAMUser","userName":"a"}}}}"#
        );
        std::fs::write(dir.join("f.json"), format!(r#"{{"Records":[{},{}]}}"#, rec(0), rec(1))).unwrap();

        let mut store = Store::new();
        store.load_directory(&dir, |_| {}).unwrap();
        let state = AppState::new(dir.join("rules.yaml"), vec![], vec![]);
        *state.store.write().unwrap() = Some(store);
        (state, dir)
    }

    fn custom_rule(id: &str) -> CustomRule {
        CustomRule {
            id: id.into(),
            name: "Custom".into(),
            enabled: true,
            severity: Severity::Low,
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            service: String::new(),
            description: String::new(),
            match_spec: MatchSpec { event_name: vec!["CreateUser".into()] },
            filters: None::<FilterExpr>,
            threshold: None::<Threshold>,
        }
    }

    fn ids(alerts: &[Alert]) -> Vec<String> {
        let mut v: Vec<String> = alerts.iter().map(|a| a.rule_id.clone()).collect();
        v.sort();
        v
    }

    #[test]
    fn alerts_are_cached_until_invalidated() {
        let (state, dir) = state_with_dataset();
        let first = state.all_alerts().unwrap();
        assert_eq!(ids(&first), vec!["PE-01"]);

        // Add a custom rule WITHOUT invalidating: the cached result is served unchanged.
        state.custom_rules.write().unwrap().push(custom_rule("CR-X"));
        assert_eq!(ids(&state.all_alerts().unwrap()), vec!["PE-01"], "served from cache");

        // Invalidation makes the next call recompute, now including the custom rule.
        state.invalidate_alerts();
        assert_eq!(ids(&state.all_alerts().unwrap()), vec!["CR-X", "PE-01"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cached_alerts_are_uncapped_and_unfiltered() {
        // The cache must hold the full match set; the cap and time filter are applied per call.
        let (state, dir) = state_with_dataset();
        let alerts = state.all_alerts().unwrap();
        let pe01 = alerts.iter().find(|a| a.rule_id == "PE-01").unwrap();
        assert_eq!(pe01.matching_record_ids.len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_stale_computation_cannot_install_itself_after_invalidation() {
        let (state, dir) = state_with_dataset();
        // Simulate: a computation captured generation 0, an invalidation then bumped it.
        let generation = state.alerts_gen.load(Ordering::SeqCst);
        state.invalidate_alerts();
        let stale = vec![];
        {
            let mut cache = state.alerts_cache.write().unwrap();
            if state.alerts_gen.load(Ordering::SeqCst) == generation {
                *cache = Some(stale);
            }
        }
        assert!(state.alerts_cache.read().unwrap().is_none(), "stale result must not be installed");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn no_dataset_is_an_error_not_an_empty_cache() {
        let state = AppState::new(PathBuf::from("rules.yaml"), vec![], vec![]);
        assert!(state.all_alerts().is_err());
        assert!(state.alerts_cache.read().unwrap().is_none());
    }
}
