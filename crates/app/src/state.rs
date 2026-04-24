use std::path::PathBuf;
use std::sync::RwLock;
use trail_inspector_core::store::Store;
use trail_inspector_core::session::SessionIndex;
use trail_inspector_core::geoip::GeoIpEngine;
use trail_inspector_core::detection::custom_rules::CustomRule;

pub struct AppState {
    pub store: RwLock<Option<Store>>,
    pub session_index: RwLock<Option<SessionIndex>>,
    pub geoip: RwLock<Option<GeoIpEngine>>,
    pub custom_rules: RwLock<Vec<CustomRule>>,
    pub custom_rule_errors: RwLock<Vec<String>>,
    /// Resolved path to the user's rules.yaml in the app config directory.
    pub rules_path: PathBuf,
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
        }
    }
}
