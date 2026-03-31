use std::sync::RwLock;
use trail_inspector_core::store::Store;
use trail_inspector_core::session::SessionIndex;
use trail_inspector_core::geoip::GeoIpEngine;

pub struct AppState {
    pub store: RwLock<Option<Store>>,
    /// Lazily-built session index; cleared when a new dataset is loaded.
    pub session_index: RwLock<Option<SessionIndex>>,
    /// Optional GeoIP engine; loaded on demand via load_geoip_db command.
    pub geoip: RwLock<Option<GeoIpEngine>>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            store: RwLock::new(None),
            session_index: RwLock::new(None),
            geoip: RwLock::new(None),
        }
    }
}
