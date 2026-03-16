use std::sync::RwLock;
use trail_inspector_core::store::Store;

pub struct AppState {
    pub store: RwLock<Option<Store>>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            store: RwLock::new(None),
        }
    }
}
