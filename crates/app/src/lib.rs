mod commands;
mod state;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(state::AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::ingest::load_directory,
            commands::query::search,
            commands::query::get_field_values,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TrailInspector");
}
