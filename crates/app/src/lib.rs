mod commands;
mod state;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(state::AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::ingest::load_directory,
            commands::query::get_record_by_id,
            commands::query::search,
            commands::query::get_field_values,
            commands::stats::get_timeline,
            commands::stats::get_top_fields,
            commands::stats::get_identity_summary_cmd,
            commands::detection::run_detections,
            commands::export::export_csv,
            commands::export::export_json,
            commands::session::list_sessions,
            commands::session::get_session_detail,
            commands::session::get_session_alerts,
            commands::session::get_alert_sessions,
            commands::geoip::load_geoip_db,
            commands::geoip::lookup_ip,
            commands::geoip::list_ips,
            commands::geoip::check_abuseipdb,
            commands::geoip::geo_lookup_online,
            commands::s3::get_s3_summary,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TrailInspector");
}
