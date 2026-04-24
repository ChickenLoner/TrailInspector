mod commands;
mod state;

use tauri::Manager;
use trail_inspector_core::detection::custom_rules::{load_custom_rules, DEFAULT_RULES_YAML};
use state::AppState;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            std::fs::create_dir_all(&config_dir)?;
            let rules_path = config_dir.join("rules.yaml");

            if !rules_path.exists() {
                std::fs::write(&rules_path, DEFAULT_RULES_YAML)?;
            }

            let result = load_custom_rules(&rules_path);
            app.manage(AppState::new(rules_path, result.rules, result.errors));
            Ok(())
        })
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
            commands::custom_rules::get_custom_rule_errors,
            commands::custom_rules::reload_custom_rules,
            commands::custom_rules::open_rules_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TrailInspector");
}
