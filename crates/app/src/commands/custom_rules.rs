use tauri::State;
use trail_inspector_core::detection::custom_rules::load_custom_rules;
use crate::state::AppState;

/// Return any parse or validation errors from the currently loaded rules.yaml.
#[tauri::command]
pub async fn get_custom_rule_errors(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let errors = state.custom_rule_errors.read().map_err(|e| format!("Lock error: {e}"))?;
    Ok(errors.clone())
}

/// Re-read rules.yaml from disk, apply the new rules, and return any errors.
/// An empty return list means all rules loaded successfully.
#[tauri::command]
pub async fn reload_custom_rules(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let result = load_custom_rules(&state.rules_path);
    *state.custom_rules.write().map_err(|e| format!("Lock error: {e}"))? = result.rules;
    let errors = result.errors;
    *state.custom_rule_errors.write().map_err(|e| format!("Lock error: {e}"))? = errors.clone();
    Ok(errors)
}

/// Open rules.yaml in the user's default text editor.
#[tauri::command]
pub async fn open_rules_file(state: State<'_, AppState>) -> Result<(), String> {
    open::that(&state.rules_path).map_err(|e| format!("Failed to open rules file: {e}"))
}
