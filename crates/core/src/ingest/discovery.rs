use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Recursively find all CloudTrail log files under a directory.
/// Returns paths to: .json, .json.gz, .zip files
pub fn find_log_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_lowercase();
            name.ends_with(".json.gz") || name.ends_with(".json") || name.ends_with(".zip")
        })
        .map(|e| e.into_path())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_find_log_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("events.json.gz"), b"").unwrap();
        fs::write(dir.path().join("events.json"), b"").unwrap();
        fs::write(dir.path().join("other.txt"), b"").unwrap();
        let found = find_log_files(dir.path());
        assert_eq!(found.len(), 2);
    }
}
