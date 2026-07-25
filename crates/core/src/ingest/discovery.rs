use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Recursively find all CloudTrail log files under a directory.
/// Returns paths to: .json, .json.gz, .zip files
///
/// If `root` is itself a file it is returned as-is, extension filter skipped —
/// the user picked that exact file, so an unusual name should surface a parse
/// warning rather than a silent zero-record load.
pub fn find_log_files(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }

    WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_lowercase();
            // Any `.gz`, not just `.json.gz`: CloudTrail delivers `.json.gz`, but
            // emulated and CTF environments use names like `audit.log.gz`.
            // Decompression sniffs the gzip magic, so the suffix only decides
            // what's worth opening.
            name.ends_with(".json")
                || name.ends_with(".gz")
                || name.ends_with(".zip")
                || name.ends_with(".log")
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

    /// Emulated AWS / CTF environments deliver `audit.log.gz`, not `.json.gz`.
    #[test]
    fn test_find_log_files_accepts_non_json_gzip_names() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("audit.log.gz"), b"").unwrap();
        fs::write(dir.path().join("notes.md"), b"").unwrap();
        let found = find_log_files(dir.path());
        assert_eq!(found.len(), 1);
        assert!(found[0].ends_with("audit.log.gz"));
    }

    #[test]
    fn test_find_log_files_accepts_single_file_root() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("cloudtrail-events.json");
        fs::write(&file, b"").unwrap();
        assert_eq!(find_log_files(&file), vec![file]);
    }

    #[test]
    fn test_single_file_root_ignores_extension_filter() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("export.log");
        fs::write(&file, b"").unwrap();
        assert_eq!(find_log_files(&file).len(), 1);
    }
}
