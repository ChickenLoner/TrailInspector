use std::io::{Read, ErrorKind};
use std::path::Path;
use crate::error::CoreError;

fn map_io_err(e: std::io::Error, path: &Path) -> CoreError {
    if e.kind() == ErrorKind::PermissionDenied {
        CoreError::PermissionDenied { path: path.to_string_lossy().into_owned() }
    } else {
        CoreError::Io { path: path.to_string_lossy().into_owned(), source: e }
    }
}

/// Gzip magic number. Detecting by content rather than filename matters: CloudTrail
/// delivers `.json.gz`, but emulated/CTF environments hand out names like
/// `audit.log.gz`, and an extension check silently reads those as raw bytes and
/// then fails to parse.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Read a file (gzip or plain JSON) into a byte buffer.
/// Uses read_to_end + serde_json::from_slice (NOT from_reader) for performance.
pub fn read_log_file(path: &Path) -> Result<Vec<u8>, CoreError> {
    let mut file = std::fs::File::open(path).map_err(|e| map_io_err(e, path))?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw).map_err(|e| map_io_err(e, path))?;

    if raw.starts_with(&GZIP_MAGIC) {
        let mut buf = Vec::new();
        flate2::read::GzDecoder::new(&raw[..])
            .read_to_end(&mut buf)
            .map_err(|e| CoreError::CorruptGzip {
                path: path.to_string_lossy().into_owned(),
                source: e,
            })?;
        Ok(buf)
    } else {
        Ok(raw)
    }
}

/// Extract all CloudTrail-relevant entries from a ZIP archive.
/// Returns a `Vec<Vec<u8>>` where each element is the decompressed bytes of one
/// `.json.gz` or `.json` entry found inside the archive.
pub fn read_zip_entries(path: &Path) -> Result<Vec<Vec<u8>>, CoreError> {
    let file = std::fs::File::open(path).map_err(|e| map_io_err(e, path))?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut result = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_lowercase();

        // Same rule as the directory walk: any plausible log name, with gzip
        // detected from the bytes rather than the extension.
        if !(name.ends_with(".json") || name.ends_with(".gz") || name.ends_with(".log")) {
            continue;
        }

        let mut raw = Vec::new();
        entry.read_to_end(&mut raw).map_err(|e| map_io_err(e, path))?;

        if raw.starts_with(&GZIP_MAGIC) {
            let mut buf = Vec::new();
            flate2::read::GzDecoder::new(&raw[..])
                .read_to_end(&mut buf)
                .map_err(|e| CoreError::CorruptGzip {
                    path: path.to_string_lossy().into_owned(),
                    source: e,
                })?;
            result.push(buf);
        } else {
            result.push(raw);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// Gzip is detected from the magic bytes, so a `.log.gz` name decompresses
    /// exactly like `.json.gz`. Extension-based detection returned raw gzip bytes
    /// here, which then failed to parse as JSON.
    #[test]
    fn decompresses_gzip_regardless_of_extension() {
        let dir = TempDir::new().unwrap();
        let body = br#"{"Records":[]}"#;

        for name in ["audit.log.gz", "events.json.gz", "weird.name"] {
            let p = dir.path().join(name);
            std::fs::write(&p, gzip(body)).unwrap();
            assert_eq!(read_log_file(&p).unwrap(), body, "failed for {name}");
        }
    }

    #[test]
    fn plain_json_passes_through_untouched() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("events.json");
        let body = br#"{"Records":[]}"#;
        std::fs::write(&p, body).unwrap();
        assert_eq!(read_log_file(&p).unwrap(), body);
    }

    /// A `.gz` name whose contents aren't gzip must not be mangled — it is read
    /// as-is and left for the parser to judge.
    #[test]
    fn misnamed_gz_is_read_as_plain() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("notreally.gz");
        let body = br#"{"Records":[]}"#;
        std::fs::write(&p, body).unwrap();
        assert_eq!(read_log_file(&p).unwrap(), body);
    }
}
