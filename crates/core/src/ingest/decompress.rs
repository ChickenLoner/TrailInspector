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

/// Read a file (gzip or plain JSON) into a byte buffer.
/// Uses read_to_end + serde_json::from_slice (NOT from_reader) for performance.
pub fn read_log_file(path: &Path) -> Result<Vec<u8>, CoreError> {
    let file = std::fs::File::open(path).map_err(|e| map_io_err(e, path))?;
    let name = path.to_string_lossy().to_lowercase();

    if name.ends_with(".json.gz") {
        let mut decoder = flate2::read::GzDecoder::new(file);
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf).map_err(|e| CoreError::CorruptGzip {
            path: path.to_string_lossy().into_owned(),
            source: e,
        })?;
        Ok(buf)
    } else {
        let mut buf = Vec::new();
        let mut f = file;
        f.read_to_end(&mut buf).map_err(|e| map_io_err(e, path))?;
        Ok(buf)
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

        if name.ends_with(".json.gz") {
            let mut decoder = flate2::read::GzDecoder::new(entry);
            let mut buf = Vec::new();
            decoder.read_to_end(&mut buf).map_err(|e| CoreError::CorruptGzip {
                path: path.to_string_lossy().into_owned(),
                source: e,
            })?;
            result.push(buf);
        } else if name.ends_with(".json") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| map_io_err(e, path))?;
            result.push(buf);
        }
    }

    Ok(result)
}
