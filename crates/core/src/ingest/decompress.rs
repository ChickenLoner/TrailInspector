use std::io::Read;
use std::path::Path;
use crate::error::CoreError;

/// Read a file (gzip or plain JSON) into a byte buffer.
/// Uses read_to_end + serde_json::from_slice (NOT from_reader) for performance.
pub fn read_log_file(path: &Path) -> Result<Vec<u8>, CoreError> {
    let file = std::fs::File::open(path).map_err(|e| CoreError::Io(e))?;
    let name = path.to_string_lossy().to_lowercase();

    if name.ends_with(".json.gz") {
        let mut decoder = flate2::read::GzDecoder::new(file);
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf).map_err(|e| CoreError::Io(e))?;
        Ok(buf)
    } else {
        let mut buf = Vec::new();
        let mut f = file;
        f.read_to_end(&mut buf).map_err(|e| CoreError::Io(e))?;
        Ok(buf)
    }
}
