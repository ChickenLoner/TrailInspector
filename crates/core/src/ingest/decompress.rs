use std::io::{Read, ErrorKind};
use std::ops::ControlFlow;
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

/// Upper bound on one decompressed log. Real CloudTrail files inflate to a few MB; a hostile or
/// corrupt archive (a "zip bomb") would otherwise allocate until the process is killed.
pub const MAX_DECOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

fn too_large(path: &Path, cap: u64) -> CoreError {
    CoreError::CorruptGzip {
        path: path.to_string_lossy().into_owned(),
        source: std::io::Error::new(
            ErrorKind::InvalidData,
            format!("exceeds {} decompressed", human_bytes(cap)),
        ),
    }
}

fn human_bytes(n: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if n >= GIB && n % GIB == 0 {
        format!("{} GiB", n / GIB)
    } else if n >= MIB && n % MIB == 0 {
        format!("{} MiB", n / MIB)
    } else {
        format!("{n} bytes")
    }
}

/// Read `r` to the end, failing (instead of allocating without bound) past `cap` bytes.
fn read_capped<R: Read>(r: R, path: &Path, cap: u64, on_err: impl Fn(std::io::Error) -> CoreError) -> Result<Vec<u8>, CoreError> {
    let mut buf = Vec::new();
    // One byte over the cap is enough to tell "exactly cap" from "more than cap".
    r.take(cap.saturating_add(1)).read_to_end(&mut buf).map_err(on_err)?;
    if buf.len() as u64 > cap {
        return Err(too_large(path, cap));
    }
    Ok(buf)
}

/// Inflate gzip bytes. `MultiGzDecoder` reads every member: `cat a.gz b.gz > c.gz` is valid gzip,
/// and the single-member decoder silently stopped after the first.
fn gunzip_capped(raw: &[u8], path: &Path, cap: u64) -> Result<Vec<u8>, CoreError> {
    read_capped(flate2::read::MultiGzDecoder::new(raw), path, cap, |source| CoreError::CorruptGzip {
        path: path.to_string_lossy().into_owned(),
        source,
    })
}

/// Read a file (gzip or plain JSON) into a byte buffer.
/// Uses read_to_end + serde_json::from_slice (NOT from_reader) for performance.
pub fn read_log_file(path: &Path) -> Result<Vec<u8>, CoreError> {
    read_log_file_capped(path, MAX_DECOMPRESSED_BYTES)
}

fn read_log_file_capped(path: &Path, cap: u64) -> Result<Vec<u8>, CoreError> {
    let mut file = std::fs::File::open(path).map_err(|e| map_io_err(e, path))?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw).map_err(|e| map_io_err(e, path))?;

    if raw.starts_with(&GZIP_MAGIC) {
        gunzip_capped(&raw, path, cap)
    } else {
        Ok(raw)
    }
}

/// Visit every CloudTrail-relevant entry of a ZIP archive, one at a time.
///
/// Each entry is inflated, handed to `f`, and dropped before the next is read, so memory is
/// bounded by the largest single entry rather than by the whole archive. (Collecting every
/// entry first held a 1 GB archive of `.json.gz` as roughly 10 GB of JSON at once.) `f` returns
/// `Break` to stop early, for instance when the consumer has hung up.
pub fn for_each_zip_entry(
    path: &Path,
    f: impl FnMut(Vec<u8>) -> ControlFlow<()>,
) -> Result<(), CoreError> {
    for_each_zip_entry_capped(path, MAX_DECOMPRESSED_BYTES, f)
}

fn for_each_zip_entry_capped(
    path: &Path,
    cap: u64,
    mut f: impl FnMut(Vec<u8>) -> ControlFlow<()>,
) -> Result<(), CoreError> {
    let file = std::fs::File::open(path).map_err(|e| map_io_err(e, path))?;
    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        let name = entry.name().to_lowercase();

        // Same rule as the directory walk: any plausible log name, with gzip
        // detected from the bytes rather than the extension.
        if !(name.ends_with(".json") || name.ends_with(".gz") || name.ends_with(".log")) {
            continue;
        }

        let raw = read_capped(entry, path, cap, |e| map_io_err(e, path))?;
        let bytes = if raw.starts_with(&GZIP_MAGIC) { gunzip_capped(&raw, path, cap)? } else { raw };

        if f(bytes).is_break() {
            break;
        }
    }

    Ok(())
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

    /// `cat a.gz b.gz` is valid gzip. The single-member decoder returned only `a`.
    #[test]
    fn reads_every_member_of_a_multi_member_gzip() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("two.json.gz");
        let mut both = gzip(b"first,");
        both.extend(gzip(b"second"));
        std::fs::write(&p, both).unwrap();
        assert_eq!(read_log_file(&p).unwrap(), b"first,second");
    }

    #[test]
    fn decompression_over_the_cap_is_an_error_not_an_allocation() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("bomb.json.gz");
        std::fs::write(&p, gzip(&vec![b'0'; 10_000])).unwrap();

        let msg = match read_log_file_capped(&p, 1_000) {
            Err(e) => e.to_string(),
            Ok(v) => panic!("expected the cap to trip, got {} bytes", v.len()),
        };
        assert!(msg.contains("exceeds 1000 bytes decompressed"), "{msg}");
        // Exactly at the cap is allowed.
        assert_eq!(read_log_file_capped(&p, 10_000).unwrap().len(), 10_000);
        assert_eq!(human_bytes(MAX_DECOMPRESSED_BYTES), "2 GiB");
    }

    fn make_zip(path: &Path, entries: &[(&str, Vec<u8>)]) {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        for (name, data) in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }

    #[test]
    fn zip_entries_stream_one_at_a_time_and_skip_other_files() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("logs.zip");
        make_zip(&p, &[
            ("a.json", b"{\"Records\":[]}".to_vec()),
            ("notes.txt", b"ignore me".to_vec()),
            ("b.json.gz", gzip(b"{\"Records\":[1]}")),
        ]);
        let mut seen: Vec<Vec<u8>> = Vec::new();
        for_each_zip_entry(&p, |b| {
            seen.push(b);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(seen, vec![b"{\"Records\":[]}".to_vec(), b"{\"Records\":[1]}".to_vec()]);
    }

    #[test]
    fn zip_visitor_can_stop_early() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("logs.zip");
        make_zip(&p, &[("a.json", b"1".to_vec()), ("b.json", b"2".to_vec()), ("c.json", b"3".to_vec())]);
        let mut calls = 0;
        for_each_zip_entry(&p, |_| {
            calls += 1;
            ControlFlow::Break(())
        })
        .unwrap();
        assert_eq!(calls, 1);
    }

    #[test]
    fn oversized_zip_entry_is_an_error() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("bomb.zip");
        make_zip(&p, &[("big.json", vec![b'0'; 10_000])]);
        let msg = match for_each_zip_entry_capped(&p, 1_000, |_| ControlFlow::Continue(())) {
            Err(e) => e.to_string(),
            Ok(()) => panic!("expected the cap to trip"),
        };
        assert!(msg.contains("exceeds"), "{msg}");
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
