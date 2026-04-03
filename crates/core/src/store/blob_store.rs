//! BlobStore: off-heap storage for large per-event JSON blobs.
//!
//! CloudTrail requestParameters, responseElements, and additionalEventData
//! are only accessed by detection rules that have already filtered down to
//! a small set of matching records — no need to keep them in RAM for all events.
//!
//! ## Two-phase design
//!
//! **Write phase (ingestion):** blobs are appended to a temp file through a
//! `BufWriter`. Batched writes dramatically reduce syscall overhead vs the
//! previous unbuffered approach (15M writes → ~600 flushed batches for 5M events).
//!
//! **Sealed phase (post-ingestion):** `seal()` flushes the writer and memory-maps
//! the file read-only. All subsequent `load_str` calls are lock-free pointer
//! arithmetic into the mmap region — OS page-cache backed, near-RAM speed.
//! This restores filter/detection latency to pre-Phase-F levels while keeping
//! the ~1.8 GB RAM savings.

use std::io::{Write, BufWriter};
use std::sync::{Mutex, OnceLock};
use memmap2::Mmap;
use serde_json::value::RawValue;

/// Pointer to a JSON blob in the BlobStore temp file.
/// 12 bytes on the stack (vs 200-800 bytes for Box<RawValue> on the heap).
#[derive(Clone, Copy, Debug, Default)]
pub struct BlobRef {
    pub offset: u64,
    pub len: u32,
}

pub struct BlobStore {
    /// Write-phase state. Held only during ingestion; `None` once sealed.
    writer: Mutex<Option<BufWriter<std::fs::File>>>,
    write_pos: Mutex<u64>,
    /// Sealed read-only mmap. Populated by `seal()` after ingestion finishes.
    mmap: OnceLock<Mmap>,
}

impl BlobStore {
    /// Create a new BlobStore backed by an anonymous temp file.
    pub fn new() -> std::io::Result<Self> {
        let file = tempfile::tempfile()?;
        Ok(Self {
            writer: Mutex::new(Some(BufWriter::new(file))),
            write_pos: Mutex::new(0),
            mmap: OnceLock::new(),
        })
    }

    /// Write raw JSON bytes to the blob store and return a BlobRef.
    /// Called during ingestion. Uses buffered I/O to batch disk writes.
    pub fn write(&self, data: &[u8]) -> std::io::Result<BlobRef> {
        let mut pos = self.write_pos.lock().unwrap();
        let offset = *pos;
        self.writer
            .lock()
            .unwrap()
            .as_mut()
            .expect("BlobStore::write called after seal()")
            .write_all(data)?;
        *pos += data.len() as u64;
        Ok(BlobRef { offset, len: data.len() as u32 })
    }

    /// Flush the write buffer and memory-map the file for fast read-only access.
    /// Must be called once after ingestion is complete, before any `load_str` calls.
    /// Safe to call multiple times (no-op if already sealed).
    pub fn seal(&self) -> std::io::Result<()> {
        if self.mmap.get().is_some() {
            return Ok(());
        }
        let file = {
            let mut guard = self.writer.lock().unwrap();
            let mut writer = guard.take().expect("already sealed");
            writer.flush()?;
            writer.into_inner().map_err(|e| e.into_error())?
        };
        // Safety: the file is fully written and will not be modified after this point.
        let mmap = unsafe { Mmap::map(&file)? };
        let _ = self.mmap.set(mmap); // OnceLock: no-op if already set by a race
        Ok(())
    }

    /// Load the raw JSON string for a BlobRef.
    /// After `seal()`: lock-free slice into the mmap region.
    pub fn load_str(&self, blob_ref: BlobRef) -> Option<&str> {
        let mmap = self.mmap.get()?;
        let start = blob_ref.offset as usize;
        let end = start + blob_ref.len as usize;
        let bytes = mmap.get(start..end)?;
        std::str::from_utf8(bytes).ok()
    }

    /// Load and parse a BlobRef as a `serde_json::Value`.
    pub fn parse_value(&self, blob_ref: BlobRef) -> Option<serde_json::Value> {
        serde_json::from_str(self.load_str(blob_ref)?).ok()
    }

    /// Load a BlobRef as `Box<RawValue>` (for re-serialisation into IPC responses).
    pub fn load_raw_value(&self, blob_ref: BlobRef) -> Option<Box<RawValue>> {
        serde_json::from_str(self.load_str(blob_ref)?).ok()
    }
}
