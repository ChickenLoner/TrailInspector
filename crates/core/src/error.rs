use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O error reading '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Permission denied reading '{path}'")]
    PermissionDenied { path: String },

    #[error("JSON parse error in '{path}': {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Corrupt gzip file '{path}': {source}")]
    CorruptGzip {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("Query parse error: {0}")]
    Query(String),

    /// AWS API / SDK failure during a fetch.
    ///
    /// Carries a formatted `String` rather than the SDK error type on purpose:
    /// it keeps this enum byte-identical between `--features aws` and default
    /// builds, so no SDK type leaks into the offline build.
    #[error("AWS error during {context}: {message}")]
    Aws { context: String, message: String },
}

impl CoreError {
    /// Build an `Aws` variant from any SDK error.
    ///
    /// `context` should name the operation ("LookupEvents", "DescribeTrails") so a
    /// failure is attributable without a stack trace.
    pub fn aws(context: impl Into<String>, err: impl std::fmt::Display) -> Self {
        CoreError::Aws { context: context.into(), message: err.to_string() }
    }
}

/// A non-fatal warning emitted during ingestion when a file cannot be parsed.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestWarning {
    pub message: String,
    pub file: Option<String>,
}
