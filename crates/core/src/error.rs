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
}

/// A non-fatal warning emitted during ingestion when a file cannot be parsed.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestWarning {
    pub message: String,
    pub file: Option<String>,
}
