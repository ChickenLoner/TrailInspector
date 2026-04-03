use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// Top-level CloudTrail file wrapper
#[derive(Debug, Deserialize)]
pub struct CloudTrailFile {
    #[serde(rename = "Records")]
    pub records: Vec<CloudTrailRecord>,
}

/// Raw CloudTrail record — deserialize all known fields, ignore unknown fields.
///
/// Memory layout choices:
/// - JSON blob fields (requestParameters, responseElements, additionalEventData)
///   stored as raw JSON text (Box<RawValue>) — saves ~500 MB per 1M records.
/// - High-repetition string fields (eventName, awsRegion, etc.) are `Arc<str>`.
///   After deserialization, `intern()` deduplicates them through a StringPool so
///   "us-east-1" stored in 5M records shares a single heap allocation.
///   Arc<str> = 16 bytes stack vs String = 24 bytes stack + independent heap.
/// - Truly unique per-event fields (eventID, requestID) stay as Option<String>.
/// - eventVersion is dropped — never used anywhere in the codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudTrailRecord {
    pub event_time: Arc<str>,
    pub event_source: Arc<str>,
    pub event_name: Arc<str>,
    pub aws_region: Arc<str>,
    #[serde(rename = "sourceIPAddress")]
    pub source_ip_address: Option<Arc<str>>,
    pub user_agent: Option<Arc<str>>,
    pub user_identity: UserIdentity,
    pub request_parameters: Option<Box<RawValue>>,
    pub response_elements: Option<Box<RawValue>>,
    pub additional_event_data: Option<Box<RawValue>>,
    pub error_code: Option<Arc<str>>,
    pub error_message: Option<Arc<str>>,
    pub request_id: Option<String>,
    #[serde(rename = "eventID")]
    pub event_id: Option<String>,
    pub event_type: Option<Arc<str>>,
    pub read_only: Option<bool>,
    pub management_event: Option<bool>,
    pub recipient_account_id: Option<Arc<str>>,
    pub event_category: Option<Arc<str>>,
    pub shared_event_id: Option<String>,
    pub session_credential_from_console: Option<String>,
    #[serde(default)]
    pub resources: Vec<Resource>,
}

impl CloudTrailRecord {
    /// Replace all Arc<str> fields with pooled (interned) versions.
    /// Called from Store::load_directory after each batch is parsed.
    /// After interning, identical string values share a single Arc heap allocation.
    pub(crate) fn intern(&mut self, pool: &mut crate::store::StringPool) {
        self.event_time = pool.intern(&self.event_time);
        self.event_source = pool.intern(&self.event_source);
        self.event_name = pool.intern(&self.event_name);
        self.aws_region = pool.intern(&self.aws_region);
        self.source_ip_address = self.source_ip_address.as_deref().map(|s| pool.intern(s));
        self.user_agent = self.user_agent.as_deref().map(|s| pool.intern(s));
        self.error_code = self.error_code.as_deref().map(|s| pool.intern(s));
        self.error_message = self.error_message.as_deref().map(|s| pool.intern(s));
        self.event_type = self.event_type.as_deref().map(|s| pool.intern(s));
        self.recipient_account_id = self.recipient_account_id.as_deref().map(|s| pool.intern(s));
        self.event_category = self.event_category.as_deref().map(|s| pool.intern(s));
        self.user_identity.intern(pool);
        for r in &mut self.resources {
            r.intern(pool);
        }
    }

    /// Parse requestParameters into a Value on demand (only when needed by detection rules).
    pub fn parse_request_parameters(&self) -> Option<serde_json::Value> {
        self.request_parameters.as_ref()
            .and_then(|v| serde_json::from_str(v.get()).ok())
    }

    /// Parse responseElements into a Value on demand.
    pub fn parse_response_elements(&self) -> Option<serde_json::Value> {
        self.response_elements.as_ref()
            .and_then(|v| serde_json::from_str(v.get()).ok())
    }

    /// Parse additionalEventData into a Value on demand.
    pub fn parse_additional_event_data(&self) -> Option<serde_json::Value> {
        self.additional_event_data.as_ref()
            .and_then(|v| serde_json::from_str(v.get()).ok())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdentity {
    #[serde(rename = "type")]
    pub identity_type: Option<Arc<str>>,
    pub principal_id: Option<Arc<str>>,
    pub arn: Option<Arc<str>>,
    pub account_id: Option<Arc<str>>,
    pub access_key_id: Option<Arc<str>>,
    pub user_name: Option<Arc<str>>,
    pub session_context: Option<Box<RawValue>>,
    pub invoked_by: Option<Arc<str>>,
}

impl UserIdentity {
    pub(crate) fn intern(&mut self, pool: &mut crate::store::StringPool) {
        self.identity_type = self.identity_type.as_deref().map(|s| pool.intern(s));
        self.principal_id = self.principal_id.as_deref().map(|s| pool.intern(s));
        self.arn = self.arn.as_deref().map(|s| pool.intern(s));
        self.account_id = self.account_id.as_deref().map(|s| pool.intern(s));
        self.access_key_id = self.access_key_id.as_deref().map(|s| pool.intern(s));
        self.user_name = self.user_name.as_deref().map(|s| pool.intern(s));
        self.invoked_by = self.invoked_by.as_deref().map(|s| pool.intern(s));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub account_id: Option<Arc<str>>,
    #[serde(rename = "type")]
    pub resource_type: Option<Arc<str>>,
    #[serde(rename = "ARN")]
    pub arn: Option<Arc<str>>,
}

impl Resource {
    pub(crate) fn intern(&mut self, pool: &mut crate::store::StringPool) {
        self.account_id = self.account_id.as_deref().map(|s| pool.intern(s));
        self.resource_type = self.resource_type.as_deref().map(|s| pool.intern(s));
        self.arn = self.arn.as_deref().map(|s| pool.intern(s));
    }
}

/// Internal record with parsed timestamp and assigned ID.
/// Uses u32 for id — supports up to ~4 billion records, halves index memory vs u64.
///
/// JSON blob fields (requestParameters, responseElements, additionalEventData)
/// are extracted from `record` during ingestion and written to the BlobStore.
/// The corresponding `Option<Box<RawValue>>` in `record` is set to None, and
/// these BlobRef fields point to the data in the temp file.
pub struct IndexedRecord {
    pub id: u32,
    pub timestamp: i64,   // epoch millis
    pub source_file: u32, // index into file path table
    pub record: CloudTrailRecord,
    /// Blob refs populated during ingestion (None on newly-parsed records)
    pub request_params_ref: Option<crate::store::BlobRef>,
    pub response_elements_ref: Option<crate::store::BlobRef>,
    pub additional_event_data_ref: Option<crate::store::BlobRef>,
}
