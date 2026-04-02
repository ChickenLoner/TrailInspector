use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// Top-level CloudTrail file wrapper
#[derive(Debug, Deserialize)]
pub struct CloudTrailFile {
    #[serde(rename = "Records")]
    pub records: Vec<CloudTrailRecord>,
}

/// Raw CloudTrail record — deserialize all known fields, ignore unknown fields.
/// JSON blob fields (requestParameters, responseElements, additionalEventData) are stored
/// as raw JSON text (Box<RawValue>) rather than parsed Value trees to save ~500 MB per 1M records.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudTrailRecord {
    pub event_version: Option<String>,
    pub event_time: String,
    pub event_source: String,
    pub event_name: String,
    pub aws_region: String,
    #[serde(rename = "sourceIPAddress")]
    pub source_ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_identity: UserIdentity,
    pub request_parameters: Option<Box<RawValue>>,
    pub response_elements: Option<Box<RawValue>>,
    pub additional_event_data: Option<Box<RawValue>>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub request_id: Option<String>,
    #[serde(rename = "eventID")]
    pub event_id: Option<String>,
    pub event_type: Option<String>,
    pub read_only: Option<bool>,
    pub management_event: Option<bool>,
    pub recipient_account_id: Option<String>,
    pub event_category: Option<String>,
    pub shared_event_id: Option<String>,
    pub session_credential_from_console: Option<String>,
    #[serde(default)]
    pub resources: Vec<Resource>,
}

impl CloudTrailRecord {
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
    pub identity_type: Option<String>,
    pub principal_id: Option<String>,
    pub arn: Option<String>,
    pub account_id: Option<String>,
    pub access_key_id: Option<String>,
    pub user_name: Option<String>,
    pub session_context: Option<Box<RawValue>>,
    pub invoked_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub account_id: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    #[serde(rename = "ARN")]
    pub arn: Option<String>,
}

/// Internal record with parsed timestamp and assigned ID
pub struct IndexedRecord {
    pub id: u64,
    pub timestamp: i64,   // epoch millis
    pub source_file: u32, // index into file path table
    pub record: CloudTrailRecord,
}
