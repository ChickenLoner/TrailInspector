use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level CloudTrail file wrapper
#[derive(Debug, Deserialize)]
pub struct CloudTrailFile {
    #[serde(rename = "Records")]
    pub records: Vec<CloudTrailRecord>,
}

/// Raw CloudTrail record — deserialize all known fields, capture extras
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
    pub request_parameters: Option<serde_json::Value>,
    pub response_elements: Option<serde_json::Value>,
    pub additional_event_data: Option<serde_json::Value>,
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

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
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
    pub session_context: Option<serde_json::Value>,
    pub invoked_by: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
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
