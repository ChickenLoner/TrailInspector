/// Indexed fields available for filtering
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldName {
    EventName,
    EventSource,
    AwsRegion,
    SourceIPAddress,
    UserArn,
    UserName,
    AccountId,
    ErrorCode,
    IdentityType,
    UserAgent,
    BucketName,
}

impl FieldName {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "eventName" => Some(Self::EventName),
            "eventSource" => Some(Self::EventSource),
            "awsRegion" | "region" => Some(Self::AwsRegion),
            "sourceIPAddress" | "sourceIp" => Some(Self::SourceIPAddress),
            "userArn" | "arn" => Some(Self::UserArn),
            "userName" => Some(Self::UserName),
            "accountId" => Some(Self::AccountId),
            "errorCode" => Some(Self::ErrorCode),
            "identityType" | "userIdentity.type" => Some(Self::IdentityType),
            "userAgent" => Some(Self::UserAgent),
            "bucketName" => Some(Self::BucketName),
            _ => None,
        }
    }
}

/// How to match the filter value
#[derive(Debug, Clone)]
pub enum MatchMode {
    Exact(String),       // field=value  (case-sensitive for API names)
    Prefix(String),      // field=val*   (lowercased for comparison)
    Suffix(String),      // field=*val   (lowercased for comparison)
    Contains(String),    // field=*val*  (lowercased for comparison)
    Exists,              // field=*  (field has any indexed value)
}

/// A single field filter predicate
#[derive(Debug, Clone)]
pub struct FieldFilter {
    pub field: FieldName,
    pub mode: MatchMode,
    pub negated: bool,
}

/// Time range in epoch milliseconds (inclusive on both ends)
#[derive(Debug, Clone, Copy)]
pub struct TimeRange {
    pub start_ms: i64,
    pub end_ms: i64,
}

/// A fully parsed query ready for execution.
///
/// Stored in Disjunctive Normal Form (DNF):
/// - The outer Vec is OR'd: any group matching is a match.
/// - Each inner Vec is AND'd: all filters in a group must match.
///
/// Example: `eventName=A OR eventName=B` →
///   filter_groups = [[{eventName=A}], [{eventName=B}]]
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub filter_groups: Vec<Vec<FieldFilter>>,
    pub time_range: Option<TimeRange>,
}

impl Query {
    pub fn is_empty(&self) -> bool {
        self.filter_groups.is_empty() && self.time_range.is_none()
    }
}
