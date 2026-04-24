//! User-defined detection rules loaded from `rules.yaml` in the app config directory.
//!
//! Rules extend the 60 built-in detections. Each rule specifies:
//! - Metadata (id, name, severity, MITRE fields, service)
//! - One or more `event_name` values to match (exact)
//! - An optional boolean filter tree (AND / OR / NOT on indexed fields)
//! - An optional threshold (minimum count, optional sliding time window)

use std::collections::HashSet;
use std::path::Path;
use serde::Deserialize;
use crate::store::Store;
use crate::detection::{Alert, Severity};

// ---------------------------------------------------------------------------
// Schema types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterField {
    IdentityType,
    ErrorCode,
    SourceIp,
    UserName,
    UserArn,
    EventSource,
    Region,
    AccountId,
    UserAgent,
    BucketName,
}

/// Recursive boolean filter expression.
///
/// YAML representation:
/// ```yaml
/// and:
///   - field: identity_type
///     value: Root
///   - not:
///       field: error_code
///       value: AccessDenied
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum FilterExpr {
    And { and: Vec<FilterExpr> },
    Or  { or:  Vec<FilterExpr> },
    Not { not: Box<FilterExpr> },
    Condition { field: FilterField, value: String },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Threshold {
    pub min_count: usize,
    #[serde(default)]
    pub window_minutes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatchSpec {
    #[serde(deserialize_with = "one_or_many")]
    pub event_name: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub severity: Severity,
    #[serde(default)]
    pub mitre_tactic: String,
    #[serde(default)]
    pub mitre_technique: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
    pub filters: Option<FilterExpr>,
    pub threshold: Option<Threshold>,
}

#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<CustomRule>,
}

fn default_true() -> bool { true }

fn one_or_many<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where D: serde::Deserializer<'de>
{
    use serde::de::{self, SeqAccess, Visitor};
    use std::fmt;

    struct OneOrMany;
    impl<'de> Visitor<'de> for OneOrMany {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a string or list of strings")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(OneOrMany)
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

pub struct LoadResult {
    pub rules: Vec<CustomRule>,
    pub errors: Vec<String>,
}

/// Parse `rules.yaml`, validate, and reject duplicate IDs.
/// Never fails — callers always get a usable (possibly empty) rule list plus
/// a list of human-readable error strings to show in the UI.
pub fn load_custom_rules(path: &Path) -> LoadResult {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return LoadResult {
            rules: vec![],
            errors: vec![format!("Cannot read rules file: {e}")],
        },
    };

    let file: RulesFile = match serde_yaml::from_str(&text) {
        Ok(f) => f,
        Err(e) => return LoadResult {
            rules: vec![],
            errors: vec![format!("YAML parse error: {e}")],
        },
    };

    let mut errors = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut duplicate_ids: HashSet<String> = HashSet::new();
    let mut out: Vec<CustomRule> = Vec::new();

    for rule in file.rules {
        if rule.id.is_empty() {
            errors.push(format!("Rule '{}': id must not be empty", rule.name));
            continue;
        }

        if duplicate_ids.contains(&rule.id) {
            errors.push(format!("Rule '{}': duplicate id — already rejected", rule.id));
            continue;
        }

        if seen_ids.contains(&rule.id) {
            errors.push(format!("Duplicate rule id '{}' — skipping both occurrences", rule.id));
            out.retain(|r| r.id != rule.id);
            duplicate_ids.insert(rule.id.clone());
            seen_ids.remove(&rule.id);
            continue;
        }

        if rule.match_spec.event_name.is_empty() {
            errors.push(format!("Rule '{}': match.event_name must have at least one entry", rule.id));
            continue;
        }

        if let Some(ref t) = rule.threshold {
            if t.min_count == 0 {
                errors.push(format!("Rule '{}': threshold.min_count must be >= 1", rule.id));
                continue;
            }
        }

        seen_ids.insert(rule.id.clone());
        out.push(rule);
    }

    LoadResult { rules: out, errors }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

fn apply_filter(expr: &FilterExpr, store: &Store, candidates: &[u32]) -> Vec<u32> {
    match expr {
        FilterExpr::Condition { field, value } => {
            let idx = match field {
                FilterField::IdentityType => &store.idx_identity_type,
                FilterField::ErrorCode    => &store.idx_error_code,
                FilterField::SourceIp     => &store.idx_source_ip,
                FilterField::UserName     => &store.idx_user_name,
                FilterField::UserArn      => &store.idx_user_arn,
                FilterField::EventSource  => &store.idx_event_source,
                FilterField::Region       => &store.idx_region,
                FilterField::AccountId    => &store.idx_account_id,
                FilterField::UserAgent    => &store.idx_user_agent,
                FilterField::BucketName   => &store.idx_bucket_name,
            };
            let matching: HashSet<u32> = idx.get(value.as_str())
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default();
            candidates.iter().copied().filter(|id| matching.contains(id)).collect()
        }
        FilterExpr::And { and: exprs } => {
            let mut result: Vec<u32> = candidates.to_vec();
            for e in exprs {
                result = apply_filter(e, store, &result);
                if result.is_empty() { break; }
            }
            result
        }
        FilterExpr::Or { or: exprs } => {
            let mut result_set: HashSet<u32> = HashSet::new();
            for e in exprs {
                for id in apply_filter(e, store, candidates) {
                    result_set.insert(id);
                }
            }
            candidates.iter().copied().filter(|id| result_set.contains(id)).collect()
        }
        FilterExpr::Not { not: inner } => {
            let excluded: HashSet<u32> = apply_filter(inner, store, candidates).into_iter().collect();
            candidates.iter().copied().filter(|id| !excluded.contains(id)).collect()
        }
    }
}

fn check_threshold(store: &Store, matching: &[u32], threshold: &Threshold) -> bool {
    if matching.len() < threshold.min_count {
        return false;
    }
    if let Some(window_minutes) = threshold.window_minutes {
        let window_ms = window_minutes as i64 * 60_000;
        let mut ts: Vec<i64> = matching.iter()
            .filter_map(|&id| store.get_record(id).map(|r| r.timestamp))
            .collect();
        ts.sort_unstable();

        let mut left = 0;
        for right in 0..ts.len() {
            while ts[right] - ts[left] > window_ms {
                left += 1;
            }
            if right - left + 1 >= threshold.min_count {
                return true;
            }
        }
        false
    } else {
        true
    }
}

pub fn evaluate_custom_rule(rule: &CustomRule, store: &Store) -> Vec<Alert> {
    if !rule.enabled {
        return vec![];
    }

    let mut candidates: Vec<u32> = rule.match_spec.event_name.iter()
        .flat_map(|name| {
            store.idx_event_name.get(name.as_str())
                .into_iter()
                .flatten()
                .copied()
        })
        .collect();

    if candidates.is_empty() {
        return vec![];
    }

    candidates.sort_unstable();
    candidates.dedup();

    let matching = if let Some(ref expr) = rule.filters {
        apply_filter(expr, store, &candidates)
    } else {
        candidates
    };

    if matching.is_empty() {
        return vec![];
    }

    if let Some(ref threshold) = rule.threshold {
        if !check_threshold(store, &matching, threshold) {
            return vec![];
        }
    }

    let query = rule.match_spec.event_name.iter()
        .map(|n| format!("eventName={n}"))
        .collect::<Vec<_>>()
        .join(" OR ");

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("source".to_string(), "custom".to_string());

    vec![Alert {
        rule_id: rule.id.clone(),
        severity: rule.severity.clone(),
        title: rule.name.clone(),
        description: rule.description.clone(),
        matching_count: matching.len(),
        matching_record_ids: matching,
        metadata,
        mitre_tactic: rule.mitre_tactic.clone(),
        mitre_technique: rule.mitre_technique.clone(),
        service: rule.service.clone(),
        query,
    }]
}

pub fn run_custom_rules(rules: &[CustomRule], store: &Store) -> Vec<Alert> {
    rules.iter().flat_map(|r| evaluate_custom_rule(r, store)).collect()
}

// ---------------------------------------------------------------------------
// Default template written to rules.yaml on first launch
// ---------------------------------------------------------------------------

pub const DEFAULT_RULES_YAML: &str = r#"# TrailInspector Custom Detection Rules
#
# These rules extend the 60 built-in detections. They are evaluated every
# time you run detections. Edit this file and click "Reload Rules" in the
# Detection tab to apply changes without restarting the app.
#
# Rule fields:
#   id              Unique rule ID (e.g. "CR-01"). Duplicate IDs are rejected.
#   name            Display name shown in the Detection tab
#   enabled         Set to false to disable without deleting the rule (default: true)
#   severity        critical | high | medium | low | info
#   mitre_tactic    MITRE ATT&CK tactic (optional)
#   mitre_technique MITRE ATT&CK technique ID (optional, e.g. "T1485")
#   service         AWS service label (optional, e.g. "S3", "IAM", "EC2")
#   description     Alert description shown in the detail panel
#
#   match:
#     event_name    CloudTrail eventName — one name or a list
#
#   filters:        (optional) Boolean filter tree — supports AND / OR / NOT
#     Filterable fields:
#       identity_type, error_code, source_ip, user_name, user_arn,
#       event_source, region, account_id, user_agent, bucket_name
#
#   threshold:      (optional) Only alert if count meets the bar
#     min_count       Minimum matching events required (must be >= 1)
#     window_minutes  If set, min_count must be reached within this window

rules:
  # -- Example 1: simple event match ------------------------------------------
  - id: "CR-01"
    name: "Example: IAM Group Deleted"
    enabled: true
    severity: medium
    mitre_tactic: "Impact"
    mitre_technique: "T1531"
    service: "IAM"
    description: "An IAM group was deleted."
    match:
      event_name: "DeleteGroup"

  # -- Example 2: NOT filter ---------------------------------------------------
  - id: "CR-02"
    name: "Example: EC2 Key Pair Created by Non-Admin"
    enabled: true
    severity: high
    mitre_tactic: "Persistence"
    mitre_technique: "T1098"
    service: "EC2"
    description: "An EC2 key pair was imported by a user other than terraform-admin."
    match:
      event_name: "ImportKeyPair"
    filters:
      not:
        field: user_name
        value: "terraform-admin"

  # -- Example 3: multi-event list + AND/OR filter ----------------------------
  - id: "CR-03"
    name: "Example: Secrets Access by Assumed Role"
    enabled: true
    severity: high
    mitre_tactic: "Credential Access"
    mitre_technique: "T1555"
    service: "SecretsManager"
    description: "Secrets accessed or listed by an assumed role."
    match:
      event_name:
        - "GetSecretValue"
        - "ListSecrets"
    filters:
      field: identity_type
      value: "AssumedRole"

  # -- Example 4: AND / OR / NOT combined -------------------------------------
  - id: "CR-04"
    name: "Example: Suspicious Root or External AssumedRole Activity"
    enabled: true
    severity: critical
    mitre_tactic: "Initial Access"
    mitre_technique: "T1078.004"
    service: "IAM"
    description: "Console login by root or an assumed role not from a known IP."
    match:
      event_name: "ConsoleLogin"
    filters:
      and:
        - or:
            - field: identity_type
              value: "Root"
            - field: identity_type
              value: "AssumedRole"
        - not:
            field: source_ip
            value: "10.0.0.1"

  # -- Example 5: threshold with time window ----------------------------------
  - id: "CR-05"
    name: "Example: Rapid Security Group Changes"
    enabled: true
    severity: high
    mitre_tactic: "Defense Evasion"
    mitre_technique: "T1562.007"
    service: "VPC"
    description: "5 or more security group rule changes within 5 minutes."
    match:
      event_name:
        - "AuthorizeSecurityGroupIngress"
        - "RevokeSecurityGroupIngress"
        - "AuthorizeSecurityGroupEgress"
        - "RevokeSecurityGroupEgress"
    threshold:
      min_count: 5
      window_minutes: 5
"#;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::store::Store;
    use crate::model::{CloudTrailRecord, IndexedRecord, UserIdentity};

    fn default_identity() -> UserIdentity {
        UserIdentity {
            identity_type: Some(Arc::from("IAMUser")),
            principal_id: Some(Arc::from("AIDAEXAMPLE")),
            arn: Some(Arc::from("arn:aws:iam::123456789012:user/alice")),
            account_id: Some(Arc::from("123456789012")),
            access_key_id: None,
            user_name: Some(Arc::from("alice")),
            session_context: None,
            invoked_by: None,
        }
    }

    fn make_rec(event_name: &str, event_source: &str) -> CloudTrailRecord {
        CloudTrailRecord {
            event_time: Arc::from("2024-01-15T10:00:00Z"),
            event_source: Arc::from(event_source),
            event_name: Arc::from(event_name),
            aws_region: Arc::from("us-east-1"),
            source_ip_address: Some(Arc::from("203.0.113.10")),
            user_agent: None,
            user_identity: default_identity(),
            request_parameters: None,
            response_elements: None,
            additional_event_data: None,
            error_code: None,
            error_message: None,
            request_id: None,
            event_id: None,
            event_type: None,
            read_only: None,
            management_event: None,
            recipient_account_id: None,
            event_category: None,
            shared_event_id: None,
            session_credential_from_console: None,
            resources: vec![],
        }
    }

    fn make_indexed(id: u32, event_name: &str, event_source: &str) -> IndexedRecord {
        IndexedRecord {
            id,
            timestamp: id as i64 * 60_000,
            source_file: 0,
            record: make_rec(event_name, event_source),
            request_params_ref: None,
            response_elements_ref: None,
            additional_event_data_ref: None,
        }
    }

    fn make_indexed_ts(id: u32, event_name: &str, ts_ms: i64) -> IndexedRecord {
        let mut r = make_indexed(id, event_name, "test.amazonaws.com");
        r.timestamp = ts_ms;
        r
    }

    fn build_store(records: Vec<IndexedRecord>) -> Store {
        let mut store = Store::new();
        let mut records = records;
        records.sort_by_key(|r| r.id);

        for rec in records.iter_mut() {
            store.drain_blobs(rec);
        }
        store.blob_store.seal().expect("BlobStore seal failed in test");

        for rec in &records {
            let id = rec.id;
            store.idx_event_name.entry(rec.record.event_name.clone()).or_default().push(id);
            store.idx_event_source.entry(rec.record.event_source.clone()).or_default().push(id);
            store.idx_region.entry(rec.record.aws_region.clone()).or_default().push(id);
            if let Some(ip) = &rec.record.source_ip_address {
                store.idx_source_ip.entry(ip.clone()).or_default().push(id);
            }
            if let Some(arn) = &rec.record.user_identity.arn {
                store.idx_user_arn.entry(arn.clone()).or_default().push(id);
            }
            if let Some(name) = &rec.record.user_identity.user_name {
                store.idx_user_name.entry(name.clone()).or_default().push(id);
            }
            if let Some(acct) = &rec.record.user_identity.account_id {
                store.idx_account_id.entry(acct.clone()).or_default().push(id);
            }
            if let Some(err) = &rec.record.error_code {
                store.idx_error_code.entry(err.clone()).or_default().push(id);
            }
            if let Some(t) = &rec.record.user_identity.identity_type {
                store.idx_identity_type.entry(t.clone()).or_default().push(id);
            }
            if let Some(ua) = &rec.record.user_agent {
                store.idx_user_agent.entry(ua.clone()).or_default().push(id);
            }
        }

        let mut sorted: Vec<(i64, u32)> = records.iter().map(|r| (r.timestamp, r.id)).collect();
        sorted.sort_unstable_by_key(|(ts, _)| *ts);
        store.time_sorted_ids = sorted.into_iter().map(|(_, id)| id).collect();
        store.records = records;
        store
    }

    fn simple_rule(event_name: &str) -> CustomRule {
        CustomRule {
            id: "TEST-01".into(),
            name: "Test Rule".into(),
            enabled: true,
            severity: Severity::Medium,
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            service: String::new(),
            description: String::new(),
            match_spec: MatchSpec { event_name: vec![event_name.to_string()] },
            filters: None,
            threshold: None,
        }
    }

    // ── YAML parsing ─────────────────────────────────────────────────────────

    #[test]
    fn default_template_parses_cleanly() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), DEFAULT_RULES_YAML).unwrap();
        let result = load_custom_rules(tmp.path());
        assert!(result.errors.is_empty(), "template errors: {:?}", result.errors);
    }

    #[test]
    fn parse_single_event_name_string() {
        let yaml = r#"
rules:
  - id: "CR-01"
    name: "Test"
    severity: high
    match:
      event_name: "DeleteBucket"
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), yaml).unwrap();
        let result = load_custom_rules(tmp.path());
        assert!(result.errors.is_empty());
        assert_eq!(result.rules[0].match_spec.event_name, vec!["DeleteBucket"]);
    }

    #[test]
    fn parse_event_name_list() {
        let yaml = r#"
rules:
  - id: "CR-01"
    name: "Test"
    severity: medium
    match:
      event_name:
        - "PutBucketPolicy"
        - "PutBucketAcl"
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), yaml).unwrap();
        let result = load_custom_rules(tmp.path());
        assert!(result.errors.is_empty());
        assert_eq!(result.rules[0].match_spec.event_name.len(), 2);
    }

    #[test]
    fn parse_and_or_not_filter() {
        let yaml = r#"
rules:
  - id: "CR-01"
    name: "Complex filter"
    severity: critical
    match:
      event_name: "ConsoleLogin"
    filters:
      and:
        - or:
            - field: identity_type
              value: "Root"
            - field: identity_type
              value: "AssumedRole"
        - not:
            field: source_ip
            value: "10.0.0.1"
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), yaml).unwrap();
        let result = load_custom_rules(tmp.path());
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        assert_eq!(result.rules.len(), 1);
    }

    #[test]
    fn reject_duplicate_ids_both_dropped() {
        let yaml = r#"
rules:
  - id: "CR-01"
    name: "First"
    severity: low
    match:
      event_name: "DeleteBucket"
  - id: "CR-01"
    name: "Duplicate"
    severity: high
    match:
      event_name: "DeleteObject"
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), yaml).unwrap();
        let result = load_custom_rules(tmp.path());
        assert_eq!(result.rules.len(), 0, "both duplicate rules must be rejected");
        assert!(result.errors.iter().any(|e| e.contains("CR-01")));
    }

    #[test]
    fn third_occurrence_of_duplicate_also_rejected() {
        let yaml = r#"
rules:
  - id: "CR-01"
    name: "First"
    severity: low
    match:
      event_name: "DeleteBucket"
  - id: "CR-01"
    name: "Second"
    severity: high
    match:
      event_name: "DeleteObject"
  - id: "CR-01"
    name: "Third"
    severity: medium
    match:
      event_name: "ListBuckets"
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), yaml).unwrap();
        let result = load_custom_rules(tmp.path());
        assert_eq!(result.rules.len(), 0);
    }

    #[test]
    fn reject_zero_min_count() {
        let yaml = r#"
rules:
  - id: "CR-01"
    name: "Bad threshold"
    severity: medium
    match:
      event_name: "DeleteBucket"
    threshold:
      min_count: 0
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), yaml).unwrap();
        let result = load_custom_rules(tmp.path());
        assert_eq!(result.rules.len(), 0);
        assert!(result.errors.iter().any(|e| e.contains("min_count")));
    }

    #[test]
    fn valid_and_invalid_rules_coexist() {
        let yaml = r#"
rules:
  - id: "CR-01"
    name: "Good"
    severity: info
    match:
      event_name: "ListBuckets"
  - id: "CR-01"
    name: "Duplicate — bad"
    severity: high
    match:
      event_name: "DeleteBucket"
  - id: "CR-02"
    name: "Also good"
    severity: medium
    match:
      event_name: "CreateBucket"
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), yaml).unwrap();
        let result = load_custom_rules(tmp.path());
        // CR-01 both dropped, CR-02 accepted
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.rules[0].id, "CR-02");
        assert_eq!(result.errors.len(), 1);
    }

    // ── Evaluation ───────────────────────────────────────────────────────────

    #[test]
    fn disabled_rule_produces_no_alert() {
        let store = build_store(vec![make_indexed(0, "DeleteBucket", "s3.amazonaws.com")]);
        let mut rule = simple_rule("DeleteBucket");
        rule.enabled = false;
        assert!(evaluate_custom_rule(&rule, &store).is_empty());
    }

    #[test]
    fn simple_event_match_fires() {
        let store = build_store(vec![make_indexed(0, "DeleteBucket", "s3.amazonaws.com")]);
        let alerts = evaluate_custom_rule(&simple_rule("DeleteBucket"), &store);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].matching_count, 1);
        assert_eq!(alerts[0].matching_record_ids, vec![0u32]);
    }

    #[test]
    fn no_matching_event_no_alert() {
        let store = build_store(vec![make_indexed(0, "ListBuckets", "s3.amazonaws.com")]);
        assert!(evaluate_custom_rule(&simple_rule("DeleteBucket"), &store).is_empty());
    }

    #[test]
    fn multi_event_name_list_aggregates() {
        let store = build_store(vec![
            make_indexed(0, "PutBucketPolicy", "s3.amazonaws.com"),
            make_indexed(1, "PutBucketAcl", "s3.amazonaws.com"),
        ]);
        let mut rule = simple_rule("PutBucketPolicy");
        rule.match_spec.event_name.push("PutBucketAcl".into());
        let alerts = evaluate_custom_rule(&rule, &store);
        assert_eq!(alerts[0].matching_count, 2);
    }

    #[test]
    fn custom_alert_has_source_metadata() {
        let store = build_store(vec![make_indexed(0, "DeleteBucket", "s3.amazonaws.com")]);
        let alerts = evaluate_custom_rule(&simple_rule("DeleteBucket"), &store);
        assert_eq!(alerts[0].metadata.get("source").map(|s| s.as_str()), Some("custom"));
    }

    // ── Filter: Condition ────────────────────────────────────────────────────

    #[test]
    fn filter_condition_matches_identity_type() {
        let mut rec = make_indexed(0, "DeleteBucket", "s3.amazonaws.com");
        rec.record.user_identity.identity_type = Some(Arc::from("Root"));
        let store = build_store(vec![rec]);
        let mut rule = simple_rule("DeleteBucket");
        rule.filters = Some(FilterExpr::Condition {
            field: FilterField::IdentityType,
            value: "Root".into(),
        });
        assert_eq!(evaluate_custom_rule(&rule, &store).len(), 1);
    }

    #[test]
    fn filter_condition_no_match_no_alert() {
        let store = build_store(vec![make_indexed(0, "DeleteBucket", "s3.amazonaws.com")]);
        let mut rule = simple_rule("DeleteBucket");
        rule.filters = Some(FilterExpr::Condition {
            field: FilterField::IdentityType,
            value: "Root".into(), // record is IAMUser
        });
        assert!(evaluate_custom_rule(&rule, &store).is_empty());
    }

    #[test]
    fn filter_condition_matches_region() {
        let store = build_store(vec![make_indexed(0, "DeleteBucket", "s3.amazonaws.com")]);
        let mut rule = simple_rule("DeleteBucket");
        rule.filters = Some(FilterExpr::Condition {
            field: FilterField::Region,
            value: "us-east-1".into(),
        });
        assert_eq!(evaluate_custom_rule(&rule, &store).len(), 1);
    }

    // ── Filter: NOT ──────────────────────────────────────────────────────────

    #[test]
    fn filter_not_excludes_matching_record() {
        let store = build_store(vec![make_indexed(0, "CreateKey", "kms.amazonaws.com")]);
        let mut rule = simple_rule("CreateKey");
        rule.filters = Some(FilterExpr::Not {
            not: Box::new(FilterExpr::Condition {
                field: FilterField::UserName,
                value: "alice".into(), // alice IS the user → NOT(alice) excludes it
            }),
        });
        assert!(evaluate_custom_rule(&rule, &store).is_empty());
    }

    #[test]
    fn filter_not_passes_non_matching_record() {
        let store = build_store(vec![make_indexed(0, "CreateKey", "kms.amazonaws.com")]);
        let mut rule = simple_rule("CreateKey");
        rule.filters = Some(FilterExpr::Not {
            not: Box::new(FilterExpr::Condition {
                field: FilterField::UserName,
                value: "bob".into(), // alice != bob → NOT(bob) passes → alert
            }),
        });
        assert_eq!(evaluate_custom_rule(&rule, &store).len(), 1);
    }

    // ── Filter: AND ──────────────────────────────────────────────────────────

    #[test]
    fn filter_and_all_conditions_match() {
        let mut rec = make_indexed(0, "DeleteBucket", "s3.amazonaws.com");
        rec.record.user_identity.identity_type = Some(Arc::from("Root"));
        let store = build_store(vec![rec]);
        let mut rule = simple_rule("DeleteBucket");
        rule.filters = Some(FilterExpr::And { and: vec![
            FilterExpr::Condition { field: FilterField::IdentityType, value: "Root".into() },
            FilterExpr::Condition { field: FilterField::Region, value: "us-east-1".into() },
        ]});
        assert_eq!(evaluate_custom_rule(&rule, &store).len(), 1);
    }

    #[test]
    fn filter_and_one_condition_fails_no_alert() {
        let store = build_store(vec![make_indexed(0, "DeleteBucket", "s3.amazonaws.com")]);
        let mut rule = simple_rule("DeleteBucket");
        rule.filters = Some(FilterExpr::And { and: vec![
            FilterExpr::Condition { field: FilterField::IdentityType, value: "Root".into() }, // fails
            FilterExpr::Condition { field: FilterField::Region, value: "us-east-1".into() },
        ]});
        assert!(evaluate_custom_rule(&rule, &store).is_empty());
    }

    // ── Filter: OR ───────────────────────────────────────────────────────────

    #[test]
    fn filter_or_first_condition_matches() {
        let store = build_store(vec![make_indexed(0, "DeleteBucket", "s3.amazonaws.com")]);
        let mut rule = simple_rule("DeleteBucket");
        rule.filters = Some(FilterExpr::Or { or: vec![
            FilterExpr::Condition { field: FilterField::Region, value: "us-east-1".into() }, // passes
            FilterExpr::Condition { field: FilterField::IdentityType, value: "Root".into() }, // fails
        ]});
        assert_eq!(evaluate_custom_rule(&rule, &store).len(), 1);
    }

    #[test]
    fn filter_or_all_conditions_fail_no_alert() {
        let store = build_store(vec![make_indexed(0, "DeleteBucket", "s3.amazonaws.com")]);
        let mut rule = simple_rule("DeleteBucket");
        rule.filters = Some(FilterExpr::Or { or: vec![
            FilterExpr::Condition { field: FilterField::IdentityType, value: "Root".into() },
            FilterExpr::Condition { field: FilterField::Region, value: "ap-southeast-1".into() },
        ]});
        assert!(evaluate_custom_rule(&rule, &store).is_empty());
    }

    // ── Filter: nested AND/OR/NOT ────────────────────────────────────────────

    #[test]
    fn filter_nested_and_or_not() {
        // Rule: (identity_type=Root OR identity_type=AssumedRole) AND NOT(user_name=alice)
        // Record: IAMUser alice → fails OR branch → no alert
        let store = build_store(vec![make_indexed(0, "ConsoleLogin", "signin.amazonaws.com")]);
        let mut rule = simple_rule("ConsoleLogin");
        rule.filters = Some(FilterExpr::And { and: vec![
            FilterExpr::Or { or: vec![
                FilterExpr::Condition { field: FilterField::IdentityType, value: "Root".into() },
                FilterExpr::Condition { field: FilterField::IdentityType, value: "AssumedRole".into() },
            ]},
            FilterExpr::Not { not: Box::new(FilterExpr::Condition {
                field: FilterField::UserName,
                value: "alice".into(),
            })},
        ]});
        assert!(evaluate_custom_rule(&rule, &store).is_empty());
    }

    #[test]
    fn filter_nested_passes_when_conditions_met() {
        // Root user (not alice) → OR passes, NOT(alice) passes → alert
        let mut rec = make_indexed(0, "ConsoleLogin", "signin.amazonaws.com");
        rec.record.user_identity.identity_type = Some(Arc::from("Root"));
        rec.record.user_identity.user_name = Some(Arc::from("root"));
        let store = build_store(vec![rec]);
        let mut rule = simple_rule("ConsoleLogin");
        rule.filters = Some(FilterExpr::And { and: vec![
            FilterExpr::Or { or: vec![
                FilterExpr::Condition { field: FilterField::IdentityType, value: "Root".into() },
                FilterExpr::Condition { field: FilterField::IdentityType, value: "AssumedRole".into() },
            ]},
            FilterExpr::Not { not: Box::new(FilterExpr::Condition {
                field: FilterField::UserName,
                value: "alice".into(),
            })},
        ]});
        assert_eq!(evaluate_custom_rule(&rule, &store).len(), 1);
    }

    // ── Threshold ────────────────────────────────────────────────────────────

    #[test]
    fn threshold_count_met_fires() {
        let store = build_store(vec![
            make_indexed(0, "DeleteBucket", "s3.amazonaws.com"),
            make_indexed(1, "DeleteBucket", "s3.amazonaws.com"),
            make_indexed(2, "DeleteBucket", "s3.amazonaws.com"),
        ]);
        let mut rule = simple_rule("DeleteBucket");
        rule.threshold = Some(Threshold { min_count: 3, window_minutes: None });
        assert_eq!(evaluate_custom_rule(&rule, &store).len(), 1);
    }

    #[test]
    fn threshold_count_not_met_no_alert() {
        let store = build_store(vec![
            make_indexed(0, "DeleteBucket", "s3.amazonaws.com"),
            make_indexed(1, "DeleteBucket", "s3.amazonaws.com"),
        ]);
        let mut rule = simple_rule("DeleteBucket");
        rule.threshold = Some(Threshold { min_count: 3, window_minutes: None });
        assert!(evaluate_custom_rule(&rule, &store).is_empty());
    }

    #[test]
    fn threshold_time_window_met_fires() {
        let base = 1_000_000i64;
        let store = build_store(vec![
            make_indexed_ts(0, "ConsoleLogin", base),
            make_indexed_ts(1, "ConsoleLogin", base + 60_000),
            make_indexed_ts(2, "ConsoleLogin", base + 120_000),
            make_indexed_ts(3, "ConsoleLogin", base + 150_000),
            make_indexed_ts(4, "ConsoleLogin", base + 170_000),
        ]);
        let mut rule = simple_rule("ConsoleLogin");
        rule.threshold = Some(Threshold { min_count: 5, window_minutes: Some(10) });
        assert_eq!(evaluate_custom_rule(&rule, &store).len(), 1);
    }

    #[test]
    fn threshold_time_window_not_met_no_alert() {
        // 5 events each 5 min apart — no 5-within-10-min window exists
        let base = 1_000_000i64;
        let store = build_store(vec![
            make_indexed_ts(0, "ConsoleLogin", base),
            make_indexed_ts(1, "ConsoleLogin", base + 5 * 60_000),
            make_indexed_ts(2, "ConsoleLogin", base + 10 * 60_000),
            make_indexed_ts(3, "ConsoleLogin", base + 15 * 60_000),
            make_indexed_ts(4, "ConsoleLogin", base + 20 * 60_000),
        ]);
        let mut rule = simple_rule("ConsoleLogin");
        rule.threshold = Some(Threshold { min_count: 5, window_minutes: Some(10) });
        assert!(evaluate_custom_rule(&rule, &store).is_empty());
    }

    #[test]
    fn threshold_time_window_boundary_exact_fit() {
        // 3 events exactly at the window boundary — should fire
        let base = 0i64;
        let window_ms = 10 * 60_000i64;
        let store = build_store(vec![
            make_indexed_ts(0, "DeleteBucket", base),
            make_indexed_ts(1, "DeleteBucket", base + window_ms / 2),
            make_indexed_ts(2, "DeleteBucket", base + window_ms),
        ]);
        let mut rule = simple_rule("DeleteBucket");
        rule.threshold = Some(Threshold { min_count: 3, window_minutes: Some(10) });
        assert_eq!(evaluate_custom_rule(&rule, &store).len(), 1);
    }

    // ── run_custom_rules ─────────────────────────────────────────────────────

    #[test]
    fn run_multiple_rules() {
        let store = build_store(vec![
            make_indexed(0, "DeleteBucket", "s3.amazonaws.com"),
            make_indexed(1, "CreateUser", "iam.amazonaws.com"),
        ]);
        let rules = vec![
            simple_rule("DeleteBucket"),
            {
                let mut r = simple_rule("CreateUser");
                r.id = "TEST-02".into();
                r
            },
        ];
        let alerts = run_custom_rules(&rules, &store);
        assert_eq!(alerts.len(), 2);
    }
}
