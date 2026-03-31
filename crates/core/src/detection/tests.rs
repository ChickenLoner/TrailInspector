//! Unit tests for all detection rules added in v0.2.0 (Phases 2 & 3).
//!
//! Each test builds a minimal in-memory Store, injects the one or two CloudTrail
//! events needed to trigger a rule, then asserts the expected alert fires (or
//! does not fire).  A shared `helpers` module provides ergonomic builders.

use std::collections::HashMap;
use serde_json::json;
use crate::store::Store;
use crate::model::{CloudTrailRecord, IndexedRecord, UserIdentity};
use crate::detection::rules;
use crate::detection::run_all_rules;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_identity() -> UserIdentity {
    UserIdentity {
        identity_type: Some("IAMUser".to_string()),
        principal_id: Some("AIDAEXAMPLE0123456789".to_string()),
        arn: Some("arn:aws:iam::123456789012:user/alice".to_string()),
        account_id: Some("123456789012".to_string()),
        access_key_id: None,
        user_name: Some("alice".to_string()),
        session_context: None,
        invoked_by: None,
        extra: HashMap::new(),
    }
}

/// Build a minimal `CloudTrailRecord` with sensible defaults.
fn make_rec(event_name: &str, event_source: &str) -> CloudTrailRecord {
    CloudTrailRecord {
        event_version: None,
        event_time: "2024-01-15T10:00:00Z".to_string(),
        event_source: event_source.to_string(),
        event_name: event_name.to_string(),
        aws_region: "us-east-1".to_string(),
        source_ip_address: Some("203.0.113.10".to_string()),
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
        extra: HashMap::new(),
    }
}

/// Build an IndexedRecord. `id` must equal the eventual index in `Store.records`.
fn make_indexed(id: u64, event_name: &str, event_source: &str) -> IndexedRecord {
    make_indexed_ts(id, event_name, event_source, id as i64 * 60_000)
}

fn make_indexed_ts(id: u64, event_name: &str, event_source: &str, ts_ms: i64) -> IndexedRecord {
    IndexedRecord {
        id,
        timestamp: ts_ms,
        source_file: 0,
        record: make_rec(event_name, event_source),
    }
}

/// Return a copy of `rec` with `request_parameters` replaced.
fn with_params(mut rec: IndexedRecord, params: serde_json::Value) -> IndexedRecord {
    rec.record.request_parameters = Some(params);
    rec
}

/// Return a copy of `rec` with `response_elements` replaced.
fn with_resp(mut rec: IndexedRecord, resp: serde_json::Value) -> IndexedRecord {
    rec.record.response_elements = Some(resp);
    rec
}

/// Build a Store from a slice of IndexedRecords.
///
/// Records **must** be ordered by `id` (0-based) because `Store::get_record(id)`
/// indexes directly into the `records` vector.
fn build_store(records: Vec<IndexedRecord>) -> Store {
    let mut store = Store::new();

    // Sort by id to preserve the id == index invariant
    let mut records = records;
    records.sort_by_key(|r| r.id);

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
        if let Some(params) = &rec.record.request_parameters {
            if let Some(bucket) = params.get("bucketName").and_then(|v| v.as_str()) {
                store.idx_bucket_name.entry(bucket.to_string()).or_default().push(id);
            }
        }
    }

    let mut sorted: Vec<(i64, u64)> = records.iter().map(|r| (r.timestamp, r.id)).collect();
    sorted.sort_unstable_by_key(|(ts, _)| *ts);
    store.time_sorted_ids = sorted.into_iter().map(|(_, id)| id).collect();
    store.records = records;
    store
}

// ---------------------------------------------------------------------------
// Infrastructure
// ---------------------------------------------------------------------------

#[test]
fn test_run_all_rules_empty_store() {
    let store = Store::new();
    let alerts = run_all_rules(&store);
    assert!(alerts.is_empty(), "empty store should produce no alerts");
}

// ---------------------------------------------------------------------------
// Phase 2 — Defense Evasion (new rules DE-05 … DE-09)
// ---------------------------------------------------------------------------

#[test]
fn test_de_05_fires_on_delete_flow_logs() {
    let store = build_store(vec![make_indexed(0, "DeleteFlowLogs", "ec2.amazonaws.com")]);
    let alerts = rules::defense_evasion::de_05_flow_log_deleted(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "DE-05");
    assert_eq!(alerts[0].matching_record_ids, vec![0u64]);
}

#[test]
fn test_de_05_no_fire_on_empty_store() {
    let store = Store::new();
    let alerts = rules::defense_evasion::de_05_flow_log_deleted(&store);
    assert!(alerts.is_empty());
}

#[test]
fn test_de_06_fires_on_delete_log_group() {
    let store = build_store(vec![make_indexed(0, "DeleteLogGroup", "logs.amazonaws.com")]);
    let alerts = rules::defense_evasion::de_06_log_group_deleted(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "DE-06");
}

#[test]
fn test_de_07_fires_when_s3_bucket_changed() {
    let rec = with_params(
        make_indexed(0, "UpdateTrail", "cloudtrail.amazonaws.com"),
        json!({"s3BucketName": "attacker-bucket"}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::defense_evasion::de_07_cloudtrail_s3_changed(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "DE-07");
}

#[test]
fn test_de_07_no_fire_without_s3_bucket_param() {
    let rec = with_params(
        make_indexed(0, "UpdateTrail", "cloudtrail.amazonaws.com"),
        json!({"enableLogFileValidation": true}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::defense_evasion::de_07_cloudtrail_s3_changed(&store);
    assert!(alerts.is_empty(), "UpdateTrail without s3BucketName change must not fire");
}

#[test]
fn test_de_08_fires_on_disable_rule() {
    let store = build_store(vec![make_indexed(0, "DisableRule", "events.amazonaws.com")]);
    let alerts = rules::defense_evasion::de_08_eventbridge_rule_disabled(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "DE-08");
}

#[test]
fn test_de_09_fires_on_delete_web_acl() {
    let store = build_store(vec![make_indexed(0, "DeleteWebACL", "waf.amazonaws.com")]);
    let alerts = rules::defense_evasion::de_09_waf_acl_deleted(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "DE-09");
}

#[test]
fn test_de_09_fires_on_delete_web_acl_v2() {
    let store = build_store(vec![make_indexed(0, "DeleteWebAclV2", "wafv2.amazonaws.com")]);
    let alerts = rules::defense_evasion::de_09_waf_acl_deleted(&store);
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_de_10_fires_on_cloudfront_logging_disabled() {
    let rec = with_params(
        make_indexed(0, "UpdateDistribution", "cloudfront.amazonaws.com"),
        json!({"distributionConfig": {"Logging": {"Enabled": false}}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::defense_evasion::de_10_cloudfront_logging_disabled(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "DE-10");
}

#[test]
fn test_de_10_no_fire_without_logging_disabled() {
    let rec = with_params(
        make_indexed(0, "UpdateDistribution", "cloudfront.amazonaws.com"),
        json!({"distributionConfig": {"comment": "update"}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::defense_evasion::de_10_cloudfront_logging_disabled(&store);
    assert!(alerts.is_empty());
}

#[test]
fn test_de_11_fires_on_sqs_encryption_removed() {
    let rec = with_params(
        make_indexed(0, "SetQueueAttributes", "sqs.amazonaws.com"),
        json!({"attributes": {"KmsMasterKeyId": ""}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::defense_evasion::de_11_sqs_encryption_removed(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "DE-11");
}

#[test]
fn test_de_11_no_fire_with_active_kms_key() {
    let rec = with_params(
        make_indexed(0, "SetQueueAttributes", "sqs.amazonaws.com"),
        json!({"attributes": {"KmsMasterKeyId": "alias/aws/sqs"}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::defense_evasion::de_11_sqs_encryption_removed(&store);
    assert!(alerts.is_empty(), "non-empty KmsMasterKeyId must not fire");
}

#[test]
fn test_de_12_fires_on_sns_encryption_removed() {
    let rec = with_params(
        make_indexed(0, "SetTopicAttributes", "sns.amazonaws.com"),
        json!({"attributeName": "KmsMasterKeyId", "attributeValue": ""}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::defense_evasion::de_12_sns_encryption_removed(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "DE-12");
}

#[test]
fn test_de_13_fires_on_route53_zone_deleted() {
    let store = build_store(vec![make_indexed(0, "DeleteHostedZone", "route53.amazonaws.com")]);
    let alerts = rules::defense_evasion::de_13_route53_zone_deleted(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "DE-13");
}

// ---------------------------------------------------------------------------
// Phase 2 — Network rules (NW-01 … NW-08)
// ---------------------------------------------------------------------------

#[test]
fn test_nw_01_fires_on_open_sg_ipv4() {
    let rec = with_params(
        make_indexed(0, "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com"),
        json!({"cidrIp": "0.0.0.0/0", "fromPort": 22, "toPort": 22}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::network::nw_01_sg_ingress_all(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "NW-01");
}

#[test]
fn test_nw_01_fires_on_open_sg_ipv6() {
    let rec = with_params(
        make_indexed(0, "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com"),
        json!({"cidrIpv6": "::/0", "fromPort": 443, "toPort": 443}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::network::nw_01_sg_ingress_all(&store);
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_nw_01_no_fire_without_open_cidr() {
    let rec = with_params(
        make_indexed(0, "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com"),
        json!({"cidrIp": "10.0.0.0/8", "fromPort": 22, "toPort": 22}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::network::nw_01_sg_ingress_all(&store);
    assert!(alerts.is_empty(), "private CIDR must not fire NW-01");
}

#[test]
fn test_nw_02_fires_on_allow_all_nacl() {
    let rec = with_params(
        make_indexed(0, "CreateNetworkAclEntry", "ec2.amazonaws.com"),
        json!({"cidrBlock": "0.0.0.0/0", "ruleAction": "allow", "ruleNumber": 100}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::network::nw_02_nacl_allows_all(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "NW-02");
}

#[test]
fn test_nw_02_no_fire_on_deny_rule() {
    let rec = with_params(
        make_indexed(0, "CreateNetworkAclEntry", "ec2.amazonaws.com"),
        json!({"cidrBlock": "0.0.0.0/0", "ruleAction": "deny", "ruleNumber": 32767}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::network::nw_02_nacl_allows_all(&store);
    assert!(alerts.is_empty(), "deny rule with 0.0.0.0/0 must not fire NW-02");
}

#[test]
fn test_nw_03_fires_on_igw_created() {
    let store = build_store(vec![make_indexed(0, "CreateInternetGateway", "ec2.amazonaws.com")]);
    let alerts = rules::network::nw_03_igw_created(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "NW-03");
}

#[test]
fn test_nw_03_fires_on_igw_attached() {
    let store = build_store(vec![make_indexed(0, "AttachInternetGateway", "ec2.amazonaws.com")]);
    let alerts = rules::network::nw_03_igw_created(&store);
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_nw_04_fires_on_default_route_create() {
    let rec = with_params(
        make_indexed(0, "CreateRoute", "ec2.amazonaws.com"),
        json!({"destinationCidrBlock": "0.0.0.0/0", "gatewayId": "igw-abc123"}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::network::nw_04_route_to_internet(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "NW-04");
}

#[test]
fn test_nw_04_no_fire_on_private_route() {
    let rec = with_params(
        make_indexed(0, "CreateRoute", "ec2.amazonaws.com"),
        json!({"destinationCidrBlock": "10.0.0.0/8", "gatewayId": "vgw-abc123"}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::network::nw_04_route_to_internet(&store);
    assert!(alerts.is_empty());
}

#[test]
fn test_nw_05_fires_on_vpc_peering() {
    let store = build_store(vec![make_indexed(0, "CreateVpcPeeringConnection", "ec2.amazonaws.com")]);
    let alerts = rules::network::nw_05_vpc_peering_created(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "NW-05");
}

#[test]
fn test_nw_06_fires_on_sg_deleted() {
    let store = build_store(vec![make_indexed(0, "DeleteSecurityGroup", "ec2.amazonaws.com")]);
    let alerts = rules::network::nw_06_sg_deleted(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "NW-06");
}

#[test]
fn test_nw_07_fires_on_subnet_made_public() {
    let rec = with_params(
        make_indexed(0, "ModifySubnetAttribute", "ec2.amazonaws.com"),
        json!({"mapPublicIpOnLaunch": {"value": true}, "subnetId": "subnet-abc123"}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::network::nw_07_subnet_public(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "NW-07");
}

#[test]
fn test_nw_07_no_fire_without_public_ip_flag() {
    let rec = with_params(
        make_indexed(0, "ModifySubnetAttribute", "ec2.amazonaws.com"),
        json!({"mapPublicIpOnLaunch": {"value": false}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::network::nw_07_subnet_public(&store);
    assert!(alerts.is_empty());
}

#[test]
fn test_nw_08_fires_on_nat_deleted() {
    let store = build_store(vec![make_indexed(0, "DeleteNatGateway", "ec2.amazonaws.com")]);
    let alerts = rules::network::nw_08_nat_deleted(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "NW-08");
}

// ---------------------------------------------------------------------------
// Phase 2 — Persistence extensions (PE-05, PE-06, PE-07)
// ---------------------------------------------------------------------------

#[test]
fn test_pe_05_fires_on_mfa_deactivated() {
    let store = build_store(vec![make_indexed(0, "DeactivateMFADevice", "iam.amazonaws.com")]);
    let alerts = rules::persistence_ext::pe_05_mfa_deactivated(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "PE-05");
}

#[test]
fn test_pe_05_fires_on_virtual_mfa_deleted() {
    let store = build_store(vec![make_indexed(0, "DeleteVirtualMFADevice", "iam.amazonaws.com")]);
    let alerts = rules::persistence_ext::pe_05_mfa_deactivated(&store);
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_pe_06_fires_when_set_as_default() {
    let rec = with_params(
        make_indexed(0, "CreatePolicyVersion", "iam.amazonaws.com"),
        json!({"policyArn": "arn:aws:iam::123456789012:policy/MyPolicy", "setAsDefault": true}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::persistence_ext::pe_06_policy_version_created(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "PE-06");
}

#[test]
fn test_pe_06_no_fire_without_set_as_default() {
    let rec = with_params(
        make_indexed(0, "CreatePolicyVersion", "iam.amazonaws.com"),
        json!({"policyArn": "arn:aws:iam::123456789012:policy/MyPolicy", "setAsDefault": false}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::persistence_ext::pe_06_policy_version_created(&store);
    assert!(alerts.is_empty());
}

#[test]
fn test_pe_07_fires_on_cross_account_assume_role() {
    let mut rec = make_indexed(0, "AssumeRole", "sts.amazonaws.com");
    rec.record.user_identity.account_id = Some("111111111111".to_string());
    let rec = with_params(
        rec,
        json!({"roleArn": "arn:aws:iam::999999999999:role/CrossAccountRole"}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::persistence_ext::pe_07_cross_account_assume_role(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "PE-07");
}

#[test]
fn test_pe_07_no_fire_on_same_account_assume_role() {
    let mut rec = make_indexed(0, "AssumeRole", "sts.amazonaws.com");
    rec.record.user_identity.account_id = Some("123456789012".to_string());
    let rec = with_params(
        rec,
        json!({"roleArn": "arn:aws:iam::123456789012:role/SameAccountRole"}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::persistence_ext::pe_07_cross_account_assume_role(&store);
    assert!(alerts.is_empty(), "same-account AssumeRole must not fire PE-07");
}

// ---------------------------------------------------------------------------
// Phase 2 — Credential Access (CA-05) + Phase 3 (CA-06)
// ---------------------------------------------------------------------------

#[test]
fn test_ca_05_fires_on_successful_root_login() {
    let mut rec = make_indexed(0, "ConsoleLogin", "signin.amazonaws.com");
    rec.record.user_identity.identity_type = Some("Root".to_string());
    let rec = with_resp(rec, json!({"ConsoleLogin": "Success"}));
    let store = build_store(vec![rec]);
    let alerts = rules::credential_access::ca_05_root_console_login(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "CA-05");
}

#[test]
fn test_ca_05_no_fire_on_non_root_login() {
    let rec = with_resp(
        make_indexed(0, "ConsoleLogin", "signin.amazonaws.com"),
        json!({"ConsoleLogin": "Success"}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::credential_access::ca_05_root_console_login(&store);
    assert!(alerts.is_empty(), "IAMUser login must not fire CA-05");
}

#[test]
fn test_ca_05_no_fire_on_root_login_failure() {
    let mut rec = make_indexed(0, "ConsoleLogin", "signin.amazonaws.com");
    rec.record.user_identity.identity_type = Some("Root".to_string());
    let rec = with_resp(rec, json!({"ConsoleLogin": "Failure"}));
    let store = build_store(vec![rec]);
    let alerts = rules::credential_access::ca_05_root_console_login(&store);
    assert!(alerts.is_empty(), "failed root login must not fire CA-05");
}

#[test]
fn test_ca_06_fires_on_kms_key_deletion_scheduled() {
    let store = build_store(vec![make_indexed(0, "ScheduleKeyDeletion", "kms.amazonaws.com")]);
    let alerts = rules::credential_access::ca_06_kms_key_deletion(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "CA-06");
}

// ---------------------------------------------------------------------------
// Phase 2 — RDS rules (RDS-01, RDS-02, RDS-03)
// ---------------------------------------------------------------------------

#[test]
fn test_rds_01_fires_on_deletion_protection_disabled() {
    let rec = with_params(
        make_indexed(0, "ModifyDBInstance", "rds.amazonaws.com"),
        json!({"dbInstanceIdentifier": "mydb", "deletionProtection": false}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::rds::rds_01_deletion_protection_disabled(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "RDS-01");
}

#[test]
fn test_rds_01_no_fire_without_deletion_protection_param() {
    let rec = with_params(
        make_indexed(0, "ModifyDBInstance", "rds.amazonaws.com"),
        json!({"dbInstanceIdentifier": "mydb", "allocatedStorage": 100}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::rds::rds_01_deletion_protection_disabled(&store);
    assert!(alerts.is_empty());
}

#[test]
fn test_rds_02_fires_on_public_restore() {
    let rec = with_params(
        make_indexed(0, "RestoreDBInstanceFromDBSnapshot", "rds.amazonaws.com"),
        json!({"dbSnapshotIdentifier": "snap-abc", "publiclyAccessible": true}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::rds::rds_02_public_snapshot_restore(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "RDS-02");
}

#[test]
fn test_rds_02_no_fire_on_private_restore() {
    let rec = with_params(
        make_indexed(0, "RestoreDBInstanceFromDBSnapshot", "rds.amazonaws.com"),
        json!({"dbSnapshotIdentifier": "snap-abc", "publiclyAccessible": false}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::rds::rds_02_public_snapshot_restore(&store);
    assert!(alerts.is_empty());
}

#[test]
fn test_rds_03_fires_on_master_password_changed() {
    let rec = with_params(
        make_indexed(0, "ModifyDBInstance", "rds.amazonaws.com"),
        json!({"dbInstanceIdentifier": "mydb", "masterUserPassword": "NewP@ss123"}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::rds::rds_03_master_password_changed(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "RDS-03");
}

// ---------------------------------------------------------------------------
// Phase 3 — EBS rules (EBS-01 … EBS-05)
// ---------------------------------------------------------------------------

#[test]
fn test_ebs_01_fires_on_encryption_disabled() {
    let store = build_store(vec![
        make_indexed(0, "DisableEbsEncryptionByDefault", "ec2.amazonaws.com")
    ]);
    let alerts = rules::ebs::ebs_01_encryption_disabled(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "EBS-01");
}

#[test]
fn test_ebs_02_fires_on_snapshot_made_public() {
    let rec = with_params(
        make_indexed(0, "ModifySnapshotAttribute", "ec2.amazonaws.com"),
        json!({"snapshotId": "snap-abc", "createVolumePermission": {"add": {"items": [{"group": "all"}]}}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::ebs::ebs_02_snapshot_public(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "EBS-02");
}

#[test]
fn test_ebs_02_no_fire_without_all_group() {
    let rec = with_params(
        make_indexed(0, "ModifySnapshotAttribute", "ec2.amazonaws.com"),
        json!({"snapshotId": "snap-abc", "createVolumePermission": {"add": {"items": [{"userId": "123456789012"}]}}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::ebs::ebs_02_snapshot_public(&store);
    // Note: rule also fires if "all" appears as substring anywhere in params
    // This test verifies when there's no "all" group term
    // The actual rule checks for `"all"` substring, so userId=123456789012 shouldn't contain "all"
    assert!(alerts.is_empty());
}

#[test]
fn test_ebs_03_fires_on_volume_detached() {
    let store = build_store(vec![make_indexed(0, "DetachVolume", "ec2.amazonaws.com")]);
    let alerts = rules::ebs::ebs_03_volume_detached(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "EBS-03");
}

#[test]
fn test_ebs_04_fires_on_snapshot_deleted() {
    let store = build_store(vec![make_indexed(0, "DeleteSnapshot", "ec2.amazonaws.com")]);
    let alerts = rules::ebs::ebs_04_snapshot_deleted(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "EBS-04");
}

#[test]
fn test_ebs_05_fires_on_kms_key_changed() {
    let store = build_store(vec![
        make_indexed(0, "ModifyEbsDefaultKmsKeyId", "ec2.amazonaws.com")
    ]);
    let alerts = rules::ebs::ebs_05_default_kms_changed(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "EBS-05");
}

// ---------------------------------------------------------------------------
// Phase 3 — Lambda rules (LM-01, LM-02)
// ---------------------------------------------------------------------------

#[test]
fn test_lm_01_fires_on_public_lambda_access() {
    let rec = with_params(
        make_indexed(0, "AddPermission20150331v2", "lambda.amazonaws.com"),
        json!({"functionName": "my-fn", "principal": "*", "action": "lambda:InvokeFunction"}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::lambda::lm_01_lambda_public_access(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "LM-01");
}

#[test]
fn test_lm_01_no_fire_without_wildcard_principal() {
    let rec = with_params(
        make_indexed(0, "AddPermission20150331v2", "lambda.amazonaws.com"),
        json!({"functionName": "my-fn", "principal": "123456789012", "action": "lambda:InvokeFunction"}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::lambda::lm_01_lambda_public_access(&store);
    assert!(alerts.is_empty(), "specific-account principal must not fire LM-01");
}

#[test]
fn test_lm_02_fires_on_env_vars_updated() {
    let rec = with_params(
        make_indexed(0, "UpdateFunctionConfiguration20150331v2", "lambda.amazonaws.com"),
        json!({"functionName": "my-fn", "Environment": {"Variables": {"KEY": "VALUE"}}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::lambda::lm_02_lambda_env_updated(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "LM-02");
}

// ---------------------------------------------------------------------------
// Phase 3 — Exfiltration new rules (EX-02 … EX-05)
// ---------------------------------------------------------------------------

#[test]
fn test_ex_02_fires_on_bucket_deleted() {
    let store = build_store(vec![make_indexed(0, "DeleteBucket", "s3.amazonaws.com")]);
    let alerts = rules::exfiltration::ex_02_s3_bucket_deleted(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "EX-02");
}

#[test]
fn test_ex_03_fires_on_bulk_download_within_window() {
    // 50 GetObject events by the same identity within 5 minutes (300_000 ms)
    let base_ts: i64 = 1_700_000_000_000;
    let interval_ms: i64 = 5_000; // 5 s apart → 50 events ≈ 4 min total
    let records: Vec<IndexedRecord> = (0u64..50)
        .map(|i| {
            let mut rec = make_indexed_ts(
                i,
                "GetObject",
                "s3.amazonaws.com",
                base_ts + i as i64 * interval_ms,
            );
            rec.record.user_identity.arn =
                Some("arn:aws:iam::123456789012:user/alice".to_string());
            rec
        })
        .collect();
    let store = build_store(records);
    let alerts = rules::exfiltration::ex_03_s3_bulk_download(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "EX-03");
    assert_eq!(alerts[0].matching_record_ids.len(), 50);
}

#[test]
fn test_ex_03_no_fire_below_threshold() {
    // Only 10 GetObject events — below the 50-event threshold
    let base_ts: i64 = 1_700_000_000_000;
    let records: Vec<IndexedRecord> = (0u64..10)
        .map(|i| make_indexed_ts(i, "GetObject", "s3.amazonaws.com", base_ts + i as i64 * 1000))
        .collect();
    let store = build_store(records);
    let alerts = rules::exfiltration::ex_03_s3_bulk_download(&store);
    assert!(alerts.is_empty());
}

#[test]
fn test_ex_03_no_fire_when_spread_across_windows() {
    // 50 GetObject events by same identity but spaced > 5 min apart in pairs
    let base_ts: i64 = 1_700_000_000_000;
    let ten_min_ms: i64 = 10 * 60 * 1000;
    let records: Vec<IndexedRecord> = (0u64..50)
        .map(|i| {
            let mut rec = make_indexed_ts(
                i,
                "GetObject",
                "s3.amazonaws.com",
                base_ts + i as i64 * ten_min_ms, // each 10 min apart — never 50 in 5 min
            );
            rec.record.user_identity.arn =
                Some("arn:aws:iam::123456789012:user/alice".to_string());
            rec
        })
        .collect();
    let store = build_store(records);
    let alerts = rules::exfiltration::ex_03_s3_bulk_download(&store);
    assert!(alerts.is_empty(), "50 events spread over 8+ hours must not fire EX-03");
}

#[test]
fn test_ex_04_fires_on_logging_disabled() {
    let rec = with_params(
        make_indexed(0, "PutBucketLogging", "s3.amazonaws.com"),
        json!({"BucketLoggingStatus": {}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::exfiltration::ex_04_s3_logging_disabled(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "EX-04");
}

#[test]
fn test_ex_04_no_fire_with_logging_config_present() {
    let rec = with_params(
        make_indexed(0, "PutBucketLogging", "s3.amazonaws.com"),
        json!({
            "BucketLoggingStatus": {
                "LoggingEnabled": {
                    "TargetBucket": "my-access-logs",
                    "TargetPrefix": "logs/"
                }
            }
        }),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::exfiltration::ex_04_s3_logging_disabled(&store);
    assert!(alerts.is_empty(), "PutBucketLogging with LoggingEnabled must not fire EX-04");
}

#[test]
fn test_ex_05_fires_on_bucket_encryption_removed() {
    let store = build_store(vec![
        make_indexed(0, "DeleteBucketEncryption", "s3.amazonaws.com")
    ]);
    let alerts = rules::exfiltration::ex_05_s3_encryption_removed(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "EX-05");
}

// ---------------------------------------------------------------------------
// Phase 3 — Resource Sharing rules (RS-01, RS-02, RS-03)
// ---------------------------------------------------------------------------

#[test]
fn test_rs_01_fires_on_ami_made_public() {
    let rec = with_params(
        make_indexed(0, "ModifyImageAttribute", "ec2.amazonaws.com"),
        json!({"imageId": "ami-abc123", "launchPermission": {"add": {"items": [{"group": "all"}]}}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::resource_sharing::rs_01_ami_made_public(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "RS-01");
}

#[test]
fn test_rs_01_no_fire_without_all_group() {
    let rec = with_params(
        make_indexed(0, "ModifyImageAttribute", "ec2.amazonaws.com"),
        json!({"imageId": "ami-abc123", "description": {"value": "updated"}}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::resource_sharing::rs_01_ami_made_public(&store);
    assert!(alerts.is_empty());
}

#[test]
fn test_rs_02_fires_on_ssm_doc_public() {
    let rec = with_params(
        make_indexed(0, "ModifyDocumentPermission", "ssm.amazonaws.com"),
        json!({"name": "MyDoc", "permissionType": "Share", "accountIdsToAdd": ["All"]}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::resource_sharing::rs_02_ssm_document_public(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "RS-02");
}

#[test]
fn test_rs_03_fires_on_rds_snapshot_public() {
    let rec = with_params(
        make_indexed(0, "ModifyDBSnapshotAttribute", "rds.amazonaws.com"),
        json!({"dbSnapshotIdentifier": "snap-abc", "attributeName": "restore", "valuesToAdd": ["all"]}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::resource_sharing::rs_03_rds_snapshot_public(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "RS-03");
}

#[test]
fn test_rs_03_fires_on_cluster_snapshot_public() {
    let rec = with_params(
        make_indexed(0, "ModifyDBClusterSnapshotAttribute", "rds.amazonaws.com"),
        json!({"dbClusterSnapshotIdentifier": "cluster-snap", "attributeName": "restore", "valuesToAdd": ["all"]}),
    );
    let store = build_store(vec![rec]);
    let alerts = rules::resource_sharing::rs_03_rds_snapshot_public(&store);
    assert_eq!(alerts.len(), 1);
}

// ---------------------------------------------------------------------------
// Phase 3 — Impact new rule (IM-03)
// ---------------------------------------------------------------------------

#[test]
fn test_im_03_fires_on_ses_email_verified() {
    let store = build_store(vec![make_indexed(0, "VerifyEmailIdentity", "ses.amazonaws.com")]);
    let alerts = rules::impact::im_03_ses_email_verified(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "IM-03");
}

// ---------------------------------------------------------------------------
// Counts and severity ordering
// ---------------------------------------------------------------------------

#[test]
fn test_matching_record_count_is_accurate() {
    // Two DeleteFlowLogs events → alert should reference both record IDs
    let store = build_store(vec![
        make_indexed(0, "DeleteFlowLogs", "ec2.amazonaws.com"),
        make_indexed(1, "DeleteFlowLogs", "ec2.amazonaws.com"),
    ]);
    let alerts = rules::defense_evasion::de_05_flow_log_deleted(&store);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].matching_record_ids.len(), 2);
}

#[test]
fn test_run_all_rules_sorts_by_severity_descending() {
    // Inject Critical (DE-01) and Low (NW-06) events so both rules fire
    let store = build_store(vec![
        make_indexed(0, "StopLogging", "cloudtrail.amazonaws.com"),
        make_indexed(1, "DeleteSecurityGroup", "ec2.amazonaws.com"),
    ]);
    let alerts = run_all_rules(&store);
    assert!(alerts.len() >= 2);
    // First alert must have severity >= last alert
    assert!(alerts[0].severity >= alerts[alerts.len() - 1].severity);
}

// ---------------------------------------------------------------------------
// Performance — run all 58 rules over 100,000 synthetic records
// (skipped in normal CI; run with: cargo test -- --ignored bench)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn bench_detection_100k_records() {
    use std::time::Instant;

    let event_names = [
        "ConsoleLogin", "StopLogging", "DeleteBucket", "CreateUser",
        "AttachUserPolicy", "GetObject", "RunInstances", "DeleteFlowLogs",
        "AuthorizeSecurityGroupIngress", "DeleteWebACL", "ScheduleKeyDeletion",
        "ModifyDBInstance", "DisableEbsEncryptionByDefault", "DeleteSnapshot",
    ];

    let records: Vec<IndexedRecord> = (0u64..100_000)
        .map(|i| {
            let event = event_names[i as usize % event_names.len()];
            make_indexed_ts(i, event, "ec2.amazonaws.com", i as i64 * 100)
        })
        .collect();

    let store = build_store(records);

    let start = Instant::now();
    let alerts = run_all_rules(&store);
    let elapsed = start.elapsed();

    println!("Detection on 100K records: {:?}, {} alerts fired", elapsed, alerts.len());
    assert!(
        elapsed.as_secs() < 2,
        "Detection took {:?}, expected < 2s",
        elapsed
    );
}
