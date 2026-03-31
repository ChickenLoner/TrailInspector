# TrailInspector Detection Rules

TrailInspector ships **60 detection rules** mapped to MITRE ATT&CK tactics and techniques.  
Rules are evaluated entirely in-memory against the loaded CloudTrail event set — no network calls required.

Rules are organised by tactic below. Each entry shows the rule ID, name, severity, the AWS service it monitors, the MITRE technique, and the CloudTrail event(s) that trigger it.

---

## Severity Legend

| Severity | Colour | Meaning |
|----------|--------|---------|
| Critical | Red | Immediate response required — direct evidence of compromise |
| High | Orange | Strong indicator of attack or misconfiguration |
| Medium | Yellow | Suspicious activity worth investigating |
| Low | Blue | Noteworthy change; investigate in context |
| Info | Grey | Informational; expected in some environments |

---

## Initial Access

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| IA-01 | Console Login Without MFA | High | IAM | T1078.004 | `ConsoleLogin` (MFA not used) |
| IA-03 | Root Account Usage | Critical | IAM | T1078.004 | Any event from Root identity |
| IA-04 | Failed Login Brute Force | High | IAM | T1110.001 | ≥5 failed `ConsoleLogin` from same IP in 10 min |

---

## Persistence

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| PE-01 | IAM User Created | Medium | IAM | T1136.003 | `CreateUser` |
| PE-02 | Access Key Created for Another User | High | IAM | T1098.001 | `CreateAccessKey` (different principal) |
| PE-03 | Login Profile Created | Medium | IAM | T1098 | `CreateLoginProfile` |
| PE-04 | Backdoor Admin Policy Attached | Critical | IAM | T1098.003 | `AttachUserPolicy` / `AttachGroupPolicy` / `AttachRolePolicy` with admin ARN |
| PE-05 | MFA Device Deactivated | High | IAM | T1556.006 | `DeactivateMFADevice`, `DeleteVirtualMFADevice` |
| PE-06 | IAM Policy Version Created (SetAsDefault) | Medium | IAM | T1098.003 | `CreatePolicyVersion` with `setAsDefault=true` |
| PE-07 | Cross-Account AssumeRole | Medium | STS | T1098.001 | `AssumeRole` where caller account ≠ role account |

---

## Defense Evasion

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| DE-01 | CloudTrail Stopped or Deleted | Critical | CloudTrail | T1562.008 | `StopLogging`, `DeleteTrail`, `UpdateTrail` |
| DE-02 | GuardDuty Disabled | Critical | GuardDuty | T1562.001 | `DeleteDetector`, `StopMonitoringMembers`, `DisassociateMembers` |
| DE-04 | Config Recorder Stopped | High | Config | T1562.001 | `StopConfigurationRecorder`, `DeleteConfigurationRecorder` |
| DE-05 | VPC Flow Log Deletion | Critical | VPC | T1562.008 | `DeleteFlowLogs` |
| DE-06 | CloudWatch Log Group Deleted | High | CloudWatch | T1562.008 | `DeleteLogGroup` |
| DE-07 | CloudTrail S3 Logging Bucket Changed | High | CloudTrail | T1562.008 | `UpdateTrail` with `s3BucketName` in request |
| DE-08 | EventBridge Rule Disabled | Medium | EventBridge | T1562.001 | `DisableRule` |
| DE-09 | WAF Web ACL Deleted | High | WAF | T1562.001 | `DeleteWebACL`, `DeleteWebAclV2` |
| DE-10 | CloudFront Distribution Logging Disabled | Medium | CloudFront | T1562.008 | `UpdateDistribution` with `Enabled:false` in logging config |
| DE-11 | SQS Queue Encryption Removed | Medium | SQS | T1562.001 | `SetQueueAttributes` with empty `KmsMasterKeyId` |
| DE-12 | SNS Topic Encryption Removed | Medium | SNS | T1562.001 | `SetTopicAttributes` with empty `attributeValue` for KmsMasterKeyId |
| DE-13 | Route53 Hosted Zone Deleted | Medium | Route53 | T1485 | `DeleteHostedZone` |

---

## Credential Access

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| CA-02 | Secrets Manager Bulk Access | High | SecretsManager | T1555 | >5 `GetSecretValue` by same identity in 10 min |
| CA-04 | Password Policy Weakened | Medium | IAM | T1556 | `UpdateAccountPasswordPolicy` |
| CA-05 | Root Account Console Login | Critical | IAM | T1078.004 | Successful `ConsoleLogin` from Root identity |
| CA-06 | KMS Key Scheduled for Deletion | High | KMS | T1485 | `ScheduleKeyDeletion` |

---

## Discovery

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| DI-02 | IAM Enumeration | Medium | IAM | T1087.004 | Multiple `GetUser` / `ListUsers` / `GetRole` / `ListRoles` in short window |
| DI-03 | AccessDenied Spike | Medium | IAM | T1580 | Multiple `AccessDenied` errors in time window |

---

## Exfiltration

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| EX-01 | S3 Bucket Made Public | High | S3 | T1537 | `PutBucketPolicy` / `PutBucketAcl` with `Principal=*` or public grantee |
| EX-02 | S3 Bucket Deleted | Medium | S3 | T1485 | `DeleteBucket` |
| EX-03 | S3 Bulk Object Download | Medium | S3 | T1530 | ≥50 `GetObject` by same identity within 5 min |
| EX-04 | S3 Bucket Access Logging Disabled | Medium | S3 | T1562.008 | `PutBucketLogging` with empty `BucketLoggingStatus` |
| EX-05 | S3 Bucket Encryption Removed | High | S3 | T1537 | `DeleteBucketEncryption` |

---

## Impact

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| IM-01 | EC2 Instances Launched in Bulk | High | EC2 | T1496 | Multiple `RunInstances` in short window |
| IM-02 | Resource Deletion Spree | Critical | Multi | T1485 | Multiple delete events across services in short time |
| IM-03 | SES Email Identity Verified | Low | SES | T1534 | `VerifyEmailIdentity` |

---

## Network / VPC

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| NW-01 | Security Group Ingress Open to 0.0.0.0/0 | High | VPC | T1562.007 | `AuthorizeSecurityGroupIngress` with `0.0.0.0/0` or `::/0` |
| NW-02 | Network ACL Allows All Traffic | Medium | VPC | T1562.007 | `CreateNetworkAclEntry` / `ReplaceNetworkAclEntry` allow rule with `0.0.0.0/0` |
| NW-03 | Internet Gateway Created | Info | VPC | T1562.007 | `CreateInternetGateway`, `AttachInternetGateway` |
| NW-04 | Route to Internet Added | Medium | VPC | T1562.007 | `CreateRoute` / `ReplaceRoute` with destination `0.0.0.0/0` |
| NW-05 | VPC Peering Connection Created | Info | VPC | T1021 | `CreateVpcPeeringConnection` |
| NW-06 | Security Group Deleted | Low | VPC | T1562.007 | `DeleteSecurityGroup` |
| NW-07 | Subnet Auto-Assign Public IP Enabled | Medium | VPC | T1562.007 | `ModifySubnetAttribute` with `mapPublicIpOnLaunch=true` |
| NW-08 | NAT Gateway Deleted | Low | VPC | T1485 | `DeleteNatGateway` |

---

## RDS

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| RDS-01 | RDS Deletion Protection Disabled | High | RDS | T1485 | `ModifyDBInstance` / `ModifyDBCluster` with `deletionProtection=false` |
| RDS-02 | RDS Instance Restored with Public Access | High | RDS | T1537 | `RestoreDBInstanceFromDBSnapshot` etc. with `publiclyAccessible=true` |
| RDS-03 | RDS Master Password Changed | Medium | RDS | T1098 | `ModifyDBInstance` / `ModifyDBCluster` with `masterUserPassword` in request |

---

## EBS

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| EBS-01 | EBS Default Encryption Disabled | High | EBS | T1486 | `DisableEbsEncryptionByDefault` |
| EBS-02 | EBS Snapshot Made Public | Critical | EBS | T1537 | `ModifySnapshotAttribute` granting `all` group access |
| EBS-03 | EBS Volume Detached | Low | EBS | T1537 | `DetachVolume` |
| EBS-04 | EBS Snapshot Deleted | Medium | EBS | T1485 | `DeleteSnapshot` |
| EBS-05 | EBS Default KMS Key Changed | Medium | EBS | T1486 | `ModifyEbsDefaultKmsKeyId` |

---

## Lambda

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| LM-01 | Lambda Function Granted Public Access | High | Lambda | T1098 | `AddPermission20150331v2` with `principal=*` |
| LM-02 | Lambda Environment Variables Updated | Low | Lambda | T1525 | `UpdateFunctionConfiguration20150331v2` with `Environment` key |

---

## Resource Sharing

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| RS-01 | EC2 AMI Made Public | High | EC2 | T1537 | `ModifyImageAttribute` granting `launchPermission` to `all` |
| RS-02 | SSM Document Made Public | High | SSM | T1537 | `ModifyDocumentPermission` with `All` accounts |
| RS-03 | RDS Snapshot Made Public | High | RDS | T1537 | `ModifyDBSnapshotAttribute` / `ModifyDBClusterSnapshotAttribute` with `all` |

---

## Geo Anomaly *(requires GeoLite2 MMDB files)*

| ID | Rule | Severity | Service | Technique | Trigger Events |
|----|------|----------|---------|-----------|----------------|
| GEO-01 | Multi-Country Access | Medium | IAM | T1078 | Same identity observed from 2+ countries |
| GEO-02 | Console Login from Unusual Country | High | IAM | T1078.004 | `ConsoleLogin` from country not seen in identity's history |

---

## Rule Coverage Summary

| Category | Rules | New in v0.2.0 |
|----------|-------|--------------|
| Initial Access | 3 | — |
| Persistence | 7 | PE-05, PE-06, PE-07 |
| Defense Evasion | 13 | DE-05 … DE-13 |
| Credential Access | 4 | CA-05, CA-06 |
| Discovery | 2 | — |
| Exfiltration | 5 | EX-02 … EX-05 |
| Impact | 3 | IM-03 |
| Network/VPC | 8 | NW-01 … NW-08 |
| RDS | 3 | RDS-01 … RDS-03 |
| EBS | 5 | EBS-01 … EBS-05 |
| Lambda | 2 | LM-01, LM-02 |
| Resource Sharing | 3 | RS-01 … RS-03 |
| Geo Anomaly | 2 | GEO-01, GEO-02 |
| **Total** | **60** | **+42** |

---

## Adding Custom Rules

Rules live in `crates/core/src/detection/rules/`. To add a new rule:

1. Add a function `fn my_rule(store: &Store) -> Vec<Alert>` to the appropriate tactic file (or a new file).
2. Register it in `crates/core/src/detection/mod.rs` inside `all_rules()`.
3. Add unit tests in `crates/core/src/detection/tests.rs`.

See any existing rule function as a template — the pattern is: look up event names via `store.idx_event_name`, optionally filter on `request_parameters` / `response_elements`, then return a `Vec<Alert>`.
