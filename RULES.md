# TrailInspector Detection Rules

TrailInspector ships **60 built-in detection rules** mapped to MITRE ATT&CK tactics and techniques, plus a **custom YAML rule engine** so you can write your own rules without touching Rust code.

All rules run entirely in-memory against the loaded CloudTrail event set — no network calls required.

---

## Contents

- [Severity Legend](#severity-legend)
- [Built-in Rules](#built-in-rules)
  - [Initial Access](#initial-access)
  - [Persistence](#persistence)
  - [Defense Evasion](#defense-evasion)
  - [Credential Access](#credential-access)
  - [Discovery](#discovery)
  - [Exfiltration](#exfiltration)
  - [Impact](#impact)
  - [Network / VPC](#network--vpc)
  - [RDS](#rds)
  - [EBS](#ebs)
  - [Lambda](#lambda)
  - [Resource Sharing](#resource-sharing)
  - [Geo Anomaly](#geo-anomaly)
  - [Coverage Summary](#rule-coverage-summary)
- [Custom YAML Rules](#custom-yaml-rules)

---

## Severity Legend

| Severity | Meaning |
|----------|---------|
| **Critical** | Immediate response required — direct evidence of compromise |
| **High** | Strong indicator of attack or misconfiguration |
| **Medium** | Suspicious activity worth investigating |
| **Low** | Noteworthy change; investigate in context |
| **Info** | Informational; expected in some environments |

---

## Built-in Rules

### Initial Access

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| IA-01 | Console Login Without MFA | High | IAM | T1078.004 |
| IA-03 | Root Account Usage | Critical | IAM | T1078.004 |
| IA-04 | Failed Login Brute Force | High | IAM | T1110.001 |

---

#### IA-01 — Console Login Without MFA

**Trigger:** `ConsoleLogin` event where `additionalEventData.MFAUsed != "Yes"` and identity type is `IAMUser` (root logins are handled separately by IA-03 / CA-05).

**Criteria:**
- Event name: `ConsoleLogin`
- Response: `ConsoleLogin = "Success"`
- `additionalEventData.MFAUsed` is absent or not `"Yes"`
- Identity type: `IAMUser` (not Root)

**Why it matters:** Console access without MFA means a stolen password alone grants full AWS Console access. Any IAM user with console access should have MFA enforced via an IAM policy.

**False positives:** Service accounts or CI/CD users that are not supposed to use the console. Suppress by restricting those identities via IAM policy to deny console login entirely.

---

#### IA-03 — Root Account Usage

**Trigger:** Any successful API call or console login where `userIdentity.type = "Root"`.

**Criteria:**
- `userIdentity.type = "Root"`
- Any event (not just console login)
- No error in response required — any Root activity fires this rule

**Why it matters:** Root has unlimited permissions that cannot be restricted by IAM policies. AWS best practice is to lock away Root credentials and use IAM users or roles for all operations. Any Root activity is inherently suspicious.

**False positives:** Legitimate Root use cases include recovering a locked account, changing account settings, or billing tasks not yet delegated. These should be rare, documented, and time-boxed.

---

#### IA-04 — Failed Login Brute Force

**Trigger:** ≥ 5 failed `ConsoleLogin` events from the **same source IP** within a **10-minute sliding window**.

**Criteria:**
- Event name: `ConsoleLogin`
- `responseElements.ConsoleLogin = "Failure"`
- Same `sourceIPAddress`
- ≥ 5 failures within 600 seconds

**Why it matters:** Repeated failed console logins from a single IP indicate a credential-stuffing or brute-force attack. AWS does not rate-limit console login attempts by default.

**False positives:** A user who repeatedly misremembers their password. Check whether the failures resolve into a success; if so, treat as a user error rather than an attack.

---

### Persistence

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| PE-01 | IAM User Created | Medium | IAM | T1136.003 |
| PE-02 | Access Key Created for Another User | High | IAM | T1098.001 |
| PE-03 | Login Profile Created | Medium | IAM | T1098 |
| PE-04 | Backdoor Admin Policy Attached | Critical | IAM | T1098.003 |
| PE-05 | MFA Device Deactivated | High | IAM | T1556.006 |
| PE-06 | IAM Policy Version Created (SetAsDefault) | Medium | IAM | T1098.003 |
| PE-07 | Cross-Account AssumeRole | Medium | STS | T1098.001 |

---

#### PE-01 — IAM User Created

**Trigger:** `CreateUser` event.

**Criteria:**
- Event name: `CreateUser`
- No error in response

**Why it matters:** Creating a new IAM user is a common persistence technique — attackers provision a new account they control after gaining initial access. Alert on any `CreateUser` not correlated with an approved provisioning workflow.

**False positives:** Legitimate HR onboarding or terraform provisioning. Correlate with change tickets.

---

#### PE-02 — Access Key Created for Another User

**Trigger:** `CreateAccessKey` where the target user differs from the calling identity.

**Criteria:**
- Event name: `CreateAccessKey`
- `requestParameters.userName` is present and does not match `userIdentity.userName` of the caller

**Why it matters:** Creating an access key for a different user grants programmatic access under that user's identity, enabling lateral movement or covert persistence.

**False positives:** Legitimate admin provisioning new developers' access keys. This should be done via IAM Identity Center rather than long-lived keys.

---

#### PE-03 — Login Profile Created

**Trigger:** `CreateLoginProfile` event.

**Criteria:**
- Event name: `CreateLoginProfile`
- No error in response

**Why it matters:** Creating a login profile enables console access for an IAM user that previously had none. Attackers may enable console access for a service account to broaden their access surface.

**False positives:** Legitimate admin granting a user console access for the first time.

---

#### PE-04 — Backdoor Admin Policy Attached

**Trigger:** `AttachUserPolicy`, `AttachGroupPolicy`, or `AttachRolePolicy` where the attached policy is `arn:aws:iam::aws:policy/AdministratorAccess`.

**Criteria:**
- Event name: one of `AttachUserPolicy`, `AttachGroupPolicy`, `AttachRolePolicy`
- `requestParameters.policyArn` = `arn:aws:iam::aws:policy/AdministratorAccess`

**Why it matters:** Attaching the managed AdministratorAccess policy grants unrestricted access to all AWS services and resources. This is the fastest path to full account takeover after initial compromise.

**False positives:** Breaking-glass emergency access scenarios. Should be immediately reviewed and revoked after the emergency.

---

#### PE-05 — MFA Device Deactivated

**Trigger:** `DeactivateMFADevice` or `DeleteVirtualMFADevice`.

**Criteria:**
- Event name: `DeactivateMFADevice` or `DeleteVirtualMFADevice`

**Why it matters:** Removing MFA from an account weakens its login security, enabling future console access with only a password. Attackers deactivate MFA to ensure they retain access even if the victim resets their password.

**False positives:** Legitimate MFA device replacement (user lost their phone). Should be paired with immediate re-enrollment.

---

#### PE-06 — IAM Policy Version Created (SetAsDefault)

**Trigger:** `CreatePolicyVersion` with `setAsDefault = true`.

**Criteria:**
- Event name: `CreatePolicyVersion`
- `requestParameters.setAsDefault = true`

**Why it matters:** Creating a new policy version and immediately setting it as the default is how attackers silently escalate permissions — they can add `*:*` to an existing policy without creating a new one, making the change harder to spot.

**False positives:** Normal IaC (Terraform/CDK) policy management. Correlate with the specific policy ARN and review the policy diff.

---

#### PE-07 — Cross-Account AssumeRole

**Trigger:** `AssumeRole` where the caller's account ID differs from the role's account ID.

**Criteria:**
- Event name: `AssumeRole`
- `userIdentity.accountId` ≠ account ID extracted from `requestParameters.roleArn`

**Why it matters:** Cross-account role assumption is a legitimate AWS feature, but it's also a lateral movement vector — an attacker who compromises one account can pivot to others via trust policies.

**False positives:** Expected in multi-account organisations with established cross-account access. Review the role ARN and caller to confirm it matches known trust relationships.

---

### Defense Evasion

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| DE-01 | CloudTrail Stopped or Deleted | Critical | CloudTrail | T1562.008 |
| DE-02 | GuardDuty Disabled | Critical | GuardDuty | T1562.001 |
| DE-04 | Config Recorder Stopped | High | Config | T1562.001 |
| DE-05 | VPC Flow Log Deletion | Critical | VPC | T1562.008 |
| DE-06 | CloudWatch Log Group Deleted | High | CloudWatch | T1562.008 |
| DE-07 | CloudTrail S3 Logging Bucket Changed | High | CloudTrail | T1562.008 |
| DE-08 | EventBridge Rule Disabled | Medium | EventBridge | T1562.001 |
| DE-09 | WAF Web ACL Deleted | High | WAF | T1562.001 |
| DE-10 | CloudFront Distribution Logging Disabled | Medium | CloudFront | T1562.008 |
| DE-11 | SQS Queue Encryption Removed | Medium | SQS | T1562.001 |
| DE-12 | SNS Topic Encryption Removed | Medium | SNS | T1562.001 |
| DE-13 | Route53 Hosted Zone Deleted | Medium | Route53 | T1485 |

---

#### DE-01 — CloudTrail Stopped or Deleted

**Trigger:** `StopLogging`, `DeleteTrail`, or `UpdateTrail`.

**Criteria:**
- Event name: `StopLogging`, `DeleteTrail`, or `UpdateTrail`
- Source: `cloudtrail.amazonaws.com`

**Why it matters:** Stopping or deleting CloudTrail is the first step an attacker takes to cover their tracks. Any of these events during an incident should be treated as a confirmed attacker action.

**False positives:** Near zero. Infrastructure decommissions should be pre-approved and extremely rare.

---

#### DE-02 — GuardDuty Disabled

**Trigger:** `DeleteDetector`, `StopMonitoringMembers`, or `DisassociateMembers`.

**Criteria:**
- Event name: `DeleteDetector`, `StopMonitoringMembers`, or `DisassociateMembers`
- Source: `guardduty.amazonaws.com`

**Why it matters:** GuardDuty is AWS's primary threat detection service. Disabling it silences real-time alerts, allowing subsequent attack phases to go undetected.

**False positives:** Rare — region consolidation or account migrations. Should have a corresponding change ticket.

---

#### DE-04 — Config Recorder Stopped

**Trigger:** `StopConfigurationRecorder` or `DeleteConfigurationRecorder`.

**Criteria:**
- Event name: `StopConfigurationRecorder` or `DeleteConfigurationRecorder`
- Source: `config.amazonaws.com`

**Why it matters:** AWS Config records resource configuration history. Stopping it prevents detection of resource misconfigurations introduced during an attack.

---

#### DE-05 — VPC Flow Log Deletion

**Trigger:** `DeleteFlowLogs`.

**Criteria:**
- Event name: `DeleteFlowLogs`
- Source: `ec2.amazonaws.com`

**Why it matters:** VPC Flow Logs capture network traffic metadata. Deleting them covers lateral movement and exfiltration activity at the network level.

---

#### DE-06 — CloudWatch Log Group Deleted

**Trigger:** `DeleteLogGroup`.

**Criteria:**
- Event name: `DeleteLogGroup`
- Source: `logs.amazonaws.com`

**Why it matters:** Application and infrastructure logs stored in CloudWatch are destroyed, eliminating evidence of attacker activity in applications and AWS services that write to CloudWatch.

---

#### DE-07 — CloudTrail S3 Logging Bucket Changed

**Trigger:** `UpdateTrail` where `requestParameters` contains `s3BucketName`.

**Criteria:**
- Event name: `UpdateTrail`
- `requestParameters.s3BucketName` is present

**Why it matters:** Redirecting CloudTrail logs to an attacker-controlled bucket means the defender loses visibility while the attacker can inspect the logs to understand what has been detected.

---

#### DE-08 — EventBridge Rule Disabled

**Trigger:** `DisableRule`.

**Criteria:**
- Event name: `DisableRule`
- Source: `events.amazonaws.com`

**Why it matters:** EventBridge rules often trigger automated security responses (e.g., auto-remediation Lambdas, security hub forwarding). Disabling them neutralises automated defences.

---

#### DE-09 — WAF Web ACL Deleted

**Trigger:** `DeleteWebACL` or `DeleteWebAclV2`.

**Criteria:**
- Event name: `DeleteWebACL` or `DeleteWebAclV2`
- Source: `waf.amazonaws.com` or `wafv2.amazonaws.com`

**Why it matters:** Deleting a WAF Web ACL removes HTTP-level protection from CloudFront distributions, ALBs, or API Gateways, exposing them to injection, XSS, and DDoS.

---

#### DE-10 — CloudFront Distribution Logging Disabled

**Trigger:** `UpdateDistribution` where the logging configuration sets `Enabled = false`.

**Criteria:**
- Event name: `UpdateDistribution`
- `requestParameters` contains logging configuration with `Enabled = false`

**Why it matters:** CloudFront access logs are used to detect data exfiltration through CDN. Disabling them removes visibility into edge traffic.

---

#### DE-11 — SQS Queue Encryption Removed

**Trigger:** `SetQueueAttributes` where `KmsMasterKeyId` is set to an empty string.

**Criteria:**
- Event name: `SetQueueAttributes`
- `requestParameters.attributes.KmsMasterKeyId` is present and empty

**Why it matters:** Removing queue encryption enables plaintext interception of message contents, which may contain credentials, tokens, or sensitive data.

---

#### DE-12 — SNS Topic Encryption Removed

**Trigger:** `SetTopicAttributes` where `attributeName = KmsMasterKeyId` and `attributeValue` is empty.

**Criteria:**
- Event name: `SetTopicAttributes`
- `requestParameters.attributeName = KmsMasterKeyId`
- `requestParameters.attributeValue` is empty

---

#### DE-13 — Route53 Hosted Zone Deleted

**Trigger:** `DeleteHostedZone`.

**Criteria:**
- Event name: `DeleteHostedZone`
- Source: `route53.amazonaws.com`

**Why it matters:** Deleting DNS zones causes service outages and can enable subdomain takeover if the zone is re-registered by an attacker. Also classified under Impact (T1485).

---

### Credential Access

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| CA-02 | Secrets Manager Bulk Access | High | SecretsManager | T1555 |
| CA-04 | Password Policy Weakened | Medium | IAM | T1556 |
| CA-05 | Root Account Console Login | Critical | IAM | T1078.004 |
| CA-06 | KMS Key Scheduled for Deletion | High | KMS | T1485 |

---

#### CA-02 — Secrets Manager Bulk Access

**Trigger:** More than 5 `GetSecretValue` calls by the **same identity** within a **10-minute sliding window**.

**Criteria:**
- Event name: `GetSecretValue`
- Same `userIdentity.arn`
- > 5 events within 600 seconds

**Why it matters:** Legitimate applications access a small, fixed set of secrets. Bulk enumeration of secrets indicates an attacker harvesting credentials after gaining access to a privileged role.

**False positives:** Secrets rotation jobs, or applications that dynamically resolve many secrets at startup. Review the identity and the specific secrets accessed.

---

#### CA-04 — Password Policy Weakened

**Trigger:** `UpdateAccountPasswordPolicy`.

**Criteria:**
- Event name: `UpdateAccountPasswordPolicy`
- Source: `iam.amazonaws.com`

**Why it matters:** Weakening the account password policy (reducing minimum length, removing complexity requirements) makes subsequent brute-force attacks more effective against all IAM users in the account.

---

#### CA-05 — Root Account Console Login

**Trigger:** Successful `ConsoleLogin` from the Root identity.

**Criteria:**
- Event name: `ConsoleLogin`
- `userIdentity.type = "Root"`
- `responseElements.ConsoleLogin = "Success"`

**Why it matters:** Root console login is extremely rare in well-run environments. Any successful Root login should be treated as a high-priority incident until proven otherwise.

---

#### CA-06 — KMS Key Scheduled for Deletion

**Trigger:** `ScheduleKeyDeletion`.

**Criteria:**
- Event name: `ScheduleKeyDeletion`
- Source: `kms.amazonaws.com`

**Why it matters:** Scheduling a KMS key for deletion will render all data encrypted with that key permanently unreadable after the waiting period. This is a ransomware-equivalent attack in cloud environments.

---

### Discovery

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| DI-02 | IAM Enumeration | Medium | IAM | T1087.004 |
| DI-03 | AccessDenied Spike | Medium | IAM | T1580 |

---

#### DI-02 — IAM Enumeration

**Trigger:** Multiple `GetUser`, `ListUsers`, `GetRole`, or `ListRoles` events from the same identity within a short window.

**Criteria:**
- Event names: `GetUser`, `ListUsers`, `GetRole`, `ListRoles`
- Same `userIdentity.arn`
- High frequency within a sliding time window

**Why it matters:** After initial access, attackers enumerate IAM identities to understand the account structure, identify high-privilege roles to assume, and find targets for lateral movement.

**False positives:** IaC tools (Terraform, CDK) performing state refresh, or audit scripts. Review the user agent and source IP.

---

#### DI-03 — AccessDenied Spike

**Trigger:** A high volume of `AccessDenied` errors from the same identity within a time window.

**Criteria:**
- `errorCode = "AccessDenied"` or `"Client.UnauthorizedOperation"`
- Same `userIdentity.arn`
- Elevated frequency within the window

**Why it matters:** An attacker probing what permissions a compromised identity has generates a burst of access denied errors as they try APIs outside the identity's allowed scope.

**False positives:** Misconfigured IAM policies on legitimate workloads. Correlate with the specific API calls being denied.

---

### Exfiltration

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| EX-01 | S3 Bucket Made Public | High | S3 | T1537 |
| EX-02 | S3 Bucket Deleted | Medium | S3 | T1485 |
| EX-03 | S3 Bulk Object Download | Medium | S3 | T1530 |
| EX-04 | S3 Bucket Access Logging Disabled | Medium | S3 | T1562.008 |
| EX-05 | S3 Bucket Encryption Removed | High | S3 | T1537 |

---

#### EX-01 — S3 Bucket Made Public

**Trigger:** `PutBucketPolicy` or `PutBucketAcl` that grants access to `Principal: "*"` or a public-access grantee (`AllUsers`, `AuthenticatedUsers`).

**Criteria:**
- Event name: `PutBucketPolicy` or `PutBucketAcl`
- Policy/ACL grants access to the wildcard principal or AWS-managed public groups

**Why it matters:** Making an S3 bucket public exposes all its contents to the internet without authentication. This is a primary data exfiltration vector.

---

#### EX-02 — S3 Bucket Deleted

**Trigger:** `DeleteBucket`.

**Criteria:**
- Event name: `DeleteBucket`
- Source: `s3.amazonaws.com`

**Why it matters:** Bucket deletion destroys all objects (unless versioned/replicated elsewhere), constituting data destruction. Can also be used to claim a known bucket name.

---

#### EX-03 — S3 Bulk Object Download

**Trigger:** ≥ 50 `GetObject` events by the **same identity** within a **5-minute sliding window**.

**Criteria:**
- Event name: `GetObject`
- Same `userIdentity.arn`
- ≥ 50 events within 300 seconds

**Why it matters:** Legitimate application access patterns fetch a bounded, predictable set of objects. Bulk `GetObject` from a single identity is a strong signal of programmatic data exfiltration.

**False positives:** Data processing jobs, backups, or analytics queries. Review the objects accessed and correlate with the bytes transferred (visible in the S3 tab).

---

#### EX-04 — S3 Bucket Access Logging Disabled

**Trigger:** `PutBucketLogging` with an empty `BucketLoggingStatus`.

**Criteria:**
- Event name: `PutBucketLogging`
- `requestParameters.bucketLoggingStatus` is empty or absent

**Why it matters:** S3 access logs record every GET/PUT/DELETE on objects. Disabling them blinds the defender to ongoing exfiltration of bucket contents.

---

#### EX-05 — S3 Bucket Encryption Removed

**Trigger:** `DeleteBucketEncryption`.

**Criteria:**
- Event name: `DeleteBucketEncryption`
- Source: `s3.amazonaws.com`

**Why it matters:** Removing server-side encryption (SSE) means future objects stored in the bucket will be unencrypted, lowering the bar for access if bucket permissions are later weakened.

---

### Impact

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| IM-01 | EC2 Instances Launched in Bulk | High | EC2 | T1496 |
| IM-02 | Resource Deletion Spree | Critical | Multi | T1485 |
| IM-03 | SES Email Identity Verified | Low | SES | T1534 |

---

#### IM-01 — EC2 Instances Launched in Bulk

**Trigger:** Multiple `RunInstances` events within a short sliding window.

**Criteria:**
- Event name: `RunInstances`
- High frequency within a time window (indicates bulk provisioning)

**Why it matters:** Bulk EC2 launches are a hallmark of cryptomining attacks (resource hijacking). An attacker who gains EC2 permissions typically launches as many instances as quotas allow.

**False positives:** Auto Scaling events triggered by legitimate load. Review the instance type, AMI, and identity.

---

#### IM-02 — Resource Deletion Spree

**Trigger:** Multiple delete events across different AWS services within a short time window.

**Criteria:**
- Event names matching `Delete*` across multiple services
- Same identity
- High frequency within the window

**Why it matters:** A coordinated series of deletions across services (EC2, RDS, S3, etc.) is a ransomware or sabotage pattern aimed at destroying the victim's infrastructure.

---

#### IM-03 — SES Email Identity Verified

**Trigger:** `VerifyEmailIdentity`.

**Criteria:**
- Event name: `VerifyEmailIdentity`
- Source: `ses.amazonaws.com`

**Why it matters:** Verifying a new SES identity sets up the ability to send email from that address using AWS infrastructure. Attackers use this for phishing and spear-phishing campaigns that bypass reputation filters.

---

### Network / VPC

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| NW-01 | Security Group Ingress Open to 0.0.0.0/0 | High | VPC | T1562.007 |
| NW-02 | Network ACL Allows All Traffic | Medium | VPC | T1562.007 |
| NW-03 | Internet Gateway Created | Info | VPC | T1562.007 |
| NW-04 | Route to Internet Added | Medium | VPC | T1562.007 |
| NW-05 | VPC Peering Connection Created | Info | VPC | T1021 |
| NW-06 | Security Group Deleted | Low | VPC | T1562.007 |
| NW-07 | Subnet Auto-Assign Public IP Enabled | Medium | VPC | T1562.007 |
| NW-08 | NAT Gateway Deleted | Low | VPC | T1485 |

---

#### NW-01 — Security Group Ingress Open to 0.0.0.0/0

**Trigger:** `AuthorizeSecurityGroupIngress` where the CIDR range is `0.0.0.0/0` (all IPv4) or `::/0` (all IPv6).

**Criteria:**
- Event name: `AuthorizeSecurityGroupIngress`
- `requestParameters` contains `cidrIp = 0.0.0.0/0` or `cidrIpv6 = ::/0`

**Why it matters:** Opening a security group to the entire internet exposes EC2 instances, RDS databases, or other resources to direct inbound connections from any source.

**False positives:** Intentional public-facing services (web servers on port 80/443). Review the port and protocol alongside the CIDR.

---

#### NW-02 — Network ACL Allows All Traffic

**Trigger:** `CreateNetworkAclEntry` or `ReplaceNetworkAclEntry` that creates an allow rule matching `0.0.0.0/0` on all ports/protocols.

**Criteria:**
- Event name: `CreateNetworkAclEntry` or `ReplaceNetworkAclEntry`
- Rule action: `allow`
- CIDR: `0.0.0.0/0`
- Protocol: all (`-1`) or all ports

---

#### NW-03 — Internet Gateway Created

**Trigger:** `CreateInternetGateway` or `AttachInternetGateway`.

**Criteria:**
- Event name: `CreateInternetGateway` or `AttachInternetGateway`

**Why it matters:** Creating and attaching an IGW makes a previously private VPC internet-routable. Severity is Info because this is expected during initial infrastructure setup, but unusual in mature environments.

---

#### NW-04 — Route to Internet Added

**Trigger:** `CreateRoute` or `ReplaceRoute` where the destination CIDR is `0.0.0.0/0`.

**Criteria:**
- Event name: `CreateRoute` or `ReplaceRoute`
- `requestParameters.destinationCidrBlock = 0.0.0.0/0`

**Why it matters:** Adding a default route to an internet gateway or NAT gateway routes all egress traffic from a subnet through the internet, potentially enabling data exfiltration from previously private subnets.

---

#### NW-05 — VPC Peering Connection Created

**Trigger:** `CreateVpcPeeringConnection`.

**Criteria:**
- Event name: `CreateVpcPeeringConnection`

**Why it matters:** VPC peering enables traffic between VPCs, which may cross account or organisation boundaries. Severity is Info — legitimate in multi-VPC architectures, but worth auditing the peer VPC owner.

---

#### NW-06 — Security Group Deleted

**Trigger:** `DeleteSecurityGroup`.

**Criteria:**
- Event name: `DeleteSecurityGroup`

**Why it matters:** Deleting a security group removes the firewall rules protecting resources associated with it. If done mid-incident, it may be an attempt to open access rather than restrict it.

---

#### NW-07 — Subnet Auto-Assign Public IP Enabled

**Trigger:** `ModifySubnetAttribute` where `mapPublicIpOnLaunch = true`.

**Criteria:**
- Event name: `ModifySubnetAttribute`
- `requestParameters.mapPublicIpOnLaunch.value = true`

**Why it matters:** Enabling auto-assign public IP on a subnet means all future EC2 instances launched in it receive a public IP automatically, making them directly internet-accessible regardless of security group rules.

---

#### NW-08 — NAT Gateway Deleted

**Trigger:** `DeleteNatGateway`.

**Criteria:**
- Event name: `DeleteNatGateway`

**Why it matters:** Deleting a NAT Gateway disrupts outbound internet access for private subnets. Can cause service outages or be used to force traffic through an attacker-controlled path.

---

### RDS

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| RDS-01 | RDS Deletion Protection Disabled | High | RDS | T1485 |
| RDS-02 | RDS Instance Restored with Public Access | High | RDS | T1537 |
| RDS-03 | RDS Master Password Changed | Medium | RDS | T1098 |

---

#### RDS-01 — RDS Deletion Protection Disabled

**Trigger:** `ModifyDBInstance` or `ModifyDBCluster` where `deletionProtection` is set to `false`.

**Criteria:**
- Event name: `ModifyDBInstance` or `ModifyDBCluster`
- `requestParameters.deletionProtection = false`

**Why it matters:** Disabling deletion protection is a prerequisite for deleting a database. In an attack, this precedes `DeleteDBInstance` as part of a data destruction sequence.

---

#### RDS-02 — RDS Instance Restored with Public Access

**Trigger:** Any RDS restore operation (`RestoreDBInstanceFromDBSnapshot`, `RestoreDBInstanceToPointInTime`, `RestoreDBClusterFromSnapshot`) where `publiclyAccessible = true`.

**Criteria:**
- Event name: restore variant
- `requestParameters.publiclyAccessible = true`

**Why it matters:** Restoring a database snapshot with public access enabled exposes the database endpoint directly to the internet. This can be used to exfiltrate data by making the database accessible outside the VPC.

---

#### RDS-03 — RDS Master Password Changed

**Trigger:** `ModifyDBInstance` or `ModifyDBCluster` where `masterUserPassword` is present in `requestParameters`.

**Criteria:**
- Event name: `ModifyDBInstance` or `ModifyDBCluster`
- `requestParameters.masterUserPassword` is present (value is redacted by CloudTrail)

**Why it matters:** Changing the master password locks out the legitimate database administrator while granting the attacker exclusive access.

---

### EBS

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| EBS-01 | EBS Default Encryption Disabled | High | EBS | T1486 |
| EBS-02 | EBS Snapshot Made Public | Critical | EBS | T1537 |
| EBS-03 | EBS Volume Detached | Low | EBS | T1537 |
| EBS-04 | EBS Snapshot Deleted | Medium | EBS | T1485 |
| EBS-05 | EBS Default KMS Key Changed | Medium | EBS | T1486 |

---

#### EBS-01 — EBS Default Encryption Disabled

**Trigger:** `DisableEbsEncryptionByDefault`.

**Criteria:**
- Event name: `DisableEbsEncryptionByDefault`
- Source: `ec2.amazonaws.com`

**Why it matters:** Disabling default EBS encryption means future volumes and snapshots will be unencrypted, enabling plaintext data access if the underlying storage is accessed outside of EC2.

---

#### EBS-02 — EBS Snapshot Made Public

**Trigger:** `ModifySnapshotAttribute` granting access to the `all` group.

**Criteria:**
- Event name: `ModifySnapshotAttribute`
- `requestParameters` grants `createVolumePermission` to group `all`

**Why it matters:** A public EBS snapshot can be copied by any AWS account. If the snapshot contains OS volumes, databases, or application data, anyone can mount it and extract the contents.

---

#### EBS-03 — EBS Volume Detached

**Trigger:** `DetachVolume`.

**Criteria:**
- Event name: `DetachVolume`

**Why it matters:** Detaching a volume is a precursor to exfiltration — an attacker can detach a data volume, attach it to an instance they control, and read its contents. Low severity because it's also a routine maintenance operation.

---

#### EBS-04 — EBS Snapshot Deleted

**Trigger:** `DeleteSnapshot`.

**Criteria:**
- Event name: `DeleteSnapshot`

**Why it matters:** Deleting snapshots destroys backup copies of data. In an attack, this prevents recovery after data destruction or ransomware.

---

#### EBS-05 — EBS Default KMS Key Changed

**Trigger:** `ModifyEbsDefaultKmsKeyId`.

**Criteria:**
- Event name: `ModifyEbsDefaultKmsKeyId`

**Why it matters:** Changing the default KMS key for EBS encryption to an attacker-controlled key means future volumes are encrypted with a key the legitimate owner may not control.

---

### Lambda

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| LM-01 | Lambda Function Granted Public Access | High | Lambda | T1098 |
| LM-02 | Lambda Environment Variables Updated | Low | Lambda | T1525 |

---

#### LM-01 — Lambda Function Granted Public Access

**Trigger:** `AddPermission20150331v2` where `principal = "*"`.

**Criteria:**
- Event name: `AddPermission20150331v2`
- `requestParameters.principal = "*"`

**Why it matters:** Granting `*` principal access to a Lambda function allows anyone on the internet to invoke it via the Lambda URL or API Gateway, potentially exposing internal functionality or enabling abuse.

---

#### LM-02 — Lambda Environment Variables Updated

**Trigger:** `UpdateFunctionConfiguration20150331v2` where the `Environment` key is present in `requestParameters`.

**Criteria:**
- Event name: `UpdateFunctionConfiguration20150331v2`
- `requestParameters` contains `Environment`

**Why it matters:** Environment variables commonly store secrets, API keys, and database connection strings. An attacker modifying them can inject malicious values or exfiltrate the existing secrets (visible in the request parameters if not encrypted).

---

### Resource Sharing

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| RS-01 | EC2 AMI Made Public | High | EC2 | T1537 |
| RS-02 | SSM Document Made Public | High | SSM | T1537 |
| RS-03 | RDS Snapshot Made Public | High | RDS | T1537 |

---

#### RS-01 — EC2 AMI Made Public

**Trigger:** `ModifyImageAttribute` granting `launchPermission` to the `all` group.

**Criteria:**
- Event name: `ModifyImageAttribute`
- `requestParameters` adds `launchPermission` for group `all`

**Why it matters:** A public AMI can be launched by any AWS account. AMIs often contain application code, secrets baked into the image, or OS configurations that reveal internal architecture.

---

#### RS-02 — SSM Document Made Public

**Trigger:** `ModifyDocumentPermission` adding `All` to the account list.

**Criteria:**
- Event name: `ModifyDocumentPermission`
- `requestParameters.accountIdsToAdd` contains `All`

**Why it matters:** SSM Run Command documents made public can be executed against EC2 instances by any AWS account with SSM access and appropriate IAM permissions, enabling remote code execution on instances.

---

#### RS-03 — RDS Snapshot Made Public

**Trigger:** `ModifyDBSnapshotAttribute` or `ModifyDBClusterSnapshotAttribute` granting access to `all`.

**Criteria:**
- Event name: `ModifyDBSnapshotAttribute` or `ModifyDBClusterSnapshotAttribute`
- `requestParameters.valuesToAdd` contains `all`

**Why it matters:** A public RDS snapshot can be restored into any AWS account, giving the attacker a full copy of the database without requiring access to the original RDS instance.

---

### Geo Anomaly

> Requires GeoLite2 MMDB files loaded via the IP tab. Without them, these rules are silently skipped.

| ID | Rule | Severity | Service | Technique |
|----|------|----------|---------|-----------|
| GEO-01 | Multi-Country Access | Medium | IAM | T1078 |
| GEO-02 | Console Login from Unusual Country | High | IAM | T1078.004 |

---

#### GEO-01 — Multi-Country Access

**Trigger:** The same IAM identity is observed making API calls from source IPs in **two or more distinct countries** within the loaded dataset.

**Criteria:**
- Same `userIdentity.arn`
- Source IPs resolve to ≥ 2 distinct countries via GeoLite2

**Why it matters:** A legitimate user rarely makes API calls from multiple countries simultaneously or in rapid succession. Multi-country activity often indicates credential theft and use by an attacker in a different geography.

**False positives:** Users who travel internationally or use VPNs with exit nodes in multiple countries. Correlate with the time gap between country transitions — simultaneous access from two countries is a stronger signal than sequential.

---

#### GEO-02 — Console Login from Unusual Country

**Trigger:** A `ConsoleLogin` event where the source IP resolves to a country not previously seen in that identity's history within the loaded dataset.

**Criteria:**
- Event name: `ConsoleLogin`
- Source IP country (via GeoLite2) not present in any prior event for that `userIdentity.arn`

**Why it matters:** A console login from a new geography is a strong account takeover signal, especially when paired with MFA being used (which an attacker with a stolen session token can bypass).

**False positives:** A user's first login after travelling, or a new user whose first login is from their home country (which appears "new" because there's no prior history). Enriched by long baseline periods.

---

### Rule Coverage Summary

| Category | Rules |
|----------|-------|
| Initial Access | 3 |
| Persistence | 7 |
| Defense Evasion | 13 |
| Credential Access | 4 |
| Discovery | 2 |
| Exfiltration | 5 |
| Impact | 3 |
| Network / VPC | 8 |
| RDS | 3 |
| EBS | 5 |
| Lambda | 2 |
| Resource Sharing | 3 |
| Geo Anomaly | 2 |
| **Total** | **60** |

---

## Custom YAML Rules

Custom rules let you write your own detections without touching Rust. They fire alongside all 60 built-in rules in the Detection tab.

### Where is rules.yaml?

The file is created automatically on first launch at:

| Platform | Path |
|----------|------|
| Windows | `%APPDATA%\trail-inspector\rules.yaml` |
| macOS | `~/Library/Application Support/trail-inspector/rules.yaml` |
| Linux | `~/.config/trail-inspector/rules.yaml` |

Click **Open Rules File** in the Detection tab to open it in your default text editor. Click **Reload Rules** after saving to apply changes without restarting the app.

---

### Full Schema

```yaml
rules:
  - id: CR-01                    # Required. Must be unique across all rules.
    name: "Rule display name"    # Required. Shown in the alert panel.
    enabled: true                # Optional. Default: true. Set false to disable without deleting.
    severity: High               # Required. One of: Critical, High, Medium, Low, Info

    # MITRE ATT&CK metadata (all optional — shown in AlertDetail)
    tactic: "Credential Access"
    technique: "Unsecured Credentials"
    technique_id: T1552
    mitre_url: "https://attack.mitre.org/techniques/T1552/"

    match_spec:
      event_name: GetSecretValue        # string or list of strings (see below)
      event_source: secretsmanager.amazonaws.com  # optional — further restricts events

    filters:                     # Optional. Recursive AND/OR/NOT filter tree.
      and:
        - field: identity_type
          value: IAMUser
        - not:
            field: user_agent
            value: "aws-sdk-python/1.0"

    threshold:                   # Optional. Without it the rule fires on any single match.
      count: 5                   # Fire only if this many events match within the window.
      window_secs: 300           # Sliding window size in seconds.
```

---

### match_spec

`event_name` accepts a **string** (single event) or a **list** (any of the listed events triggers the rule):

```yaml
# Single event
match_spec:
  event_name: DeleteBucket

# Any of multiple events
match_spec:
  event_name:
    - DeleteBucket
    - DeleteBucketEncryption
    - DeleteBucketPolicy

# Restrict to a specific service (optional)
match_spec:
  event_name: ConsoleLogin
  event_source: signin.amazonaws.com
```

---

### Filters

Filters are optional. Without `filters:` the rule matches every event with the specified event name(s).

Filters compose recursively using `and`, `or`, and `not`. Each leaf is a `field`/`value` pair (exact string match, case-sensitive).

#### Available filter fields

| Field | Matches |
|-------|---------|
| `identity_type` | `userIdentity.type` — e.g. `IAMUser`, `AssumedRole`, `Root`, `AWSService` |
| `user_name` | `userIdentity.userName` (IAM users only) |
| `user_arn` | `userIdentity.arn` |
| `source_ip` | `sourceIPAddress` |
| `event_source` | `eventSource` — e.g. `iam.amazonaws.com` |
| `region` | `awsRegion` |
| `account_id` | `userIdentity.accountId` |
| `user_agent` | `userAgent` |
| `bucket_name` | S3 bucket name from `requestParameters` |
| `error_code` | `errorCode` — e.g. `AccessDenied`, `NoSuchBucket` |

#### Filter examples

```yaml
# Simple leaf condition
filters:
  field: identity_type
  value: Root

# AND — all conditions must match
filters:
  and:
    - field: identity_type
      value: IAMUser
    - field: region
      value: ap-southeast-1

# OR — any condition matches
filters:
  or:
    - field: user_name
      value: alice
    - field: user_name
      value: bob

# NOT — exclude a condition
filters:
  not:
    field: user_agent
    value: "terraform/1.5.0"

# Compound — arbitrary nesting
filters:
  and:
    - field: identity_type
      value: IAMUser
    - not:
        or:
          - field: user_agent
            value: "terraform/1.5.0"
          - field: source_ip
            value: "10.10.0.5"
```

---

### Threshold

Without `threshold:` a rule fires once per matching event (or once per matched event group). With it, the rule fires only when `count` or more matching events occur within `window_secs` of each other (sliding window):

```yaml
threshold:
  count: 10
  window_secs: 60   # 10 events within 1 minute
```

The alert description includes the match count and time window.

---

### Example Rules

#### Detect any IAM group deletion

```yaml
rules:
  - id: CR-01
    name: "IAM Group Deleted"
    severity: Medium
    tactic: Impact
    technique: "Account Access Removal"
    technique_id: T1531
    match_spec:
      event_name: DeleteGroup
      event_source: iam.amazonaws.com
```

#### Console login without MFA by a specific user

```yaml
rules:
  - id: CR-02
    name: "alice Console Login Without MFA"
    severity: High
    match_spec:
      event_name: ConsoleLogin
    filters:
      and:
        - field: user_name
          value: alice
        - field: identity_type
          value: IAMUser
```

#### Key pair imported by a non-automation identity

```yaml
rules:
  - id: CR-03
    name: "EC2 Key Pair Imported by Human"
    severity: Medium
    tactic: Persistence
    match_spec:
      event_name: ImportKeyPair
      event_source: ec2.amazonaws.com
    filters:
      not:
        or:
          - field: user_agent
            value: "terraform/1.5.0"
          - field: user_name
            value: terraform-admin
```

#### Secrets Manager access by a specific role (frequency threshold)

```yaml
rules:
  - id: CR-04
    name: "Lambda Role Bulk Secret Access"
    severity: High
    tactic: "Credential Access"
    technique: "Credentials from Password Stores"
    technique_id: T1555
    match_spec:
      event_name:
        - GetSecretValue
        - ListSecrets
    filters:
      field: identity_type
      value: AssumedRole
    threshold:
      count: 3
      window_secs: 120
```

#### Security group rule changes (frequency threshold)

```yaml
rules:
  - id: CR-05
    name: "Security Group Rule Burst"
    severity: High
    tactic: "Defense Evasion"
    match_spec:
      event_name:
        - AuthorizeSecurityGroupIngress
        - AuthorizeSecurityGroupEgress
        - RevokeSecurityGroupIngress
        - RevokeSecurityGroupEgress
    threshold:
      count: 5
      window_secs: 300
```

---

### Error Handling

If a rule in `rules.yaml` has a parse error (invalid YAML, unknown field, missing required field) or shares an `id` with another rule:

- The bad rule is skipped and **reported individually** in an amber banner at the top of the Detection tab
- All other rules (both valid custom rules and all 60 built-in rules) continue to run normally
- The amber badge on the "Reload Rules" button shows how many rules have errors

Fix the error in `rules.yaml` and click **Reload Rules** to re-validate and re-run all detections.
