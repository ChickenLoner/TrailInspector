export interface UserIdentity {
  type?: string;
  principalId?: string;
  arn?: string;
  accountId?: string;
  accessKeyId?: string;
  userName?: string;
  sessionContext?: unknown;
  invokedBy?: string;
}

export interface CloudTrailRecord {
  eventVersion?: string;
  eventTime: string;
  eventSource: string;
  eventName: string;
  awsRegion: string;
  sourceIPAddress?: string;
  userAgent?: string;
  userIdentity: UserIdentity;
  requestParameters?: unknown;
  responseElements?: unknown;
  errorCode?: string;
  errorMessage?: string;
  eventID?: string;
  readOnly?: boolean;
  [key: string]: unknown;
}

export interface RecordRow {
  id: number;
  timestamp: number;
  eventTime: string;
  eventName: string;
  eventSource: string;
  awsRegion: string;
  sourceIPAddress?: string;
  userName?: string;
  userArn?: string;
  errorCode?: string;
  raw: CloudTrailRecord;
}

export interface SearchResult {
  records: RecordRow[];
  total: number;
  page: number;
  pageSize: number;
}

export interface FieldValue {
  value: string;
  count: number;
}

export interface IngestWarning {
  message: string;
  file?: string;
}

export type IngestProgressEvent =
  | { type: "progress"; filesTotal: number; filesDone: number; recordsTotal: number }
  | { type: "complete"; recordsTotal: number; warnings: IngestWarning[] }
  | { type: "error"; message: string };

// ---------------------------------------------------------------------------
// Phase 3 — Visualization types
// ---------------------------------------------------------------------------

export interface TimeBucket {
  startMs: number;
  endMs: number;
  count: number;
}

export interface TimelineResult {
  buckets: TimeBucket[];
  total: number;
}

export interface FieldValueCount {
  value: string;
  count: number;
}

export interface IdentityEventSummary {
  eventName: string;
  count: number;
  firstSeenMs: number;
  lastSeenMs: number;
  errorCodes: string[];
}

export interface TimelineEvent {
  id: number;
  timestampMs: number;
  eventTime: string;
  eventName: string;
  awsRegion: string;
  sourceIp?: string;
  errorCode?: string;
  userAgent?: string;
  requestParameters?: Record<string, unknown>;
}

export interface IdentitySummary {
  arn: string;
  totalEvents: number;
  firstSeenMs: number;
  lastSeenMs: number;
  byEvent: IdentityEventSummary[];
  events: TimelineEvent[];
  page: number;
  pageSize: number;
}

// ---------------------------------------------------------------------------
// GeoIP types
// ---------------------------------------------------------------------------

export interface IpInfo {
  ip: string;
  countryCode?: string;
  countryName?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  asn?: number;
  asnOrg?: string;
}

export interface IpRow {
  ip: string;
  eventCount: number;
  countryCode?: string;
  countryName?: string;
  city?: string;
  asn?: number;
  asnOrg?: string;
}

export interface IpPage {
  rows: IpRow[];
  total: number;
  page: number;
  pageSize: number;
}

export interface AbuseCheckResult {
  ip: string;
  isPublic: boolean;
  abuseConfidenceScore: number;
  countryCode: string | null;
  totalReports: number;
  lastReportedAt: string | null;
  usageType: string | null;
  isp: string | null;
  domain: string | null;
}

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

export interface SessionSummary {
  id: number;
  identityKey: string;
  sourceIp: string;
  firstEventMs: number;
  lastEventMs: number;
  durationMs: number;
  eventCount: number;
  errorCount: number;
  uniqueEventNames: string[];
  uniqueRegions: string[];
}

export interface SessionPage {
  sessions: SessionSummary[];
  total: number;
  page: number;
  pageSize: number;
}

export interface SessionEvent {
  id: number;
  timestampMs: number;
  eventTime: string;
  eventName: string;
  eventSource: string;
  awsRegion: string;
  sourceIp?: string;
  errorCode?: string;
  userAgent?: string;
}

export interface AlertStub {
  ruleId: string;
  severity: Severity;
  title: string;
  service: string;
  mitreTactic: string;
  mitreTechnique: string;
  matchingCount: number;
}

export interface SessionDetail {
  id: number;
  identityKey: string;
  sourceIp: string;
  firstEventMs: number;
  lastEventMs: number;
  durationMs: number;
  eventCount: number;
  errorCount: number;
  uniqueEventNames: string[];
  uniqueRegions: string[];
  events: SessionEvent[];
  eventsPage: number;
  eventsPageSize: number;
  eventsTotal: number;
}

// ---------------------------------------------------------------------------
// Global time range
// ---------------------------------------------------------------------------

export interface GlobalTimeRange {
  startMs: number | null;
  endMs: number | null;
  label: string; // e.g. "Last 24h", "Custom", "All"
}

// ---------------------------------------------------------------------------
// Phase 4 — Detection types
// ---------------------------------------------------------------------------

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Alert {
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  matchingRecordIds: number[];
  metadata: Record<string, string>;
  mitreTactic: string;
  mitreTechnique: string;
  /** AWS service category (e.g. "IAM", "S3", "VPC", "RDS") */
  service: string;
  /** Pre-built query — apply to the search bar to see matching events. */
  query: string;
}
