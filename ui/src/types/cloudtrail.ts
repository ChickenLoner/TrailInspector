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

export type IngestProgressEvent =
  | { type: "progress"; filesTotal: number; filesDone: number; recordsTotal: number }
  | { type: "complete"; recordsTotal: number }
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

export interface IdentitySummary {
  arn: string;
  totalEvents: number;
  firstSeenMs: number;
  lastSeenMs: number;
  byEvent: IdentityEventSummary[];
  recentEventIds: number[];
}
