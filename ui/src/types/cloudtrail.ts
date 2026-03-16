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
