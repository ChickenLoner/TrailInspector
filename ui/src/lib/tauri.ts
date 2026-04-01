import { invoke } from "@tauri-apps/api/core";
import { Channel } from "@tauri-apps/api/core";
import type {
  SearchResult,
  FieldValue,
  IngestProgressEvent,
  TimelineResult,
  FieldValueCount,
  IdentitySummary,
  Alert,
  SessionPage,
  SessionDetail,
  SessionSummary,
  AlertStub,
  IpInfo,
  IpPage,
  AbuseCheckResult,
  OnlineGeoResult,
} from "../types/cloudtrail";

export async function loadDirectory(
  path: string,
  onProgress: (event: IngestProgressEvent) => void
): Promise<number> {
  const channel = new Channel<IngestProgressEvent>();
  channel.onmessage = onProgress;
  return invoke<number>("load_directory", { path, onProgress: channel });
}

export async function search(
  page: number = 0,
  pageSize: number = 100,
  query?: string
): Promise<SearchResult> {
  return invoke<SearchResult>("search", { page, pageSize, query: query ?? null });
}

export async function getFieldValues(
  field: string,
  topN: number = 20
): Promise<FieldValue[]> {
  return invoke<FieldValue[]>("get_field_values", { field, topN });
}

export async function getTimeline(
  query?: string,
  bucketCount?: number
): Promise<TimelineResult> {
  return invoke<TimelineResult>("get_timeline", {
    query: query ?? null,
    bucketCount: bucketCount ?? null,
  });
}

export async function getTopFields(
  field: string,
  query?: string,
  topN?: number
): Promise<FieldValueCount[]> {
  return invoke<FieldValueCount[]>("get_top_fields", {
    field,
    query: query ?? null,
    topN: topN ?? null,
  });
}

export async function getIdentitySummary(
  arn: string,
  page?: number,
  pageSize?: number,
  startMs?: number,
  endMs?: number,
): Promise<IdentitySummary> {
  return invoke<IdentitySummary>("get_identity_summary_cmd", {
    arn,
    page: page ?? null,
    pageSize: pageSize ?? null,
    startMs: startMs ?? null,
    endMs: endMs ?? null,
  });
}

export async function runDetections(startMs?: number, endMs?: number): Promise<Alert[]> {
  return invoke<Alert[]>("run_detections", {
    startMs: startMs ?? null,
    endMs: endMs ?? null,
  });
}

export async function listSessions(
  page: number = 0,
  pageSize: number = 50,
  sortBy: string = "first",
  filterIdentity?: string,
  filterIp?: string,
  startMs?: number,
  endMs?: number,
): Promise<SessionPage> {
  return invoke<SessionPage>("list_sessions", {
    page,
    pageSize,
    sortBy,
    filterIdentity: filterIdentity ?? null,
    filterIp: filterIp ?? null,
    startMs: startMs ?? null,
    endMs: endMs ?? null,
  });
}

export async function getSessionAlerts(sessionId: number): Promise<AlertStub[]> {
  return invoke<AlertStub[]>("get_session_alerts", { sessionId });
}

export async function getAlertSessions(ruleId: string): Promise<SessionSummary[]> {
  return invoke<SessionSummary[]>("get_alert_sessions", { ruleId });
}

export async function getSessionDetail(
  sessionId: number,
  eventsPage: number = 0,
  eventsPageSize: number = 50,
): Promise<SessionDetail> {
  return invoke<SessionDetail>("get_session_detail", { sessionId, eventsPage, eventsPageSize });
}

export async function loadGeoipDb(
  geoPath?: string,
  asnPath?: string,
): Promise<string> {
  return invoke<string>("load_geoip_db", {
    geoPath: geoPath ?? null,
    asnPath: asnPath ?? null,
  });
}

export async function lookupIp(ip: string): Promise<IpInfo | null> {
  return invoke<IpInfo | null>("lookup_ip", { ip });
}

export async function listIps(
  page: number = 0,
  pageSize: number = 100,
  sortBy: string = "events",
  filterCountry?: string,
  startMs?: number,
  endMs?: number,
): Promise<IpPage> {
  return invoke<IpPage>("list_ips", {
    page,
    pageSize,
    sortBy,
    filterCountry: filterCountry ?? null,
    startMs: startMs ?? null,
    endMs: endMs ?? null,
  });
}

export async function geoLookupOnline(ips: string[]): Promise<OnlineGeoResult[]> {
  return invoke<OnlineGeoResult[]>("geo_lookup_online", { ips });
}

export async function checkAbuseIpdb(apiKey: string, ip: string): Promise<AbuseCheckResult> {
  return invoke<AbuseCheckResult>("check_abuseipdb", { apiKey, ip });
}

export async function exportCsv(query: string, path: string): Promise<void> {
  return invoke<void>("export_csv", { query, path });
}

export async function exportJson(query: string, path: string): Promise<void> {
  return invoke<void>("export_json", { query, path });
}
