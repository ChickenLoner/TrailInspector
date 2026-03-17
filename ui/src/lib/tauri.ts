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

export async function getIdentitySummary(arn: string): Promise<IdentitySummary> {
  return invoke<IdentitySummary>("get_identity_summary_cmd", { arn });
}

export async function runDetections(): Promise<Alert[]> {
  return invoke<Alert[]>("run_detections");
}
