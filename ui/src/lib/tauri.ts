import { invoke } from "@tauri-apps/api/core";
import { Channel } from "@tauri-apps/api/core";
import type { SearchResult, FieldValue, IngestProgressEvent } from "../types/cloudtrail";

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
