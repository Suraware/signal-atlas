export type Severity = 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export interface Reference { url: string; label: string; type: string }
export interface Evidence { source_id: string; fetched_at: string; raw: unknown; record: Vulnerability }
export interface Vulnerability {
  id: string; aliases: string[]; title: string; description: string; severity: Severity;
  cvss: number | null; epss: number | null; epss_percentile: number | null; epss_date: string | null;
  kev: boolean; kev_date: string | null; due_date: string | null; ransomware: string; required_action: string;
  exploit_count: number; vendors: string[]; products: string[]; cwes: string[]; packages: string[];
  published: string | null; modified: string | null; references: Reference[];
  source_ids: string[]; fetched_at: string; watched: boolean; evidence?: Evidence[]; notes?: Note[];
}
export interface RecordList { items: Vulnerability[]; total: number; limit: number; offset: number }
export interface Note {
  id: string; title: string; body: string; tags: string[]; links: string[]; source_urls: string[];
  status: 'unverified' | 'in-progress' | 'verified'; revision: number; created_at: string; updated_at: string;
}
export interface Stats {
  total: number; known_exploited: number; watched: number; notes: number; critical: number;
  severity_counts: Partial<Record<Severity, number>>; sources_cached: number; last_updated: string | null;
  sync_running: boolean; refresh_seconds: number;
}
export interface Source {
  id: string; name: string; url: string; description: string; mode: string; ttl: number; interval: number;
  limit: string; status: 'idle' | 'ok' | 'error' | 'syncing'; records: number;
  last_success?: string; last_attempt?: string; error?: string | null; rate_remaining?: string; no_key: boolean;
}
export interface SyncStatus {
  running: boolean; started_at?: string; finished_at?: string;
  results: { id: string; status: string; records?: number; error?: string }[];
}
export interface GraphNode {
  id: string; label: string; kind: 'vulnerability' | 'source' | 'vendor' | 'product' | 'weakness' | 'package' | 'note' | 'reference';
  severity?: Severity; kev?: boolean; url?: string; status?: string;
}
export interface GraphEdge { source: string; target: string; relation: string }
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[]; focus: string | null; limited: boolean; record_limit: number }
export interface AuditResult {
  packages: { ecosystem: string; name: string; version: string }[];
  results: { ecosystem: string; name: string; version: string; status: string; checked_at: string | null; message?: string; vulnerabilities: { id: string; url: string; modified?: string }[] }[];
  skipped: { name: string; reason: string }[]; warnings: string[]; affected_packages: number; packages_checked: number;
}
export type ExecutableLimit = 'sections' | 'program_headers' | 'import_descriptors' | 'libraries' | 'symbols' | 'symbol_records' | 'dynamic_records' | 'name_bytes' | 'entropy_bytes' | 'findings' | 'warnings';
export interface ExecutableRange {
  index: number; name: string; header_offset: string; address: string; file_offset: string;
  file_size: string; memory_size: string; flags: string[]; flags_value: string;
  status: 'file_backed' | 'zero_fill' | 'invalid_range' | 'empty';
}
export interface ExecutableSection extends ExecutableRange { rva: string | null; type: string; entropy: number | null }
export interface ExecutableReport {
  format: 'PE' | 'ELF'; status: 'parsed' | 'partial' | 'invalid'; architecture: string;
  bitness: 32 | 64 | null; byte_order: 'little' | 'big' | null; kind: string;
  // Declared binary integers remain strings: malformed 64-bit values can exceed Number.MAX_SAFE_INTEGER.
  sections_declared: string; program_headers_declared: string;
  entry_point: {
    address: string | null; rva: string | null; offset: string | null; region: string | null;
    mapping: 'file_backed' | 'zero_fill' | 'ambiguous' | 'unmapped' | 'not_declared' | 'unavailable';
  };
  sections: ExecutableSection[]; load_segments: ExecutableRange[];
  imports: {
    status: 'parsed' | 'partial' | 'not_present' | 'unavailable'; note: string;
    libraries: { name: string; offset: string; record_offset: string }[];
    symbols: { name: string | null; ordinal: string | null; library: string | null; offset: string; name_offset: string | null; binding: string | null }[];
  };
  findings: { code: string; label: string; detail: string; offset: string | null }[];
  warnings: string[];
  limits: Record<ExecutableLimit, number> & { reached: ExecutableLimit[] };
  coverage: {
    sections_read: number; program_headers_read: number; import_descriptors_read: number;
    symbol_records_read: number; dynamic_records_read: number; entropy_bytes_read: number;
  };
}
export interface Analysis {
  filename: string; size: number; file_type: string; entropy: number; sha256: string; sha1: string; md5: string;
  strings: string[]; strings_utf16: string[]; sampled_bytes: number;
  indicators: { urls: string[]; ipv4: string[]; ipv6: string[]; domains: string[] };
  warnings: string[];
  signals: { label: string; reason: string; line: number; match: string }[];
  segments: { type: string; offset: number }[];
  entropyMap: { block: number; count: number; values: number[]; highRegions: { start: number; end: number; blockCount: number }[] };
  executable?: ExecutableReport;
  capture?: { format: string; packet_count: number; captured_bytes: number; truncated: boolean; link_type?: number; warnings: string[]; protocols: { name: string; count: number }[]; conversations: { source: string; destination: string; protocol: string; packets: number; bytes: number }[] };
}
