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
export interface Analysis {
  filename: string; size: number; file_type: string; entropy: number; sha256: string; sha1: string; md5: string;
  strings: string[]; indicators: { urls: string[]; ipv4: string[] }; warnings: string[];
  signals: { label: string; reason: string; line: number; match: string }[];
  capture?: { format: string; packet_count: number; captured_bytes: number; truncated: boolean; link_type?: number; warnings: string[]; protocols: { name: string; count: number }[]; conversations: { source: string; destination: string; protocol: string; packets: number; bytes: number }[] };
}
