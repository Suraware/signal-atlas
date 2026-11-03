import { createContext, useContext, type ReactNode, type AnchorHTMLAttributes } from 'react';
import { ArrowUpRight, Database, FileSearch, LoaderCircle, ShieldAlert } from 'lucide-react';
import type { Note, RecordList, Severity, Source, Vulnerability } from './types';

export interface Notice { message: string; tone?: 'success' | 'error' | 'info'; actionLabel?: string; action?: () => void | Promise<void> }
export interface Workspace {
  version: number; refresh: () => void; notify: (notice: Notice) => void;
  sources: Source[]; syncing: boolean; refreshSources: (sourceId?: string) => Promise<void>;
  lookup: (identifier: string) => Promise<void>; lookingUp: boolean;
}
export const WorkspaceContext = createContext<Workspace | null>(null);
export function useWorkspace() { return useContext(WorkspaceContext)!; }

let approvedHash: string | null = null;
export function confirmNavigation() {
  return window.dispatchEvent(new Event('atlas:before-navigation', { cancelable: true }));
}
export function confirmHashNavigation(hash: string) {
  const approved = hash === approvedHash;
  approvedHash = null;
  return approved || confirmNavigation();
}
export function navigate(path: string, alreadyConfirmed = false) {
  if (window.location.hash === `#${path}`) return true;
  if (!alreadyConfirmed && !confirmNavigation()) return false;
  approvedHash = `#${path}`;
  window.location.hash = path;
  return true;
}
export function AppLink({ to, children, onClick, ...props }: AnchorHTMLAttributes<HTMLAnchorElement> & { to: string; children: ReactNode }) {
  return <a href={`#${to}`} {...props} onClick={event => {
    onClick?.(event);
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || (props.target && props.target !== '_self')) return;
    event.preventDefault();
    navigate(to);
  }}>{children}</a>;
}
export function SafeLink({ url, children, ...props }: { url: string; children?: ReactNode; className?: string }) {
  let valid = false;
  try { const parsed = new URL(url); valid = ['https:', 'http:'].includes(parsed.protocol) && !parsed.username && !parsed.password; } catch { /* Invalid source links are not clickable. */ }
  return valid ? <a href={url} target="_blank" rel="noopener noreferrer" {...props}>{children || url}<ArrowUpRight size={14} aria-hidden="true" /></a> : <span>{children || 'Invalid reference'}</span>;
}

export const sourceNames: Record<string, string> = { cisa: 'CISA KEV', cve: 'CVE.org', nvd: 'NVD', github: 'GitHub', epss: 'EPSS', osv: 'OSV', circl: 'CIRCL', exploitdb: 'Exploit-DB' };
export const severityNames: Record<Severity, string> = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', UNKNOWN: 'Unknown' };
export const number = (value: number) => new Intl.NumberFormat().format(value);
export const percentage = (value: number | null) => value === null ? '—' : `${(value * 100).toFixed(2)}%`;
export function date(value?: string | null, full = false) {
  if (!value) return 'Not yet fetched';
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', ...(full ? { hour: '2-digit', minute: '2-digit' } : {}) });
}
export function elapsed(value?: string | null) {
  if (!value) return 'No cached data';
  const seconds = Math.max(0, (Date.now() - new Date(value).valueOf()) / 1000);
  return seconds < 60 ? 'Just now' : seconds < 3600 ? `${Math.floor(seconds / 60)}m ago` : seconds < 86400 ? `${Math.floor(seconds / 3600)}h ago` : date(value);
}
export function SeverityBadge({ severity }: { severity: Severity }) { return <span className={`badge severity-${severity.toLowerCase()}`}><i aria-hidden="true" />{severityNames[severity] || 'Unknown'}</span>; }
export function NoteStatus({ status }: { status: Note['status'] }) { return <span className={`badge note-${status}`}>{status === 'in-progress' ? 'In progress' : status === 'verified' ? 'Verified' : 'Unverified'}</span>; }
export function SourceStatus({ source }: { source: Source }) {
  const label = source.status === 'error' ? 'Needs attention' : source.status === 'syncing' ? 'Refreshing' : source.last_success ? 'Cached' : 'Not fetched';
  return <span className={`badge source-${source.status}`}><i aria-hidden="true" />{label}</span>;
}
export function Loading({ text = 'Reading local records…' }: { text?: string }) { return <div className="loading" role="status"><LoaderCircle size={18} className="spin" aria-hidden="true" />{text}</div>; }
export function Failure({ message, retry }: { message: string; retry?: () => void }) { return <div className="error-state" role="alert"><ShieldAlert size={22} aria-hidden="true" /><div><strong>The request could not be completed.</strong><p>{message}</p>{retry ? <button className="button secondary" onClick={retry}>Try again</button> : null}</div></div>; }
export function Empty({ title, children, action, headingLevel = 3 }: { title: string; children?: ReactNode; action?: ReactNode; headingLevel?: 2 | 3 }) {
  const Heading = headingLevel === 2 ? 'h2' : 'h3';
  return <div className="empty-state"><FileSearch size={30} strokeWidth={1.5} aria-hidden="true" /><Heading>{title}</Heading><div>{children}</div>{action}</div>;
}
export function PageHeading({ title, description, actions }: { title: string; description: string; actions?: ReactNode }) { return <div className="page-heading"><div><h1>{title}</h1><p>{description}</p></div>{actions ? <div className="heading-actions">{actions}</div> : null}</div>; }
export function Panel({ title, extra, children, className = '' }: { title?: string; extra?: ReactNode; children: ReactNode; className?: string }) { return <section className={`panel ${className}`}>{title ? <div className="panel-heading"><h2>{title}</h2>{extra}</div> : null}{children}</section>; }
export function LocalHint({ children }: { children: ReactNode }) { return <div className="local-hint"><Database size={16} aria-hidden="true" /><span>{children}</span></div>; }

export function VulnerabilityTable({ records, compact = false }: { records: RecordList; compact?: boolean }) {
  return <div className="table-scroll" tabIndex={0} role="region" aria-label="Vulnerability results"><table className={`intel-table ${compact ? 'compact' : ''}`}>
    <caption className="sr-only">Cached vulnerability intelligence with severity and source evidence</caption>
    <thead><tr><th scope="col">Vulnerability</th><th scope="col">Severity</th><th scope="col">Evidence</th><th scope="col" title="EPSS predicts observed exploitation in the next 30 days.">EPSS</th>{!compact ? <th scope="col">Sources</th> : null}</tr></thead>
    <tbody>{records.items.map(record => <tr key={record.id}>
      <td><AppLink to={`/vulnerability/${encodeURIComponent(record.id)}`} className="record-id">{record.id}</AppLink><span className="record-title" title={record.title}>{record.title}</span>{record.watched ? <span className="watch-label">On your watchlist</span> : null}</td>
      <td><SeverityBadge severity={record.severity} /></td>
      <td>{record.kev ? <span className="evidence-label"><ShieldAlert size={14} aria-hidden="true" />Known exploited</span> : record.exploit_count > 0 ? <span className="poc-label">Public PoC metadata</span> : <span className="muted">Advisory</span>}</td>
      <td className="numeric" title={record.epss_date ? `Score dated ${record.epss_date}` : 'No EPSS score cached'}>{percentage(record.epss)}{record.epss === null ? <small>Not scored</small> : null}</td>
      {!compact ? <td><div className="source-tags">{record.source_ids.slice(0, 3).map(id => <span key={id}>{sourceNames[id] || id}</span>)}{record.source_ids.length > 3 ? <span>+{record.source_ids.length - 3}</span> : null}</div></td> : null}
    </tr>)}</tbody>
  </table></div>;
}

export function ReferenceList({ record }: { record: Vulnerability }) {
  return <ul className="reference-list">{record.references.map((ref, index) => <li key={`${ref.url}-${index}`}><SafeLink url={ref.url}>{ref.label}</SafeLink><span className="reference-url">{ref.url}</span>{ref.type !== 'reference' ? <small>{ref.type}</small> : null}</li>)}</ul>;
}
