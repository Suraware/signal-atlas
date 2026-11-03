import { RefreshCw, ShieldCheck } from 'lucide-react';
import { useResource } from '../api';
import { date, Failure, Loading, LocalHint, PageHeading, SafeLink, SourceStatus, useWorkspace } from '../common';
import type { Source } from '../types';

export function SourcesPage() {
  const { version, syncing, refreshSources } = useWorkspace();
  const resource = useResource<Source[]>('/sources', version);
  return <>
    <PageHeading title="Public sources" description="Eight no-key connectors. Explicit coverage, request budgets, and cached evidence." />
    <div className="safety-banner"><ShieldCheck size={22} aria-hidden="true" /><div><strong>Source status is a record of the last request, not a live health check.</strong><p>Failed requests leave cached evidence intact. Refresh reuses each source's cache window; individual retries still respect its request budget.</p></div></div>
    {resource.loading ? <Loading text="Reading source status…" /> : resource.error ? <Failure message={resource.error} retry={resource.reload} /> : <div className="sources-grid">{resource.data?.map(source => <article className="panel source-card" key={source.id}><div className="source-card-heading"><div className={`source-mark source-mark-${source.id}`} aria-hidden="true">{source.id === 'exploitdb' ? 'ED' : source.id.slice(0, 2).toUpperCase()}</div><div><h2>{source.name}</h2><span>No API key required</span></div><SourceStatus source={source} /></div><p className="source-description">{source.description}</p><dl className="source-metadata"><div><dt>Connector mode</dt><dd>{source.mode}</dd></div><div><dt>Last recorded batch</dt><dd>{source.records} record{source.records === 1 ? '' : 's'}</dd></div><div><dt>Last successful request</dt><dd>{date(source.last_success, true)}</dd></div><div><dt>Cache window</dt><dd>{source.ttl >= 3600 ? `${source.ttl / 3600} hour${source.ttl === 3600 ? '' : 's'}` : `${source.ttl / 60} minutes`}</dd></div></dl><div className="source-limit"><strong>Coverage and limits</strong><p>{source.limit}</p>{source.rate_remaining !== undefined ? <p>Last reported request budget remaining: {source.rate_remaining}</p> : null}</div>{source.error ? <div className="inline-error" role="alert"><p>{source.error}</p><small>Last attempt: {date(source.last_attempt, true)}</small></div> : null}<div className="source-card-actions"><SafeLink url={source.url}>Public endpoint</SafeLink><button className="button secondary" disabled={syncing} onClick={() => void refreshSources(source.id)} aria-label={`Refresh ${source.name}`}><RefreshCw size={15} aria-hidden="true" />{syncing ? 'Refresh in progress' : 'Refresh source'}</button></div></article>)}</div>}
    <LocalHint>Trusted LAN only: anyone who can reach the server can read and edit this workspace. No accounts or TLS are built in.</LocalHint>
  </>;
}
