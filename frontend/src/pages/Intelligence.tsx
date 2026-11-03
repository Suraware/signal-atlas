import { useDeferredValue, useEffect, useState } from 'react';
import { ArrowDownToLine, ArrowRight, Bookmark, ExternalLink, FilePlus2, Network, RefreshCw, ShieldAlert } from 'lucide-react';
import { send, useResource } from '../api';
import { AppLink, date, elapsed, Empty, Failure, Loading, LocalHint, NoteStatus, number, PageHeading, Panel, percentage, ReferenceList, SeverityBadge, sourceNames, SourceStatus, useWorkspace, VulnerabilityTable } from '../common';
import type { Note, RecordList, Severity, Stats, Vulnerability } from '../types';

export function OverviewPage() {
  const { version, sources, syncing, refreshSources } = useWorkspace();
  const stats = useResource<Stats>('/stats', version);
  const records = useResource<RecordList>('/vulnerabilities?limit=8', version);
  const notes = useResource<Note[]>('/notes', version);
  return <>
    <PageHeading title="Research overview" description="Public intelligence, connected to your local research." actions={<span className="cache-indicator"><i aria-hidden="true" />Local evidence cache</span>} />
    {stats.error ? <Failure message={stats.error} retry={stats.reload} /> : stats.data ? <dl className="metrics-strip">
      <div className="lead-metric"><dt>Correlated vulnerabilities</dt><dd>{number(stats.data.total)}</dd></div>
      <div><dt>Known exploited</dt><dd>{number(stats.data.known_exploited)}</dd><dd className="metric-detail"><small>CISA KEV evidence</small></dd></div>
      <div><dt>Your watchlist</dt><dd>{number(stats.data.watched)}</dd><dd className="metric-detail"><AppLink to="/intelligence?watched=1">Review watchlist <ArrowRight size={13} aria-hidden="true" /></AppLink></dd></div>
      <div><dt>Research notes</dt><dd>{number(stats.data.notes)}</dd><dd className="metric-detail"><small>Stored on this server</small></dd></div>
    </dl> : <Loading />}
    <div className="overview-grid">
      <div className="panel-stack">
        <Panel title="Priority intelligence" extra={<AppLink to="/intelligence" className="text-link">Browse all <ArrowRight size={15} aria-hidden="true" /></AppLink>}>
          <p className="panel-intro">Watchlisted records first, then known exploitation and published severity.</p>
          {records.loading ? <Loading /> : records.error ? <Failure message={records.error} retry={records.reload} /> : records.data?.items.length ? <VulnerabilityTable records={records.data} compact /> : <Empty title="Your research starts here" action={<button className="button primary" disabled={syncing} onClick={() => void refreshSources()}><RefreshCw size={16} aria-hidden="true" />Refresh public sources</button>}><p>Fetch a bounded set of public advisories. Once cached, you can browse and collect notes without internet access.</p></Empty>}
          <div className="panel-footer"><span>Updated {elapsed(stats.data?.last_updated)}</span><span>Unknown means no score was supplied.</span></div>
        </Panel>
        <Panel title="Recent research" extra={<AppLink to="/research/new" className="text-link"><FilePlus2 size={16} aria-hidden="true" />New research note</AppLink>}>
          {notes.loading ? <Loading /> : notes.error ? <Failure message={notes.error} retry={notes.reload} /> : notes.data?.length ? <ul className="recent-notes">{notes.data.slice(0, 3).map(note => <li key={note.id}><div><AppLink to={`/research/${note.id}`}>{note.title}</AppLink><span>{date(note.updated_at)} · Revision {note.revision}</span></div><NoteStatus status={note.status} /></li>)}</ul> : <div className="research-empty"><FilePlus2 size={24} aria-hidden="true" /><div><strong>Turn an observation into a research trail.</strong><p>Write a note, cite a source, and mention a CVE to connect it automatically.</p></div></div>}
        </Panel>
      </div>
      <div className="panel-stack">
        <Panel title="Source coverage" extra={<span className="count-label">{sources.filter(source => source.last_success).length} / {sources.length || '—'} cached</span>}>
          <ul className="source-summary">{sources.map(source => <li key={source.id}><div><strong>{sourceNames[source.id] || source.name}</strong><small>{elapsed(source.last_success)}</small></div><SourceStatus source={source} /></li>)}</ul>
          <div className="panel-footer"><AppLink to="/sources" className="text-link">Limits and source status <ArrowRight size={15} aria-hidden="true" /></AppLink></div>
        </Panel>
        <section className="evidence-guide"><ShieldAlert size={22} aria-hidden="true" /><h2>Read the signals separately</h2><p><strong>Known exploited</strong> is catalog evidence. <strong>Public PoC</strong> is published exploit metadata. <strong>EPSS</strong> predicts exploitation probability, not severity.</p><p>None of these alone establishes that your system is affected.</p></section>
      </div>
    </div>
    <LocalHint>Cached browsing stays local. Refresh and identifier lookup contact the listed public sources.</LocalHint>
  </>;
}

export function IntelligencePage({ query, initialWatched = false }: { query: string; initialWatched?: boolean }) {
  const { version, sources } = useWorkspace();
  const q = useDeferredValue(query.trim());
  const [severity, setSeverity] = useState('');
  const [source, setSource] = useState('');
  const [kev, setKev] = useState(false);
  const [watched, setWatched] = useState(initialWatched);
  const [offset, setOffset] = useState(0);
  useEffect(() => setWatched(initialWatched), [initialWatched]);
  useEffect(() => setOffset(0), [q, severity, source, kev, watched]);
  const params = new URLSearchParams({ limit: '50', offset: String(offset) });
  if (q) params.set('q', q);
  if (severity) params.set('severity', severity);
  if (source) params.set('source', source);
  if (kev) params.set('kev', 'true');
  if (watched) params.set('watched', 'true');
  const records = useResource<RecordList>(`/vulnerabilities?${params}`, version);
  return <>
    <PageHeading title="Vulnerability intelligence" description="Search cached advisories, compare signals, and follow the evidence." />
    <Panel>
      <fieldset className="filter-bar"><legend className="sr-only">Filter cached vulnerabilities</legend>
        <div className="field"><label htmlFor="severity-filter">Severity</label><select id="severity-filter" value={severity} onChange={event => setSeverity(event.target.value)}><option value="">All severities</option>{(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as Severity[]).map(value => <option value={value} key={value}>{value.charAt(0) + value.slice(1).toLowerCase()}</option>)}</select></div>
        <div className="field"><label htmlFor="source-filter">Source</label><select id="source-filter" value={source} onChange={event => setSource(event.target.value)}><option value="">All sources</option>{sources.map(source => <option value={source.id} key={source.id}>{source.name}</option>)}</select></div>
        <label className="check-control"><input type="checkbox" checked={kev} onChange={event => setKev(event.target.checked)} />Known exploited only</label>
        <label className="check-control"><input type="checkbox" checked={watched} onChange={event => setWatched(event.target.checked)} />Watchlist only</label>
        <button className="button quiet" onClick={() => { setSeverity(''); setSource(''); setKev(false); setWatched(false); }}>Reset filters</button>
      </fieldset>
      <div className="results-heading" aria-live="polite"><strong>{records.data ? `${number(records.data.total)} matching record${records.data.total === 1 ? '' : 's'}` : 'Cached results'}</strong>{q ? <span>Search: <code>{q}</code></span> : <span>Local cache · No network query</span>}</div>
      {records.loading ? <Loading /> : records.error ? <Failure message={records.error} retry={records.reload} /> : records.data?.items.length ? <>
        <VulnerabilityTable records={records.data} />
        <div className="pagination"><span>{number(offset + 1)}–{number(Math.min(offset + records.data.items.length, records.data.total))} of {number(records.data.total)}</span><div><button className="button secondary" disabled={offset === 0} onClick={() => setOffset(value => Math.max(0, value - 50))}>Previous</button><button className="button secondary" disabled={offset + 50 >= records.data.total} onClick={() => setOffset(value => value + 50)}>Next</button></div></div>
      </> : <Empty title="No cached records match" headingLevel={2}><p>Try a product name or a full identifier. Remove filters to widen the search, or use public lookup below.</p></Empty>}
    </Panel>
    <IdentifierLookup seed={/^(CVE-|GHSA-)/i.test(q) ? q : ''} />
  </>;
}

function IdentifierLookup({ seed = '' }: { seed?: string }) {
  const { lookup, lookingUp } = useWorkspace();
  const [identifier, setIdentifier] = useState(seed);
  useEffect(() => { if (seed) setIdentifier(seed); }, [seed]);
  return <section className="lookup-panel"><div><h2>Not in your local cache?</h2><p>Look up a CVE, GHSA, or OSV identifier. Only the identifier is sent to registered public sources.</p></div><form onSubmit={event => { event.preventDefault(); void lookup(identifier.trim()); }}><div className="field"><label htmlFor="public-identifier">Public identifier lookup</label><input id="public-identifier" value={identifier} maxLength={100} required placeholder="CVE-2024-3094" onChange={event => setIdentifier(event.target.value)} /></div><button className="button secondary" disabled={lookingUp} type="submit"><ExternalLink size={16} aria-hidden="true" />{lookingUp ? 'Looking up…' : 'Look up identifier'}</button></form></section>;
}

export function DetailPage({ identifier }: { identifier: string }) {
  const { version, refresh, notify, lookup, lookingUp } = useWorkspace();
  const resource = useResource<Vulnerability>(`/vulnerabilities/${encodeURIComponent(identifier)}`, version);
  const [watching, setWatching] = useState(false);
  if (resource.loading) return <Loading text="Reading cached source evidence…" />;
  if (resource.error || !resource.data) return <><PageHeading title={identifier || 'Vulnerability record'} description="Source-linked evidence from the local cache." /><Failure message={resource.error || 'This record is not cached.'} retry={resource.reload} /><IdentifierLookup seed={identifier} /></>;
  const record = resource.data;
  const toggleWatch = async () => {
    setWatching(true);
    try {
      await send(`/vulnerabilities/${encodeURIComponent(record.id)}/watch`, { watched: !record.watched }, 'PATCH');
      refresh();
      notify({ message: record.watched ? 'Removed from your local watchlist.' : 'Added to your local watchlist.', tone: 'success' });
    } catch (error) { notify({ message: error instanceof Error ? error.message : 'Watchlist update failed. Try again.', tone: 'error' }); }
    finally { setWatching(false); }
  };
  return <>
    <AppLink to="/intelligence" className="back-link">← Back to intelligence</AppLink>
    <div className="record-eyebrow"><code>{record.id}</code><span>{record.source_ids.length} source{record.source_ids.length === 1 ? '' : 's'} · Cached {date(record.fetched_at, true)}</span></div>
    <PageHeading title={record.title} description="A correlated record. Check the individual sources before drawing a conclusion." actions={<><button className={`button ${record.watched ? 'watched-button' : 'secondary'}`} disabled={watching} onClick={() => void toggleWatch()}><Bookmark size={16} aria-hidden="true" />{record.watched ? 'Remove from watchlist' : 'Add to watchlist'}</button><AppLink to={`/research/new?cve=${encodeURIComponent(record.id)}`} className="button primary"><FilePlus2 size={16} aria-hidden="true" />Add research note</AppLink></>} />
    <dl className="signal-strip">
      <div><dt>Published severity</dt><dd><SeverityBadge severity={record.severity} /></dd><dd className="metric-detail"><small>Highest reported rating</small></dd></div>
      <div><dt>CVSS severity score</dt><dd>{record.cvss === null ? 'Not supplied' : record.cvss.toFixed(1)}</dd><dd className="metric-detail"><small>{record.cvss === null ? 'No score in cached evidence' : 'Out of 10 · Not an exploit probability'}</small></dd></div>
      <div><dt>EPSS probability</dt><dd>{record.epss === null ? 'Not supplied' : percentage(record.epss)}</dd><dd className="metric-detail"><small>{record.epss_date ? `Score dated ${record.epss_date}` : 'No dated score cached'}</small></dd></div>
      <div><dt>Exploitation evidence</dt><dd className={record.kev ? 'known-exploited-value' : ''}>{record.kev ? 'Known exploited' : 'Not in cached KEV'}</dd><dd className="metric-detail"><small>{record.exploit_count ? `${record.exploit_count} public PoC metadata entr${record.exploit_count === 1 ? 'y' : 'ies'}` : 'PoC metadata is a separate signal'}</small></dd></div>
    </dl>
    <div className="detail-grid">
      <div className="panel-stack">
        <Panel title="Advisory context"><div className="panel-body"><p className="plain-text">{record.description || 'No description is supplied by the cached sources. Follow the references for context.'}</p><dl className="metadata-grid"><div><dt>Published</dt><dd>{record.published ? date(record.published) : 'Not supplied'}</dd></div><div><dt>Source modified</dt><dd>{record.modified ? date(record.modified) : 'Not supplied'}</dd></div><div><dt>Vendors</dt><dd>{record.vendors.join(', ') || 'Not supplied'}</dd></div><div><dt>Products</dt><dd>{record.products.join(', ') || 'Not supplied'}</dd></div><div><dt>Weaknesses</dt><dd>{record.cwes.join(', ') || 'Not classified'}</dd></div><div><dt>Packages</dt><dd>{record.packages.join(', ') || 'Not supplied'}</dd></div></dl>{record.aliases.filter(alias => alias !== record.id).length ? <div className="alias-list"><strong>Correlated aliases</strong>{record.aliases.filter(alias => alias !== record.id).map(alias => <code key={alias}>{alias}</code>)}</div> : null}</div></Panel>
        {record.required_action ? <Panel title="Catalog remediation"><div className="panel-body"><p className="plain-text">{record.required_action}</p><p className="muted">CISA catalog action{record.due_date ? ` · Catalog due date: ${record.due_date}` : ''}. Validate against current vendor guidance and your environment.</p></div></Panel> : null}
        <Panel title="Source provenance" extra={<button className="button quiet" disabled={lookingUp} onClick={() => void lookup(record.id)}><RefreshCw size={15} aria-hidden="true" />{lookingUp ? 'Fetching evidence…' : 'Refresh evidence'}</button>}>
          <p className="panel-intro">Normalized signals above are conservative merges. Original source observations remain separate below.</p>
          <div className="provenance-list">{record.evidence?.map(evidence => <article key={evidence.source_id}><div className="provenance-heading"><strong>{sourceNames[evidence.source_id] || evidence.source_id}</strong><span>Fetched {date(evidence.fetched_at, true)}</span></div><div className="provenance-signals"><span>Severity: {evidence.record.severity}</span>{evidence.record.cvss !== null ? <span>CVSS: {evidence.record.cvss}</span> : null}{evidence.record.epss !== null ? <span>EPSS: {percentage(evidence.record.epss)}</span> : null}{evidence.record.kev ? <span>Known exploitation catalog</span> : null}</div><details><summary>Inspect original {sourceNames[evidence.source_id] || evidence.source_id} record</summary><pre className="raw-record">{JSON.stringify(evidence.raw, null, 2)}</pre></details></article>)}</div>
        </Panel>
        <Panel title="Linked research" extra={<AppLink to={`/graph?focus=${encodeURIComponent(record.id)}`} className="text-link"><Network size={16} aria-hidden="true" />View relationships</AppLink>}>{record.notes?.length ? <ul className="recent-notes">{record.notes.map(note => <li key={note.id}><AppLink to={`/research/${note.id}`}>{note.title}</AppLink><NoteStatus status={note.status} /></li>)}</ul> : <div className="panel-body"><p className="muted">No note links to this identifier yet. Add a research note to begin an evidence trail.</p></div>}</Panel>
      </div>
      <div className="panel-stack"><Panel title="Source references"><ReferenceList record={record} /></Panel><section className="evidence-guide"><h2>Keep the context portable</h2><p>Export this record, its original source evidence, and linked notes for offline review or an agent's context.</p><a href={`/api/export?identifier=${encodeURIComponent(record.id)}`} className="button secondary" download><ArrowDownToLine size={16} aria-hidden="true" />Export this context</a></section></div>
    </div>
  </>;
}
