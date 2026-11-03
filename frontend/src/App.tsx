import { useCallback, useEffect, useRef, useState } from 'react';
import { Activity, ArrowDownToLine, ChevronRight, Database, FlaskConical, LayoutDashboard, Library, LoaderCircle, Network, Radio, RefreshCw, Search, ShieldCheck, X } from 'lucide-react';
import { ApiError, request, send, useResource } from './api';
import { AppLink, confirmHashNavigation, Failure, navigate, PageHeading, WorkspaceContext, type Notice } from './common';
import type { Source, SyncStatus, Vulnerability } from './types';
import { OverviewPage, IntelligencePage, DetailPage } from './pages/Intelligence';
import { ResearchPage } from './pages/Research';
import { GraphPage } from './pages/Graph';
import { LabPage } from './pages/Lab';
import { SourcesPage } from './pages/Sources';

const nav = [
  { path: '/overview', name: 'Overview', icon: LayoutDashboard },
  { path: '/intelligence', name: 'Vulnerability intelligence', icon: ShieldCheck },
  { path: '/research', name: 'Research library', icon: Library },
  { path: '/graph', name: 'Knowledge graph', icon: Network },
  { path: '/lab', name: 'Analysis lab', icon: FlaskConical },
  { path: '/sources', name: 'Public sources', icon: Radio },
];
const fullCve = /^CVE-\d{4}-\d{4,12}$/i;

function readRoute() {
  const raw = window.location.hash.slice(1) || '/overview';
  const [path, search = ''] = raw.split('?');
  return { path, query: new URLSearchParams(search) };
}

export function App() {
  const [route, setRoute] = useState(readRoute);
  const [query, setQuery] = useState('');
  const [version, setVersion] = useState(0);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [lookingUp, setLookingUp] = useState(false);
  const [lookupFeedback, setLookupFeedback] = useState<Notice | null>(null);
  const lookupActive = useRef(false);
  const contextRevision = useRef(0);
  const refresh = useCallback(() => setVersion(value => value + 1), []);
  const notify = useCallback((notice: Notice) => setNotice(notice), []);
  const sources = useResource<Source[]>('/sources', version);

  useEffect(() => {
    let acceptedHash = window.location.hash;
    const handler = () => {
      if (!confirmHashNavigation(window.location.hash)) {
        window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}${acceptedHash}`);
        return;
      }
      acceptedHash = window.location.hash;
      contextRevision.current++;
      setRoute(readRoute());
      window.scrollTo({ top: 0 });
    };
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, []);
  useEffect(() => {
    let active = true;
    let wasRunning = false;
    const check = async () => {
      try {
        const status = await request<SyncStatus>('/sync');
        if (!active) return;
        setSyncing(status.running);
        if (wasRunning && !status.running) refresh();
        wasRunning = status.running;
      } catch { /* Main content reports connection failures. Polling never starts external requests. */ }
    };
    void check();
    const timer = window.setInterval(check, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [refresh]);

  const refreshSources = async (sourceId?: string) => {
    setSyncing(true);
    try {
      await send<SyncStatus>('/sync', { ...(sourceId ? { sources: [sourceId], force: true } : {}) });
      let status: SyncStatus;
      do {
        await new Promise(resolve => window.setTimeout(resolve, 1000));
        status = await request<SyncStatus>('/sync');
      } while (status.running);
      refresh();
      const errors = status.results.filter(item => item.status === 'error');
      const fetched = status.results.filter(item => item.status === 'ok').length;
      notify({ message: errors.length ? `Refresh finished with ${errors.length} source issue${errors.length === 1 ? '' : 's'}. Cached data is safe; see Public sources.` : fetched ? `Updated ${fetched} public source${fetched === 1 ? '' : 's'}. All evidence is stored locally.` : 'Sources are current. Existing cached evidence was reused.', tone: errors.length ? 'error' : 'success' });
    } catch (error) { notify({ message: error instanceof Error ? error.message : 'Refresh failed. Try again.', tone: 'error' }); }
    finally { setSyncing(false); }
  };
  const lookup = async (identifier: string, cacheFirst = false) => {
    if (lookupActive.current) return;
    lookupActive.current = true;
    setLookingUp(true);
    const startedHash = window.location.hash;
    const startedRevision = contextRevision.current;
    const currentContext = () => window.location.hash === startedHash && contextRevision.current === startedRevision;
    const feedback = (message: string, tone: Notice['tone']) => {
      setLookupFeedback({ message, tone });
      if (!cacheFirst) notify({ message, tone });
    };
    const presentRecord = (record: Vulnerability, message: string, tone: Notice['tone']) => {
      const path = `/vulnerability/${encodeURIComponent(record.id)}`;
      const opened = currentContext() && navigate(path);
      if (opened) document.getElementById('workspace-content')?.focus();
      const outcome: Notice = { message: opened ? message : `${message} Your current view was kept.`, tone };
      setLookupFeedback(outcome);
      if (!cacheFirst || !opened) notify({ ...outcome, ...(!opened ? { actionLabel: 'Open cached record', action: () => { navigate(path); } } : {}) });
    };
    try {
      if (cacheFirst) {
        setLookupFeedback({ message: `Checking the local cache for ${identifier}…`, tone: 'info' });
        try {
          const cached = await request<Vulnerability>(`/vulnerabilities/${encodeURIComponent(identifier)}`);
          if (!cached || typeof cached.id !== 'string' || !fullCve.test(cached.id) || typeof cached.title !== 'string' || !cached.title || !Array.isArray(cached.aliases) || !cached.aliases.includes(identifier)) {
            throw new Error('The local server returned an invalid cached record.');
          }
          presentRecord(cached, `${cached.id} is available in the local cache. No public request was sent.`, 'success');
          return;
        }
        catch (error) {
          if (!(error instanceof ApiError) || error.status !== 404) {
            const detail = error instanceof Error ? error.message : 'The local server could not be reached.';
            feedback(`Could not read the local cache. ${detail} No public request was sent. Check the local server and try again.`, 'error');
            return;
          }
        }
        if (!currentContext()) {
          feedback('The search context changed. No public request was sent. Submit your search again when ready.', 'info');
          return;
        }
      }
      setLookupFeedback({ message: `Looking up ${identifier} in public sources… You can keep working while it finishes.`, tone: 'info' });
      const result = await send<{ record: Vulnerability | null; results: { status: string }[] }>('/lookup', { identifier });
      refresh();
      const errors = result.results.filter(item => item.status === 'error').length;
      if (result.record) {
        presentRecord(result.record, errors ? `Evidence for ${result.record.id} is saved locally. ${errors} public source${errors === 1 ? '' : 's'} failed; check Public sources.` : `Source-linked evidence for ${result.record.id} is saved in the local workspace.`, errors ? 'info' : 'success');
      } else feedback(errors ? `Could not retrieve ${identifier}. ${errors} public source${errors === 1 ? '' : 's'} failed. Check Public sources, then try again. No record was added.` : `No public record was found for ${identifier}. Check the identifier or try again later.`, 'error');
    } catch (error) { feedback(error instanceof Error ? error.message : 'Lookup failed. Try again.', 'error'); }
    finally { lookupActive.current = false; setLookingUp(false); }
  };
  const submitSearch = () => {
    if (lookupActive.current) return;
    const identifier = query.trim();
    if (fullCve.test(identifier)) void lookup(identifier.toUpperCase(), true);
    else { setLookupFeedback(null); navigate('/intelligence'); }
  };

  const section = route.path.split('/')[1] || 'overview';
  const title = section === 'vulnerability' ? 'Vulnerability intelligence' : nav.find(item => item.path === `/${section}`)?.name || 'Overview';
  let page;
  if (section === 'intelligence') page = <IntelligencePage query={query} initialWatched={route.query.get('watched') === '1'} />;
  else if (section === 'vulnerability') {
    try { page = <DetailPage identifier={decodeURIComponent(route.path.split('/')[2] || '')} />; }
    catch { page = <><PageHeading title="Vulnerability record" description="Source-linked evidence from the local cache." /><Failure message="This link has an invalid identifier. Check the URL or open vulnerability intelligence to find a record." /><AppLink to="/intelligence" className="button secondary">Open intelligence</AppLink></>; }
  }
  else if (section === 'research') page = <ResearchPage noteId={route.path.split('/')[2]} seedCve={route.query.get('cve') || ''} />;
  else if (section === 'graph') page = <GraphPage initialFocus={route.query.get('focus') || ''} />;
  else if (section === 'lab') page = <LabPage />;
  else if (section === 'sources') page = <SourcesPage />;
  else page = <OverviewPage />;

  return <WorkspaceContext.Provider value={{ version, refresh, notify, sources: sources.data || [], syncing, refreshSources, lookup, lookingUp }}>
    <a className="skip-link" href="#workspace-content" onClick={event => {
      event.preventDefault();
      const workspace = document.getElementById('workspace-content');
      workspace?.focus();
      workspace?.scrollIntoView({ block: 'start' });
    }}>Skip to research workspace</a>
    <div className="app-shell">
      <aside className="sidebar">
        <AppLink to="/overview" className="brand" aria-label="Signal Atlas overview"><img src="/favicon.svg" alt="" /><span>Signal Atlas<small>Security research workspace</small></span></AppLink>
        <div className="workspace-switch"><Database size={17} aria-hidden="true" /><div>Local workspace<small>Your data. Your machine.</small></div><ChevronRight size={14} aria-hidden="true" /></div>
        <nav aria-label="Main workspace"><span className="nav-section">Workspace</span>{nav.map(({ path, name, icon: Icon }, index) => <div key={path}>{index === 4 ? <span className="nav-section tools-label">Research tools</span> : null}<AppLink to={path} className={`nav-link ${section === path.slice(1) || (section === 'vulnerability' && path === '/intelligence') ? 'active' : ''}`} aria-current={section === path.slice(1) ? 'page' : undefined}><Icon size={18} strokeWidth={1.7} aria-hidden="true" /><span>{name}</span></AppLink></div>)}</nav>
        <div className="sidebar-bottom"><div className="privacy-note"><ShieldCheck size={18} aria-hidden="true" /><strong>Local-first by design</strong><p>No cloud account. No API keys.<br />Evidence stays on your server.</p></div><a className="export-link" href="/api/export" download><ArrowDownToLine size={17} aria-hidden="true" />Export research</a><div className="sidebar-foot"><span>Open source</span><span>v0.1.0</span></div></div>
      </aside>
      <div className="workspace">
        <header className="utility-header"><div className="breadcrumb"><Activity size={17} aria-hidden="true" /><span>Workspace</span><ChevronRight size={13} aria-hidden="true" /><strong>{title}</strong></div><form className="global-search" aria-busy={lookingUp} onSubmit={event => { event.preventDefault(); submitSearch(); }}><label htmlFor="intel-search">Search intelligence</label><div className="search-control"><Search size={17} aria-hidden="true" /><input id="intel-search" value={query} onChange={event => { contextRevision.current++; setQuery(event.target.value.slice(0, 300)); if (!lookupActive.current) setLookupFeedback(null); }} placeholder="CVE, product, package…" maxLength={300} aria-describedby="intel-search-hint intel-search-feedback" /><button type="submit" aria-label={lookingUp ? 'Lookup in progress' : 'Submit intelligence search'} disabled={lookingUp}>{lookingUp ? <LoaderCircle size={17} className="spin" aria-hidden="true" /> : <ChevronRight size={17} aria-hidden="true" />}</button></div><p id="intel-search-hint" className="search-hint">Full CVE: local cache first, then public sources if missing. Other searches stay local.</p><p id="intel-search-feedback" className={`search-feedback ${lookupFeedback?.tone === 'error' ? 'search-error' : ''}`} role={lookupFeedback?.tone === 'error' ? 'alert' : 'status'} aria-atomic="true">{lookupFeedback?.message || ''}</p></form><button className="button primary refresh-button" onClick={() => void refreshSources()} disabled={syncing}>{syncing ? <LoaderCircle size={16} className="spin" aria-hidden="true" /> : <RefreshCw size={16} aria-hidden="true" />}{syncing ? 'Refreshing sources…' : 'Refresh sources'}</button></header>
        <main id="workspace-content" tabIndex={-1}>{page}</main>
        <footer className="workspace-footer"><span><Database size={13} aria-hidden="true" />SQLite-backed · No remote AI required</span><a href="/api/openapi.json" target="_blank" rel="noopener noreferrer">Local API schema</a></footer>
      </div>
    </div>
    {notice ? <div className={`toast toast-${notice.tone || 'info'}`} role={notice.tone === 'error' ? 'alert' : 'status'}><span>{notice.message}</span>{notice.action && notice.actionLabel ? <button onClick={() => void notice.action?.()}>{notice.actionLabel}</button> : null}<button className="icon-button" aria-label="Dismiss notification" onClick={() => setNotice(null)}><X size={17} aria-hidden="true" /></button></div> : null}
  </WorkspaceContext.Provider>;
}
