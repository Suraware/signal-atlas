import { useDeferredValue, useEffect, useRef, useState } from 'react';
import { FilePlus2, Save, Search, Trash2, Upload } from 'lucide-react';
import { ApiError, request, send, useResource } from '../api';
import { AppLink, confirmNavigation, date, Empty, Failure, Loading, LocalHint, navigate, NoteStatus, PageHeading, Panel, SafeLink, useWorkspace } from '../common';
import type { Note } from '../types';

interface ImportedNote { title: string; body: string; key: number }

export function ResearchPage({ noteId, seedCve = '' }: { noteId?: string; seedCve?: string }) {
  const { version, notify } = useWorkspace();
  const [search, setSearch] = useState('');
  const q = useDeferredValue(search.trim());
  const notes = useResource<Note[]>(`/notes?q=${encodeURIComponent(q)}`, version);
  const current = useResource<Note>(noteId && noteId !== 'new' ? `/notes/${encodeURIComponent(noteId)}` : null);
  const [imported, setImported] = useState<ImportedNote | null>(null);
  const [draftVersion, setDraftVersion] = useState(0);
  const importInput = useRef<HTMLInputElement>(null);
  const beginDraft = (document: ImportedNote | null = null) => {
    if (!confirmNavigation()) return false;
    setImported(document);
    setDraftVersion(value => value + 1);
    navigate('/research/new', true);
    return true;
  };
  const importMarkdown = async (file?: File) => {
    if (!file) return;
    try {
      if (file.size > 800000) throw new Error('This document is too large. Import up to 200,000 characters of Markdown text.');
      const body = await file.text();
      if (body.length > 200000) throw new Error('This document is too long. Import up to 200,000 characters.');
      if (beginDraft({ title: file.name.replace(/\.(md|markdown|txt)$/i, '').slice(0, 200), body, key: Date.now() })) {
        notify({ message: 'Markdown loaded as a local draft. Review it, then save the note.', tone: 'info' });
      }
    } catch (error) { notify({ message: error instanceof Error ? error.message : 'The document could not be read.', tone: 'error' }); }
    finally { if (importInput.current) importInput.current.value = ''; }
  };
  return <>
    <PageHeading title="Research library" description="Source-linked notes and documents. Plain text, stored on this server." actions={<><input ref={importInput} type="file" accept=".md,.markdown,.txt,text/plain,text/markdown" className="sr-only" aria-label="Markdown document to import" onChange={event => void importMarkdown(event.target.files?.[0])} /><button className="button secondary" onClick={() => importInput.current?.click()}><Upload size={16} aria-hidden="true" />Import Markdown</button><button className="button primary" onClick={() => beginDraft()}><FilePlus2 size={16} aria-hidden="true" />New note</button></>} />
    <div className="research-grid">
      <Panel title="Saved notes" extra={<span className="count-label">{notes.data?.length ?? '—'}</span>} className="library-panel">
        <div className="library-search field"><label htmlFor="note-search">Search research notes</label><div className="input-with-icon"><Search size={16} aria-hidden="true" /><input id="note-search" value={search} maxLength={300} placeholder="Title, content, or tag" onChange={event => setSearch(event.target.value)} /></div></div>
        {notes.loading ? <Loading /> : notes.error ? <Failure message={notes.error} retry={notes.reload} /> : notes.data?.length ? <ul className="note-list">{notes.data.map(note => <li key={note.id}><AppLink to={`/research/${note.id}`} className={note.id === noteId ? 'selected' : ''} aria-current={note.id === noteId ? 'page' : undefined}><strong>{note.title}</strong><span className="note-snippet">{note.body.slice(0, 105) || 'No content yet'}</span><span className="note-list-meta"><NoteStatus status={note.status} /><small>{date(note.updated_at)}</small></span>{note.tags.length ? <span className="note-tags">{note.tags.slice(0, 4).map(tag => <span key={tag}>#{tag}</span>)}</span> : null}</AppLink></li>)}</ul> : <Empty title={q ? 'No notes match' : 'No saved notes yet'}><p>{q ? 'Try another title, phrase, or tag.' : 'Save a finding or import a Markdown document to start your library.'}</p></Empty>}
      </Panel>
      {noteId === 'new' ? <NoteEditor key={`new-${seedCve}-${draftVersion}-${imported?.key || ''}`} seedCve={seedCve} imported={imported} /> : noteId ? current.loading ? <Panel><Loading text="Reading the saved note…" /></Panel> : current.error ? <Panel><Failure message={current.error} retry={current.reload} /></Panel> : current.data ? <NoteEditor key={`${current.data.id}-${current.data.revision}`} note={current.data} /> : null : <Panel className="choose-note"><Empty title="A place for the reasoning behind the record" headingLevel={2} action={<button className="button primary" onClick={() => beginDraft()}><FilePlus2 size={16} aria-hidden="true" />Write your first note</button>}><p>Select a note to read or edit it. Mention a CVE to connect your observations to cached intelligence.</p><p>Notes begin as unverified. Citations and your assessment stay separate from public source evidence.</p></Empty></Panel>}
    </div>
    <LocalHint>Markdown is stored and displayed as text. Embedded HTML and scripts are never rendered.</LocalHint>
  </>;
}

function NoteEditor({ note: initialNote, seedCve = '', imported }: { note?: Note; seedCve?: string; imported?: ImportedNote | null }) {
  const { refresh, notify } = useWorkspace();
  const [note, setNote] = useState(initialNote);
  const [title, setTitle] = useState(note?.title || imported?.title || '');
  const [body, setBody] = useState(note?.body || imported?.body || (seedCve ? `${seedCve}\n\n` : ''));
  const [tags, setTags] = useState(note?.tags.join(', ') || '');
  const [urls, setUrls] = useState(note?.source_urls.join('\n') || '');
  const [status, setStatus] = useState<Note['status']>(note?.status || 'unverified');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [conflict, setConflict] = useState(false);
  const [saved, setSaved] = useState(false);
  const titleInput = useRef<HTMLInputElement>(null);
  const dirty = !saved && (note ? title !== note.title || body !== note.body || tags !== note.tags.join(', ') || urls !== note.source_urls.join('\n') || status !== note.status : Boolean(title || body || tags || urls));
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  const links = [...new Set([...(note?.links || []), ...(title + '\n' + body).match(/\bCVE-\d{4}-\d{4,12}\b/gi) || []])].map(value => value.toUpperCase());
  useEffect(() => { if (!note) titleInput.current?.focus(); }, [note]);
  useEffect(() => {
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (dirtyRef.current) { event.preventDefault(); event.returnValue = ''; }
    };
    const beforeNavigation = (event: Event) => {
      if (dirtyRef.current && !window.confirm('You have an unsaved note. Leave this draft and discard your changes?')) event.preventDefault();
    };
    window.addEventListener('beforeunload', beforeUnload);
    window.addEventListener('atlas:before-navigation', beforeNavigation);
    return () => {
      window.removeEventListener('beforeunload', beforeUnload);
      window.removeEventListener('atlas:before-navigation', beforeNavigation);
    };
  }, []);
  const save = async () => {
    setBusy(true); setError(''); setConflict(false);
    try {
      const payload = { title: title.trim(), body, tags: tags.split(',').map(tag => tag.trim()).filter(Boolean), source_urls: urls.split('\n').map(url => url.trim()).filter(Boolean), status, ...(note ? { revision: note.revision } : {}) };
      const result = await send<Note>(note ? `/notes/${note.id}` : '/notes', payload, note ? 'PUT' : 'POST');
      setNote(result);
      setSaved(true);
      dirtyRef.current = false;
      refresh();
      navigate(`/research/${result.id}`);
      notify({ message: 'Saved in the local database.', tone: 'success' });
    } catch (error) { setError(error instanceof Error ? error.message : 'The note could not be saved. Your draft is still here.'); setConflict(error instanceof ApiError && error.status === 409); }
    finally { setBusy(false); }
  };
  const deleteNote = async () => {
    if (!note) return;
    setBusy(true); setError('');
    try {
      await request(`/notes/${note.id}`, { method: 'DELETE' });
      setSaved(true);
      dirtyRef.current = false;
      refresh(); navigate('/research');
      notify({ message: 'Note moved out of the library. Its saved content can be restored.', tone: 'info', actionLabel: 'Undo delete', action: async () => { try { await send(`/notes/${note.id}/restore`, {}); refresh(); navigate(`/research/${note.id}`); notify({ message: 'Note restored to the library.', tone: 'success' }); } catch (error) { notify({ message: error instanceof Error ? error.message : 'The note could not be restored.', tone: 'error' }); } } });
    } catch (error) { setError(error instanceof Error ? error.message : 'The note could not be deleted.'); }
    finally { setBusy(false); }
  };
  return <Panel title={note ? 'Research note' : 'New research note'} extra={<span className="draft-status">{busy ? 'Saving…' : dirty ? 'Unsaved draft' : note ? `Revision ${note.revision}` : 'Local draft'}</span>} className="note-editor">
    <form className="panel-body" onSubmit={event => { event.preventDefault(); void save(); }}>
      <div className="field"><label htmlFor="note-title">Note title</label><input ref={titleInput} id="note-title" value={title} required maxLength={200} onChange={event => { setTitle(event.target.value); setSaved(false); }} aria-describedby="note-error" /></div>
      <div className="editor-meta"><div className="field"><label htmlFor="note-status">Research status</label><select id="note-status" value={status} onChange={event => { setStatus(event.target.value as Note['status']); setSaved(false); }}><option value="unverified">Unverified</option><option value="in-progress">In progress</option><option value="verified">Verified by researcher</option></select></div><div className="field"><label htmlFor="note-tags">Tags</label><input id="note-tags" value={tags} placeholder="Comma-separated tags" onChange={event => { setTags(event.target.value); setSaved(false); }} /></div></div>
      <div className="field"><label htmlFor="note-content">Note content</label><textarea id="note-content" value={body} maxLength={200000} rows={14} className="note-content" onChange={event => { setBody(event.target.value); setSaved(false); }} aria-describedby="note-content-hint note-error" /><p id="note-content-hint" className="field-hint">Plain Markdown text. Mention an identifier such as CVE-2024-3094 to create a relationship.</p></div>
      <div className="field"><label htmlFor="note-sources">Source URLs</label><textarea id="note-sources" value={urls} rows={3} placeholder="One HTTP or HTTPS source URL per line" onChange={event => { setUrls(event.target.value); setSaved(false); }} aria-describedby="note-sources-hint note-error" /><p id="note-sources-hint" className="field-hint">Citations are links, not fetched documents. They are never opened automatically.</p></div>
      {links.length ? <div className="linked-identifiers"><strong>Related identifiers</strong><div>{links.map(link => <AppLink key={link} to={`/vulnerability/${encodeURIComponent(link)}`}><code>{link}</code></AppLink>)}</div></div> : null}
      <div id="note-error">{error ? <div className="inline-error" role="alert"><p>{error}</p>{conflict ? <><p>Copy your draft before reloading. A newer revision will not be overwritten.</p><button type="button" className="button secondary" onClick={() => window.location.reload()}>Reload saved revision</button></> : null}</div> : null}</div>
      <div className="editor-actions"><button className="button primary" disabled={busy || !title.trim()} type="submit"><Save size={16} aria-hidden="true" />{busy ? 'Saving note…' : 'Save note'}</button>{note ? <button type="button" className="button danger" disabled={busy} onClick={() => void deleteNote()}><Trash2 size={16} aria-hidden="true" />Delete note</button> : null}<span>{note ? `Saved ${date(note.updated_at, true)}` : 'Not saved until you select Save note.'}</span></div>
    </form>
    {note ? <details className="note-reader"><summary>Read saved note as plain text</summary><div className="plain-text">{note.body || 'No note content.'}</div>{note.source_urls.length ? <ul>{note.source_urls.map(url => <li key={url}><SafeLink url={url} /></li>)}</ul> : null}</details> : null}
  </Panel>;
}
