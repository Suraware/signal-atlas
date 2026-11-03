import { useState } from 'react';
import { FileSearch, PackageSearch, ShieldCheck } from 'lucide-react';
import { request, send } from '../api';
import { date, Failure, number, PageHeading, Panel, SafeLink } from '../common';
import type { Analysis, AuditResult } from '../types';

const auditStatuses: Record<string, string> = { ok: 'Fetched', cached: 'Cached', not_cached: 'Not checked', error: 'Query failed' };

export function LabPage() {
  const [format, setFormat] = useState('npm');
  const [manifest, setManifest] = useState('');
  const [network, setNetwork] = useState(false);
  const [auditing, setAuditing] = useState(false);
  const [auditError, setAuditError] = useState('');
  const [audit, setAudit] = useState<AuditResult | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [fileError, setFileError] = useState('');
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const auditDependencies = async () => {
    setAuditing(true); setAuditError(''); setAudit(null);
    try { setAudit(await send<AuditResult>('/audit', { format, content: manifest, allow_network: network })); }
    catch (error) { setAuditError(error instanceof Error ? error.message : 'The audit failed. Your manifest is still here.'); }
    finally { setAuditing(false); }
  };
  const inspectFile = async () => {
    if (!file) return;
    setInspecting(true); setFileError(''); setAnalysis(null);
    try {
      if (file.size > 64 * 1024 * 1024) throw new Error('This file exceeds 64 MiB. Choose a smaller artifact or capture.');
      const body = new FormData(); body.append('file', file);
      setAnalysis(await request<Analysis>('/analyze', { method: 'POST', body }));
    } catch (error) { setFileError(error instanceof Error ? error.message : 'The file could not be inspected.'); }
    finally { setInspecting(false); }
  };
  return <>
    <PageHeading title="Analysis lab" description="Exact-version dependency checks and bounded, read-only artifact inspection." />
    <div className="safety-banner"><ShieldCheck size={22} aria-hidden="true" /><div><strong>Inspection, not execution.</strong><p>No exploits run. No packet capture starts. Uploaded artifacts are inspected locally, are not retained after the request, and are never sent to external services.</p></div></div>
    <div className="lab-grid">
      <Panel title="Dependency audit" extra={<PackageSearch size={20} aria-hidden="true" />}>
        <form className="panel-body" onSubmit={event => { event.preventDefault(); void auditDependencies(); }}>
          <div className="field"><label htmlFor="manifest-format">Manifest format</label><select id="manifest-format" value={format} onChange={event => setFormat(event.target.value)}><option value="npm">npm package.json or package-lock.json</option><option value="requirements">Python requirements.txt</option><option value="cyclonedx">CycloneDX JSON SBOM</option></select></div>
          <div className="field"><label htmlFor="dependency-manifest">Dependency manifest</label><textarea id="dependency-manifest" required maxLength={200000} value={manifest} rows={9} className="code-input" placeholder={format === 'requirements' ? 'requests==2.19.0' : format === 'npm' ? '{"dependencies":{"lodash":"4.17.20"}}' : 'Paste a CycloneDX JSON BOM with package URLs'} onChange={event => setManifest(event.target.value)} aria-describedby="manifest-hint" /><p className="field-hint" id="manifest-hint">Up to 100 exact package versions. Ranges, includes, and commands are never resolved or executed.</p></div>
          <label className="check-control consent-control"><input type="checkbox" checked={network} onChange={event => setNetwork(event.target.checked)} aria-describedby="osv-consent-hint" />Send exact package coordinates to OSV</label><p id="osv-consent-hint" className="field-hint">Only package names, ecosystems, and exact versions leave the server. With this unchecked, only previous cached queries are read.</p>
          <button className="button primary" type="submit" disabled={auditing || !manifest.trim()}><PackageSearch size={16} aria-hidden="true" />{auditing ? 'Checking package versions…' : 'Audit dependencies'}</button>
        </form>
        {auditError ? <Failure message={auditError} /> : null}
      </Panel>
      <Panel title="Artifact inspection" extra={<FileSearch size={20} aria-hidden="true" />}>
        <form className="panel-body" onSubmit={event => { event.preventDefault(); void inspectFile(); }}>
          <p>Inspect binary headers, hashes, printable strings, and source-code signals. PCAP and PCAPNG files also produce packet and conversation summaries.</p>
          <div className="field file-field"><label htmlFor="artifact-file">File to inspect</label><input id="artifact-file" type="file" onChange={event => setFile(event.target.files?.[0] || null)} aria-describedby="artifact-hint" /><p id="artifact-hint" className="field-hint">Up to 64 MiB. No execution, decompression, decryption, or external reputation lookup.</p></div>
          <ul className="inspection-boundaries"><li>Hashes and entropy cover the full file.</li><li>Strings, indicators, and the entropy map cover every byte.</li><li>Heuristic rules read the first 16 MiB and the final 1 MiB.</li><li>Capture decoding stops at 20,000 packets.</li><li>Indicators are research leads, not a malware verdict.</li></ul>
          <button className="button primary" type="submit" disabled={inspecting || !file}><FileSearch size={16} aria-hidden="true" />{inspecting ? 'Inspecting bytes…' : 'Inspect file'}</button>
        </form>
        {fileError ? <Failure message={fileError} /> : null}
      </Panel>
    </div>
    {audit ? <AuditReport audit={audit} /> : null}
    {analysis ? <ArtifactReport analysis={analysis} /> : null}
  </>;
}

function AuditReport({ audit }: { audit: AuditResult }) {
  return <Panel title="Dependency audit results" className="lab-report"><div className="report-summary" role="status"><strong>{audit.packages_checked} of {audit.packages.length} package versions checked</strong><span>{audit.affected_packages} with advisory matches</span></div>{audit.warnings.length ? <WarningList warnings={audit.warnings} /> : null}<div className="table-scroll" role="region" aria-label="Dependency audit results" tabIndex={0}><table className="audit-table"><caption className="sr-only">Exact package versions and OSV query evidence</caption><thead><tr><th scope="col">Package version</th><th scope="col">Query state</th><th scope="col">Advisory matches</th></tr></thead><tbody>{audit.results.map(result => <tr key={`${result.ecosystem}-${result.name}-${result.version}`}><td><strong>{result.name}</strong><code>{result.version}</code><small>{result.ecosystem}</small></td><td><span className={`badge audit-${result.status}`}>{auditStatuses[result.status] || result.status}</span><small>{result.checked_at ? date(result.checked_at, true) : 'No cached query'}</small></td><td>{result.vulnerabilities.length ? <ul className="advisory-matches">{result.vulnerabilities.map(vulnerability => <li key={vulnerability.id}><SafeLink url={vulnerability.url}>{vulnerability.id}</SafeLink></li>)}</ul> : <span className="muted">{['ok', 'cached'].includes(result.status) ? 'No matches returned by this query.' : result.message || 'This version has not been checked.'}</span>}{result.message && result.vulnerabilities.length ? <p className="field-hint">{result.message}</p> : null}</td></tr>)}</tbody></table></div>{audit.skipped.length ? <details className="report-details"><summary>{audit.skipped.length} skipped manifest entr{audit.skipped.length === 1 ? 'y' : 'ies'}</summary><ul>{audit.skipped.map((entry, index) => <li key={index}><strong>{entry.name}</strong> — {entry.reason}</li>)}</ul></details> : null}<p className="panel-intro">A query without matches is not proof that a dependency is safe. Cached results retain their original check date.</p></Panel>;
}

function WarningList({ warnings }: { warnings: string[] }) { return <ul className="warning-list">{warnings.map(warning => <li key={warning}>{warning}</li>)}</ul>; }

function ArtifactReport({ analysis }: { analysis: Analysis }) {
  return <Panel title={`Inspection: ${analysis.filename}`} className="lab-report" extra={<span className="badge note-verified"><ShieldCheck size={14} aria-hidden="true" />No code executed</span>}>
    <dl className="artifact-metrics"><div><dt>Header / type</dt><dd>{analysis.file_type}</dd></div><div><dt>File size</dt><dd>{number(analysis.size)} bytes</dd></div><div><dt>Shannon entropy</dt><dd>{analysis.entropy.toFixed(3)} / 8</dd></div><div><dt>Coverage</dt><dd>Whole file scanned ({number(analysis.sampled_bytes)} bytes)</dd></div></dl>
    <WarningList warnings={analysis.warnings} />
    <EntropyMap entropyMap={analysis.entropyMap} />
    <div className="panel-body"><h3>File fingerprints</h3><dl className="hashes">{(['sha256', 'sha1', 'md5'] as const).map(key => <div key={key}><dt>{key.toUpperCase()}</dt><dd><code>{analysis[key]}</code></dd></div>)}</dl><p className="field-hint">SHA-1 and MD5 are provided for correlation only, not security guarantees.</p>
      {analysis.signals.length ? <><h3>Static review leads</h3><ul className="signal-list">{analysis.signals.map(signal => <li key={signal.label}><strong>{signal.label}</strong><span>Approximate line {signal.line} · <code>{signal.match}</code></span><p>{signal.reason}</p></li>)}</ul></> : <p className="muted">No configured heuristic matched the sampled bytes. This is not a clean bill of health.</p>}
      {analysis.segments.length ? <><h3 id="segments-heading">Embedded segments ({analysis.segments.length})</h3><p className="field-hint">File signatures were located, never extracted, opened, or inspected.</p><ul className="segment-list" aria-labelledby="segments-heading">{analysis.segments.map((segment, index) => <li key={`${segment.type}-${segment.offset}-${index}`}><strong>{segment.type}</strong><span><code>0x{segment.offset.toString(16)}</code> · byte {number(segment.offset)}</span></li>)}</ul></> : null}
      {analysis.capture ? <section className="capture-report"><h3>Capture summary</h3><p>{analysis.capture.format} · <strong>{number(analysis.capture.packet_count)} packets decoded</strong> · {number(analysis.capture.captured_bytes)} captured bytes</p><div className="source-tags">{analysis.capture.protocols.map(protocol => <span key={protocol.name}>{protocol.name}: {number(protocol.count)}</span>)}</div>{analysis.capture.truncated ? <p className="inline-error" role="alert">The capture is truncated or malformed. The decoded summary is incomplete.</p> : null}<WarningList warnings={analysis.capture.warnings} /><div className="table-scroll" role="region" aria-label="Decoded network conversations" tabIndex={0}><table className="capture-table"><caption>Decoded network conversations</caption><thead><tr><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Protocol</th><th scope="col">Packets</th></tr></thead><tbody>{analysis.capture.conversations.map((flow, index) => <tr key={index}><td><code>{flow.source}</code></td><td><code>{flow.destination}</code></td><td>{flow.protocol}</td><td>{number(flow.packets)}</td></tr>)}</tbody></table></div>{!analysis.capture.conversations.length ? <p className="muted">No supported IP conversations were decoded.</p> : null}</section> : null}
      {anyIndicators(analysis) ? <><h3>Observed indicators</h3>{groupIndicators(analysis).map(group => group.values.length ? <div className="indicator-group" key={group.name}><h4>{group.name}</h4>{group.linked ? <ul className="indicator-list">{group.values.map(value => <li key={value}><SafeLink url={value} /></li>)}</ul> : <ul className="indicator-list">{group.values.map(value => <li key={value}><code>{value}</code></li>)}</ul>}</div> : null)}</> : null}
      <details className="report-details"><summary>Printable strings ({analysis.strings.length})</summary><pre className="raw-record">{analysis.strings.join('\n') || 'No printable strings in the scanned file.'}</pre></details>
      <h3>UTF-16 strings</h3><details className="report-details"><summary>UTF-16 strings found ({analysis.strings_utf16.length})</summary><pre className="raw-record">{analysis.strings_utf16.join('\n') || 'No UTF-16 strings in the scanned file.'}</pre></details>
    </div>
  </Panel>;
}

function EntropyMap({ entropyMap }: { entropyMap: { block: number; count: number; values: number[]; highRegions: { start: number; end: number; blockCount: number }[] } }) {
  if (!entropyMap.values.length) return null;
  const regions = entropyMap.highRegions;
  const buckets = entropyMap.count === 1 ? '1 block of' : `${entropyMap.count} blocks of`;
  const label = `Entropy map, ${buckets} ${entropyMap.block} bytes each. ${regions.length ? `${regions.length} high-entropy region${regions.length === 1 ? ', bytes' : 's, byte ranges'} ${regions.map(region => `${region.start} to ${region.end}`).join(', ')}.` : 'No high-entropy regions.'}`;
  return <section><h3>Entropy map</h3><figure className="entropy-map" aria-label={label}><figcaption>Entropy map · {buckets} {entropyMap.block} bytes · {regions.length} high-entropy region{regions.length === 1 ? '' : 's'}</figcaption><div className="entropy-bars" aria-hidden="true">{entropyMap.values.map((value, index) => <span key={index} className={value > 7.5 ? 'entropy-bar high' : 'entropy-bar'} style={{ height: `${Math.max(2, Math.round(value / 8 * 100))}%` }} />)}</div></figure></section>;
}

function groupIndicators(analysis: Analysis): { name: string; values: string[]; linked: boolean }[] {
  return [
    { name: 'URLs', values: analysis.indicators.urls, linked: true },
    { name: 'Domains', values: analysis.indicators.domains, linked: false },
    { name: 'IPv4 addresses', values: analysis.indicators.ipv4, linked: false },
    { name: 'IPv6 addresses', values: analysis.indicators.ipv6, linked: false },
  ];
}

function anyIndicators(analysis: Analysis): boolean {
  return Object.values(analysis.indicators).some(values => values.length);
}
