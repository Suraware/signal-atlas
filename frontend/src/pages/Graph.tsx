import { useEffect, useMemo, useState } from 'react';
import { Network } from 'lucide-react';
import { useResource } from '../api';
import { AppLink, Empty, Failure, Loading, LocalHint, PageHeading, Panel, SafeLink, sourceNames, useWorkspace } from '../common';
import type { Graph, GraphEdge, GraphNode } from '../types';

const kindLabels: Record<GraphNode['kind'], string> = { vulnerability: 'Vulnerability', source: 'Public source', vendor: 'Vendor', product: 'Product', weakness: 'Weakness', package: 'Package', note: 'Research note', reference: 'Citation' };

function Entity({ node }: { node: GraphNode }) {
  if (node.kind === 'vulnerability') return <AppLink to={`/vulnerability/${encodeURIComponent(node.label)}`} className="record-id">{node.label}</AppLink>;
  if (node.kind === 'note') return <AppLink to={`/research/${node.id.slice(5)}`}>{node.label}</AppLink>;
  if (node.kind === 'reference' && node.url) return <SafeLink url={node.url}>{node.label}</SafeLink>;
  return <span>{node.kind === 'source' ? sourceNames[node.label] || node.label : node.label}</span>;
}

export function GraphPage({ initialFocus = '' }: { initialFocus?: string }) {
  const { version } = useWorkspace();
  const [input, setInput] = useState(initialFocus);
  const [focus, setFocus] = useState(initialFocus);
  useEffect(() => { setInput(initialFocus); setFocus(initialFocus); }, [initialFocus]);
  const graph = useResource<Graph>(`/graph?limit=6${focus ? `&focus=${encodeURIComponent(focus)}` : ''}`, version);
  const nodes = new Map(graph.data?.nodes.map(node => [node.id, node]) || []);
  const groups = new Map<string, GraphEdge[]>();
  graph.data?.edges.forEach(edge => groups.set(edge.source, [...(groups.get(edge.source) || []), edge]));
  return <>
    <PageHeading title="Knowledge graph" description="Follow actual relationships between advisories, sources, packages, and your research." />
    <form className="graph-controls" onSubmit={event => { event.preventDefault(); setFocus(input.trim()); }}><div className="field"><label htmlFor="graph-focus">Focus identifier</label><input id="graph-focus" maxLength={100} value={input} placeholder="CVE or advisory identifier; leave blank for a sample" onChange={event => setInput(event.target.value)} /></div><button className="button primary" type="submit"><Network size={16} aria-hidden="true" />Show relationships</button>{focus ? <button type="button" className="button secondary" onClick={() => { setInput(''); setFocus(''); }}>Clear focus</button> : null}</form>
    {graph.loading ? <Loading text="Reading evidence relationships…" /> : graph.error ? <Failure message={graph.error} retry={graph.reload} /> : graph.data?.nodes.length ? <>
      <Panel title={focus ? `Relationships for ${focus}` : 'Connected evidence sample'} extra={<span className="count-label">{graph.data.nodes.length} entities · {graph.data.edges.length} relationships</span>}>
        <p className="panel-intro">{focus ? 'This map uses only cached evidence and saved notes.' : 'The sample includes up to six priority records, not the whole database. Focus an identifier for its research context.'} Every relationship is also listed in the table below.</p>
        <EvidenceMap graph={graph.data} />
      </Panel>
      <Panel title="Relationship index" className="relationship-panel"><div className="table-scroll" role="region" aria-label="Evidence relationship index" tabIndex={0}><table className="relationship-table"><caption>Evidence relationships</caption><thead><tr><th scope="col">From</th><th scope="col">Relationship</th><th scope="col">To</th></tr></thead><tbody>{[...groups.entries()].flatMap(([source, edges]) => edges.map((edge, index) => <tr key={`${edge.source}-${edge.target}-${edge.relation}`}>{index === 0 ? <td rowSpan={edges.length}><span className="entity-kind">{kindLabels[nodes.get(source)!.kind]}</span><Entity node={nodes.get(source)!} /></td> : null}<td><span className="relation-label">{edge.relation}</span></td><td><span className="entity-kind">{kindLabels[nodes.get(edge.target)!.kind]}</span><Entity node={nodes.get(edge.target)!} /></td></tr>))}</tbody></table></div>{!graph.data.edges.length ? <div className="panel-body"><p>This entity has no linked evidence yet. Mention a cached identifier in a note to connect it.</p></div> : null}</Panel>
    </> : <Panel><Empty title="No cached relationships to show" headingLevel={2}><p>{focus ? 'This identifier is not cached. Search intelligence or use public lookup first.' : 'Refresh public intelligence or save a linked note to begin the graph.'}</p><AppLink to="/intelligence" className="button secondary">Open intelligence</AppLink></Empty></Panel>}
    <LocalHint>The graph represents documented relationships, not inferred causality or an attack simulation.</LocalHint>
  </>;
}

function EvidenceMap({ graph }: { graph: Graph }) {
  const layout = useMemo(() => {
    const columns = [graph.nodes.filter(node => node.kind === 'source'), graph.nodes.filter(node => node.kind === 'vulnerability'), graph.nodes.filter(node => ['vendor', 'product', 'weakness', 'package'].includes(node.kind)), graph.nodes.filter(node => ['note', 'reference'].includes(node.kind))];
    const maxRows = Math.max(4, ...columns.map(column => Math.min(column.length, 14)));
    const height = Math.max(360, maxRows * 56 + 70);
    const positions = new Map<string, { x: number; y: number; node: GraphNode }>();
    columns.forEach((column, columnIndex) => column.slice(0, 14).forEach((node, index, shown) => positions.set(node.id, { x: 132 + columnIndex * 262, y: 76 + (index + 0.5) * (height - 102) / shown.length, node })));
    return { positions, height };
  }, [graph]);
  return <div className="graph-visual"><svg viewBox={`0 0 1050 ${layout.height}`} role="img" aria-labelledby="graph-title graph-description"><title id="graph-title">Source-linked knowledge map</title><desc id="graph-description">Entities are arranged by type. Lines are documented relationships, listed in full in the evidence relationships table.</desc><defs><pattern id="graph-grid" width="22" height="22" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="#d9e1ea" /></pattern></defs><rect width="1050" height={layout.height} fill="url(#graph-grid)" />{['Public sources', 'Vulnerabilities', 'Affected context', 'Research & citations'].map((label, index) => <text key={label} x={132 + index * 262} y="30" textAnchor="middle" className="graph-column-label">{label}</text>)}
      {graph.edges.map(edge => { const source = layout.positions.get(edge.source); const target = layout.positions.get(edge.target); if (!source || !target) return null; return <path key={`${edge.source}-${edge.target}-${edge.relation}`} d={`M ${source.x} ${source.y} C ${(source.x + target.x) / 2} ${source.y}, ${(source.x + target.x) / 2} ${target.y}, ${target.x} ${target.y}`} className="graph-edge" />; })}
      {[...layout.positions.values()].map(({ x, y, node }) => { const label = node.kind === 'source' ? sourceNames[node.label] || node.label : node.label; return <g key={node.id} transform={`translate(${x - 114},${y - 23})`} className={`graph-node graph-${node.kind}`}><title>{kindLabels[node.kind]}: {label}</title><rect width="228" height="46" rx="6" /><text x="12" y="15" className="graph-kind">{kindLabels[node.kind]}</text><text x="12" y="33" className="graph-label">{label.length > 26 ? `${label.slice(0, 24)}…` : label}</text></g>; })}
    </svg>{layout.positions.size < graph.nodes.length ? <p className="field-hint">The diagram shows {layout.positions.size} of {graph.nodes.length} entities to keep it readable. The table includes every returned relationship.</p> : null}</div>;
}
