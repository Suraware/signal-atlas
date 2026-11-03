# Signal Atlas implementation plan

> Inline execution in this session. Test each behavior before implementation; integrate the same-origin app; verify before claiming completion.

**Goal:** A runnable open-source LAN-accessible security research workspace with no-key intelligence feeds and local, source-linked knowledge.

**Architecture:** FastAPI owns validated local endpoints, bounded external connectors, and SQLite persistence. React uses relative `/api` calls; production assets are served by the same Python process. Feed refresh and CVE enrichment are distinct from cached browsing.

**Stack:** Python 3.11+, FastAPI, HTTPX, SQLite FTS5, React, TypeScript, Vite, isolated Playwright Firefox.

**Spec:** `docs/designpowers/briefs/2026-11-03-signal-atlas.md`; UI tokens in `DESIGN.md`.

## Global constraints
- No API keys, paid APIs, remote AI, telemetry, or CDN assets.
- Suspicious files and dependency manifests are never executed.
- Only known external endpoints may be called by the backend.
- Keep raw source records, record-specific references, fetched timestamps, explicit feed status, and cached data when refresh fails.
- Existing LAN only, port 8731; loopback by default, `--lan` is explicit.
- Ignore local data and test artifacts in git; no remote publishing or pushing.

## Review focus
1. Unknown IDs, long searches, malformed source payloads: return bounded useful errors, never 500s or query injection.
2. Network timeouts and rate limits: retain cached records and report a failed/skipped feed, not an empty successful sync.
3. Untrusted notes and source links: no HTML execution, JavaScript URLs, arbitrary URL fetching, or path traversal.
4. Malformed manifests and capture files: enforce byte/item limits; exact dependency versions only; no unbounded allocations.
5. LAN requests and offline use: reject foreign origins/hosts, no permissive CORS, browser assets remain local, concurrent refresh is serialized.

---

## Task 1: Local evidence and knowledge store
**Files:** `backend/atlas/store.py`, `backend/atlas/models.py`, `tests/test_store.py`.
**Produces:** `Store(data_dir)` with record upsert/list/detail, source state, notes, graph, stats, and JSON context export.
- [x] Write tests: alias merge, provenance retention, search injection safety, note CVE extraction, revision conflict, persistence, graph edges.
- [x] Run `pytest tests/test_store.py` and verify RED.
- [x] Implement SQLite WAL, FTS5 index, normalized record/alias/source tables and atomic note updates.
- [x] Run full `pytest`; verify GREEN.

## Task 2: Public no-key connectors and sync
**Files:** `backend/atlas/sources.py`, `backend/atlas/sync.py`, `tests/test_sources.py`.
**Consumes:** `Store.upsert_record(record, source_id, raw)` and source state methods.
**Produces:** `IntelService(store)` with bounded `sync()` and `enrich(identifier)`; `OSV` package version queries.
- [x] Write fixtures/tests: CISA exploitation flag, EPSS numeric validation, CVE/GHSA alias correlation, malformed payload, timeout isolation, TTL/rate-limit behavior, retained cache.
- [x] Verify RED; implement eight documented source adapters with timeout/response caps and cached feed status.
- [x] Probe public endpoints once; record actual accessibility in `docs/sources.md`.
- [x] Verify GREEN and run full `pytest`.

## Task 3: Safe laboratory and local HTTP surface
**Files:** `backend/atlas/analysis.py`, `backend/atlas/app.py`, `backend/atlas/cli.py`, `tests/test_analysis.py`, `tests/test_api.py`.
**Consumes:** Store and IntelService. **Produces:** `/api/{stats,vulnerabilities,notes,graph,sources,sync,lookup,audit,analyze,export,health}` with relative same-origin interface.
- [x] Write tests for exact npm/pip/CycloneDX versions, hashes/strings, PCAP packet summaries and truncation, upload caps, source/ID validation, origin protection, note lifecycle/export.
- [x] Verify RED; implement safe parsers, HTTP endpoints, upload limits, background refresh, and one-process LAN/loopback launcher.
- [x] Verify GREEN; run full `pytest`.

## Task 4: Evidence-led responsive interface
**Files:** `frontend/src/*`, `frontend/package.json`, `frontend/vite.config.ts`, `frontend/tests/ui.spec.ts`.
**Consumes:** documented `/api` schema via typed fetch. **Produces:** Overview, Intelligence, Research, Graph, Lab, Sources views.
- [x] Write and run browser acceptance tests to see the missing UI fail.
- [x] Implement structure and typography from `DESIGN.md`; visible search/filter/refresh; empty/failure states; source-linked detail.
- [x] Implement persistent note editor, accessible SVG+list graph, manifest audit, file/PCAP inspection, export.
- [x] `npm run build`: typecheck and bundle. Firefox: search → detail → note → reload → graph → lab → source status; check mobile and console errors.

## Task 5: Runnable open-source/LAN delivery
**Files:** `README.md`, `docs/sources.md`, `docs/security.md`, `LICENSE`, `CONTRIBUTING.md`, `start.sh`, `scripts/*`.
- [x] Document exact startup/test commands, local paths, source terms/rate limits, trusted-LAN caveat, and supported/non-supported analysis.
- [x] Sync live data; verify cache survives failed requests/restart; verify no external browser asset requests.
- [x] Run backend suite, static checks, production build, and isolated Firefox acceptance tests.
- [x] Verify host loopback and `192.168.0.7:8731` reachability without changing firewall/router.
- [x] Capture screenshots and report outcome and any material omissions.

## Final evidence
[Verification report](../../verification.md) records the passing gates, clean installation, accessibility/zoom checks, production restarts, author-review fixes, and untested deployment boundaries. [Execution ledger](../../progress.md) records the inline workflow and delivery state. No commit, push, or publish was requested or performed.
