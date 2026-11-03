# Signal Atlas design state

## Brief
Local-first, no-key security research workbench. Primary persona: a researcher triaging a vulnerability and collecting source-linked evidence. Success is a complete offline-readable research path after a bounded sync.

Brief: [2026-11-03-signal-atlas.md](docs/designpowers/briefs/2026-11-03-signal-atlas.md). Tokens: [DESIGN.md](DESIGN.md).

## Principles
1. Evidence before decoration.
2. Preserve provenance and distinguish known facts from hypotheses.
3. Local by default; network only for intentional public-feed requests.
4. A failed feed must not erase useful cached data.
5. Every visual relationship has a readable equivalent.

## Decisions
- 2026-11-03: Inline execution requested by user; no implementer agents.
- 2026-11-03: Existing LAN exposure only; trusted-network use; no firewall changes.
- 2026-11-03: FastAPI/SQLite backend and React/TypeScript interface; same-origin production serving.
- 2026-11-03: No AI endpoint or credentials. Source-linked JSON/Markdown export provides agent context.
- 2026-11-03: Complete bounded source headings and agreement-based legacy recovery; genuine or ambiguous heading evidence vetoes extension. Full-list/detail text wraps, compact overview previews stay compact. Reading a recovered heading never rewrites observations or research state.
- 2026-11-03: Full-CVE submission validates the cache first; only 404 permits public lookup. Malformed successful reads fail closed. Typing and ordinary searches stay local. In-flight and context-revision guards preserve drafts and prevent stale redirects.
- 2026-11-03: Analyzer reports use native named entropy figures with all 512 bars fitted to the available width. Output caps bound retained results, not string-preview-dependent indicator coverage. No graph redesign was included.

## Open questions
None blocking. Unlimited APIs and internet-scale ingestion are intentionally not claimed.

## Artifacts
- Implementation plan: `docs/superpowers/plans/2026-11-03-signal-atlas.md`
- Execution ledger: `docs/progress.md`
- Verification evidence: `docs/verification.md`

## Review evidence
- 2026-11-03: Production build, 43 backend tests, 18 isolated Firefox tests, and Ruff pass in the original workspace and a fresh locked-dependency installation.
- 24 axe-core 4.14.0 scans at 1440px/390px report zero automated violations. Incomplete SVG checks were measured manually: graph text/lines have minimum 4.724:1 contrast. Keyboard-only lab flow and reduced-motion behavior pass.
- Actual 200% Firefox browser zoom passes on eight routes and a lab submission without page overflow. No physical-device or assistive-technology user test was performed; no accessibility certification is claimed.
- Production localhost/LAN checks cover 24 view/width/origin combinations with no browser errors or external page requests. A private-backup note edit and original evidence survive two restarts. Separate-device LAN reachability remains untested.
- Initial-build author self-review findings were reproduced, regression-tested RED→GREEN, and retested. That snapshot had no independent reviewer.
- Original-workspace handoff: loopback/localhost/LAN health and 14 additional read-only Firefox combinations pass. Existing research data is unchanged; startup only added the expected empty audit-cache table. The LAN launcher was started for use, without installing a service or changing network settings.

## Delivered upgrade verification
- Final fix-pass gates pass: 104 backend tests, 42 Firefox tests, Ruff, and production build. Full headings and source markup remain readable plain text at 1440px/720px/390px.
- Twenty-four changed-surface axe scans report zero violations or incomplete rules, including malformed-cache and missing-record feedback. Labelled keyboard search, busy/error announcements, ≥44px submit targets, focus, reduced motion, and native 200% browser zoom pass. No physical-device or assistive-technology user study is claimed.
- Six larger-file measurements and two real 64 MiB uploads pass; 512-bucket maps fit at desktop/mobile/zoom widths. Two private-backup restarts, 28 production combinations, and a 32-view read-only rehearsal preserve source evidence and test-note revisions.
- The single fresh-context read-only review and inline fix pass are complete. Separate analyzer commits `3d819fc`/`464463c` and CVE commit `2c1e877` are pushed to public `main`. The updated original app passes 32 read-only Firefox combinations on localhost and the host LAN origin; full cached headings, focus, raw evidence, and export are verified without public requests.
- The original database remains logically unchanged at 2,062 records and 2,189 evidence rows across the identity-checked restart and handoff. The current production assets are served with automatic refresh disabled. Delivery evidence is recorded separately from product code; the approved graph redesign remains deferred.
