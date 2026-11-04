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
- 2026-11-03: Executable-aware PE/ELF analysis selected by user and implemented inline. Parse bounded headers, sections, entry points, and imports with exact offsets; no execution or dependency increase. ELF dependency names must not be guessed as individual symbol providers. Named tables, native disclosures, literal names, and visible parsed/partial/invalid states preserve the existing report patterns. Brief: `docs/designpowers/briefs/2026-11-03-executable-analysis.md`.
- 2026-11-04: User-authorized **Publish and update** completed for executable product commit `0ff4204`. Rehearse privately, then back up the latest stopped original database and restart the existing launcher; never restore an older snapshot. Preserve later audit-cache entries, the separate refresh, and the soft-deleted note. No new service/network configuration or independent-review claim.

## Open questions
None blocking. Unlimited APIs and internet-scale ingestion are intentionally not claimed.

## Artifacts
- Implementation plan: `docs/superpowers/plans/2026-11-03-signal-atlas.md`
- Execution ledger: `docs/progress.md`
- Verification evidence: `docs/verification.md`
- Executable-analysis plan: `docs/superpowers/plans/2026-11-03-executable-analysis.md` (implemented, published, and verified in the original app)

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
- A separate local refresh after the clean handoff updated the live cache to 2,064 records and 2,191 evidence rows. All original record IDs remain present. Those later results were preserved, not rolled back or confused with restart-integrity evidence.

## Delivered executable-analysis verification
- Full post-fix gates: **220 backend tests**, **60 isolated Firefox tests** (18 executable cases), Ruff, and isolated TypeScript/Vite build pass. PE32/PE32+ and ELF32/ELF64 reports preserve exact evidence values, conservative mappings, scoped import sources, and explicit partial coverage. Five fixture families exercise **2,275 deterministic mutation/truncation cases**; real compiler/binutils comparisons pass.
- **36 axe-core 4.14.0 states** at 1440px/720px/390px report zero violations, incomplete rules, page/console errors, remote requests, or public lookups. Actual **200% Firefox 158.0.1 zoom** passes eleven executable states, keyboard disclosures, fourteen table scrolls, exact wide/literal values, warnings, and no page overflow. Representative screenshots were inspected. No assistive-technology user study, physical-device test, or certification is claimed.
- Three direct compiler-artifact API uploads and five fresh-context Firefox uploads pass, including PE64/ELF64 files of exactly **64 MiB**; **64 MiB + 1 byte** returns 413. Whole-file indicators, fingerprints, original previews, ZIP offsets, and all 512 entropy bars remain available. Fifteen post-fix contained-process checks pass within their verifier-only 45-second/768 MiB settings. Measurements and configured budgets are not total request-time/RSS guarantees.
- Author self-review reproduced and fixed two Important issues: overflowed PE header mappings and declaration evidence pointing at unavailable data. Targeted regressions were observed **14 failed/7 passed → 21 passed**, followed by the complete green gates. No additional reproduced blocker or deferred Minor was identified; no new independent security-review claim is made.
- Pre-publication checks through **23:43 UTC on November 3** preserved the original counts/digest/assets, including the separate refresh and soft-deleted revision-1 note saved at **22:55:48 UTC**. Later outside audit-cache entries at **00:11:50Z/00:15:20Z** were also retained. The authorized **00:23 UTC** restart used the latest stopped original, never an older restored backup; before/after/live-acceptance digests match at **2,064 records/2,191 evidence rows/two query-cache rows/one soft-deleted note**, zero active notes/watch entries.
- Product `0ff4204` was pushed without force to public `main`. Private rehearsal passed; the production build matched exact verified assets. Existing launcher now runs as PID **133311** on **8731**, refresh disabled. Live localhost/host-LAN checks passed twelve direct API cases, 32 cached views, six executable browser uploads, eighteen reflow states, and thirty-two keyboard table scrolls, with zero browser errors or external page requests. Complete cached CVE text/evidence/export and eight source IDs are intact; representative screenshots were inspected.
- Subsequent outside audit use at **00:27:37 UTC** added a third cache row and changed three OSV request-state fields, not records, evidence, notes, aliases, or search data. Both older cache rows remain byte-identical. A separate protected latest-data backup/API baseline at **00:35 UTC** preserves this activity; immutable restart/acceptance evidence stays separate. Only the temporary final verifier's stale-baseline assumption changes; no product/data restoration.
- Fresh delivery gates pass **220 backend tests in 68.84s**, **60 isolated Firefox tests in 2.3m**, Ruff, and production build. Delivery documentation is separate from unchanged tested product bytes. No service/network change, separate-device LAN test, or obsolete handoff helper. Detailed evidence: [executable delivery verification](docs/verification.md#public-delivery-and-live-acceptance--2026-11-04); temporary ledger/review/private artifacts remain outside Git at `/tmp/opencode/signal-atlas-executable-checks/`.
