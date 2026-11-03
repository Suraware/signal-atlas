# Execution ledger — plan: docs/superpowers/plans/2026-11-03-signal-atlas.md

## Pre-flight
Repository was empty. Store → connectors → API → frontend interface boundaries are defined in the plan. New project can be built in its requested folder without moving or replacing user work.

Ruling: execute inline without agents — user explicitly changed the method — cost: author self-review rather than independent implementation review.
Ruling: use eight initial no-key sources rather than claim all APIs — no finite complete set exists and endpoints have changing access rules — cost: other useful feeds remain future connectors.
Ruling: LAN is a listener on the existing LAN, not a newly configured network — matches the intended app access without altering network settings — cost: another device's reachability still depends on existing firewall rules.

## Progress
- Planning: complete.
- Task 1: complete — 8 tests observed RED (unimplemented store) then GREEN. SQLite persistence, alias promotion, evidence retention, literal search, revision checks, note restore, and real graph edges verified.
- Task 2: complete — 9 connector/sync tests observed RED then GREEN (17 total passing). Eight live no-key HTTP probes returned 200. Adapters enforce response caps, timeouts, minimum request intervals, provenance, and TTL reuse.
- Task 3: complete — 17 lab/API tests observed RED then GREEN; additional RED→GREEN regressions cover chunked body limits, sync shutdown, malformed OSV matches, and whole-batch OSV validation with/without a cache. The final backend suite passes 43 tests and Ruff. File inspection never executes code; remote audits require consent and retain offline cache.
- Task 4: complete — all 18 Firefox acceptance tests pass. RED→GREEN regressions cover repeated saves, draft/navigation protection, skip-link focus, definition-list structure, heading hierarchy, malformed encoded routes, and graph-line contrast. Delete/restore, stale LAN revisions, cached audits, and PCAP rendering also pass. Twenty-four axe scans report zero automated violations; manual SVG contrast, keyboard-only lab flow, reduced motion, and actual 200% Firefox zoom pass. This is not accessibility certification.
- Task 5: complete — executable launcher, README, source/security documentation, MIT license, contribution guide, and lockfiles are present. A fresh 52-source-file copy installed both locked dependency sets, built, and passed 43 backend tests, 18 Firefox tests, and Ruff. Private-backup production tests verified loopback/LAN binding, 24 browser view/width/origin combinations, source evidence and revision-3 note persistence across two restarts, and no external page requests. Host LAN access is verified; another physical device is not. Screenshots/traces and [verification evidence](verification.md) record outcomes and limits.

## Initial private-handoff history
- Product gates and author self-review are complete. No reproduced blocker remains in the reviewed scope; this is not an independent security audit.
- Final original-workspace gates were rerun after the fixes. Product files match the clean-copy snapshot; final documentation is synchronized separately from the tested code.
- Original live cache contains 2,052 correlated vulnerabilities and 1,766 KEV entries. Production write tests used a private backup and did not add notes or watchlist changes to this workspace.
- User-facing launcher started against the original workspace with `./start.sh --lan --port 8731`. Loopback/localhost/LAN health and 14 final read-only Firefox combinations pass with no errors, external requests, or writes. Existing research data matches the pre-launch logical digest; startup only initialized the previously absent empty audit-cache table. Session reports/logs are listed in the verification document.
- No commit, push, publishing, or network-configuration change was performed.

## Public release and upgrades — 2026-11-03
- Public baseline `bddb30d3f8b419818775f7ab3eca001bf6d5a195` was published to [Suraware/signal-atlas](https://github.com/Suraware/signal-atlas) before analyzer changes. The separate initial analyzer commit is `3d819fc`.
- Analyzer follow-ups are committed separately as `464463c`. Its analyzer-only index copy passed 72 backend tests, 20 Firefox tests, Ruff, and build before committing; CVE changes were not included.
- Analyzer follow-up: oversized-domain, indicator retention, UTF-16 preview independence, byte-window, native-figure, and 512-bar overflow regressions were observed RED→GREEN. Dense UTF-16 at 64 MiB additionally reproduced `MemoryError`; bounded overlapping scan windows preserve run boundaries and tail indicators. Complete IPv6 candidate/scope validation and short UTF-16 indicators are fixed. The focused analysis suite passes 39 tests.
- CVE upgrades: complete bounded headings, agreement-based offline legacy recovery, and cache-first full-CVE search are implemented. Ordinary search remains local; non-404 failures and malformed cache successes fail closed. Targeted CVE.org/CIRCL 404s report missing records without changing feed-error or request-budget behavior. Draft/stale-navigation protection remains intact. Details and decisions are in the [CVE plan](superpowers/plans/2026-11-03-cve-search-and-text.md).
- Combined gates: **104 backend tests, 42 Firefox tests, Ruff, TypeScript/Vite build**, six larger-file subprocess measurements, and two real 64 MiB Firefox uploads pass. The oversize production upload returns 413.
- Changed-surface proof: 24 zero-violation axe scans, keyboard/label/focus/reduced-motion checks, native 200% zoom, 28 private-backup production combinations, and a 32-view read-only handoff rehearsal pass. Two restarts preserve source evidence and revision-3 notes on the private copy. Health timing and memory measurements are recorded, not promised as bounds.
- Current original data: **2,062 records, 2,189 evidence rows, zero notes**. Read-only logical comparison proves test runs have not changed it. No test note/watch edit or live public lookup touched this workspace.
- One fresh-context read-only review completed; its four Important and two additional indicator findings were reproduced and fixed in one inline RED→GREEN pass. Separate upgrade commits/push and the read-only original-workspace restart/handoff remain pending. Implementation remains inline; verification evidence is in [verification.md](verification.md). The approved graph redesign remains deferred.
