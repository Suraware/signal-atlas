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
- Author self-review findings were reproduced, regression-tested RED→GREEN, and retested. Inline execution means no independent reviewer; no reproduced blocker remains in the reviewed scope.
- Original-workspace handoff: loopback/localhost/LAN health and 14 additional read-only Firefox combinations pass. Existing research data is unchanged; startup only added the expected empty audit-cache table. The LAN launcher was started for use, without installing a service or changing network settings.
