# Signal Atlas verification

Verified on **2026-11-03**. These results apply to this session's source snapshot, not to every future change or deployment. The application remains an early, repository-run release for one researcher or a trusted LAN.

## Build and test results

The original workspace and a fresh source-only copy passed these gates:

| Gate | Command | Observed result |
| --- | --- | --- |
| Backend behavior | `.venv/bin/python -m pytest -q` | 43 tests passed |
| Python static checks | `.venv/bin/ruff check backend tests scripts` | All checks passed |
| Production interface | `npm --prefix frontend run build` | TypeScript and Vite build passed |
| Browser acceptance | `npm --prefix frontend test` | 18 isolated Firefox tests passed |

The final original-workspace gates were rerun after the reproduced review findings were fixed. The clean copy's 52 source files matched the original snapshot by SHA-256 before the final documentation updates.

Test environment: Linux, Python **3.12.13**, Node.js **22.23.2**, uv **0.12.0**, and Playwright Firefox **157.0**. This does not establish compatibility with every supported Python version or operating system.

## Verified research workflows

- Search cached intelligence, inspect source-specific raw evidence, and export linked JSON/Markdown context.
- Correlate identifiers without duplicate vulnerabilities; preserve evidence and cached records when a public request fails.
- Save a note repeatedly, reload its saved content, link CVE mentions, and inspect actual relationships in the graph and table.
- Warn before replacing an unsaved draft through internal navigation, a new note, or browser history. Reject stale LAN revisions without overwriting the newer note or erasing the local draft.
- Delete and restore saved notes. Display imported notes and untrusted strings as plain text.
- Parse exact npm, Python, and CycloneDX package versions. Without network consent, show cached evidence or **Not checked**, not a clean result.
- Inspect artifact headers, hashes, strings, and bounded PCAP/PCAPNG summaries without executing input or starting a capture.
- Reject unknown sources, malformed identifiers, oversized bodies, and foreign browser hosts/origins at the local API boundary.

Backend and browser suites use controlled external-response fixtures and isolated data. Fixture exploitation flags and OSV matches are **not live intelligence**.

## Public-source verification

All eight selected public endpoints returned HTTP 200 without credentials on this date. The [probe record](api-probes.json) contains the requests and response metadata.

The [initial live sync](initial-sync.json), recorded at **13:07 UTC**, cached **2,052 correlated vulnerabilities**, including **1,766 CISA KEV entries**. This is a bounded, overlapping sample, not complete public-database coverage. See [source coverage, budgets, and attribution](sources.md).

## Accessibility and responsive checks

- **24 axe-core 4.14.0 scans** covered eight routes and four additional result/error/empty states at **1440px and 390px**. They reported zero automated violations, page errors, or external page requests.
- Axe left one SVG `color-contrast` rule incomplete at each width. Manual measurements of graph text and relationship lines passed: minimum **4.724:1**, including the grid-dot background. Text was checked against 4.5:1 and relationship lines against 3:1.
- Keyboard-only navigation through the skip link, manifest format, textarea, consent control, submit button, and audit result passed.
- Reduced-motion preference disabled the loading spinner's animation.
- Actual **200% browser zoom** passed across eight routes and a lab submission in a fresh Firefox **158.0.1** WebDriver profile. Browser zoom changed the layout viewport from **1440px to 720px** and the device-pixel ratio from **1 to 2**. No page overflow was observed. This was not CSS zoom or device emulation.
- Desktop, narrow-layout, graph, and zoom screenshots were captured and inspected.

These checks are not a full accessibility certification. No assistive-technology user study or physical mobile-device test was performed.

## Production, LAN, and persistence checks

The real executable launcher was exercised from outside the clean-copy project folder against a **private SQLite backup**. The sequence was loopback → LAN → loopback, with two restarts.

- Default startup bound only `127.0.0.1:8731`; the host's LAN address did not respond in that mode.
- Explicit `--lan` bound `0.0.0.0:8731`. Health, production assets, and cached API data responded at localhost and **http://192.168.0.7:8731** from the host.
- **24 production browser combinations** covered six views, two widths, and localhost/LAN origins. There were zero page errors, console errors, failed browser responses, or external page requests.
- A LAN note edit reached revision 3, survived reload and restart, and appeared as a real evidence relationship. Records, original source evidence, watchlist state, and context exports survived both restarts.
- Source inventory stayed unchanged and automatic refresh stayed disabled during startup and cached workflows.
- The private test directory and database used modes `0700` and `0600`.
- All three shutdowns logged application shutdown completion. Uvicorn then re-raised the received SIGTERM, producing process exit code `-15`; this was not an application shutdown failure.

Production write/restart checks did **not** add test notes or watchlist changes to the original workspace. LAN reachability was tested from the host, **not from a separate physical device**. No firewall, router, Wi-Fi, or public-deployment settings were changed.

**LAN access is unauthenticated HTTP. Anyone who can reach the listener can read and change the workspace.** Use only a trusted network; do not forward the port or expose it to the internet. Host/origin checks are not authentication. See [security boundaries](security.md).

## Original-workspace handoff

At **14:41 UTC**, `./start.sh --lan --port 8731` was started from `/home/seer/Documents/Opensource` against its original `data/` directory. The production interface and health endpoint responded at loopback, localhost, and the host's LAN address. Automatic refresh remained disabled.

A final isolated Firefox run checked **14 read-only view/width/origin combinations**, plus cached search, raw evidence, and JSON export on both localhost and LAN. It recorded zero page/console errors, failed requests/responses, external page requests, or write requests.

The older live database lacked the audit-cache table. Startup added only the expected empty `query_cache` table. Excluding that single schema addition, the complete logical dump matched the pre-launch SHA-256 exactly: existing records, evidence, source state, search data, and the empty notes/watchlist were unchanged. This launcher is not installed as a system or startup service.

## Author review and fixes

The user requested inline execution without agents. Review was therefore an author self-review, not an independent code review or security audit.

Focused review covered source failure/cache behavior, identifier and upload validation, plain-text rendering and safe citations, note revisions, browser navigation, startup boundaries, and the lab's no-execution behavior. Reproduced findings received failing regressions before their fixes:

- Invalid definition-list structure, skipped empty-state headings, and malformed encoded routes.
- Graph relationship lines below 3:1 contrast; the failing measurement was **1.433:1** against grid dots. The existing muted color now passes at both widths.
- Malformed OSV batches publishing duplicate/partial rows, replacing a useful cache, or reporting premature success. The entire batch is now validated before publishing results or replacing caches. Two regressions cover existing-cache and no-cache cases.

No reproduced blocker remains in that reviewed scope. Tests and self-review do not establish that the application is free of security defects.

## Session evidence locations

These local reports, temporary verifier scripts, screenshots, and traces are **not repository deliverables** and may be removed with temporary storage:

- Clean installation: `/tmp/opencode/signal-atlas-clean-final-kzqeqiin/`; snapshot metadata: `/tmp/opencode/signal-atlas-clean-final-metadata.json`.
- Accessibility: `/tmp/opencode/signal-atlas-accessibility/report.json`, `svg-contrast.json`, and `browser-zoom.json`, with screenshots and traces in that directory.
- Production and restarts: `/tmp/opencode/signal-atlas-production/report.json` and `browser-report.json`, with launcher logs, screenshots, and Firefox traces.
- Original-workspace handoff: `/tmp/opencode/signal-atlas-final-server/health-report.json`, `browser-report.json`, and `data-integrity.json`, with read-only screenshots/traces. Launcher log: `/tmp/opencode/signal-atlas-user-server.log`.
- Extra session verifiers: `/tmp/opencode/signal-atlas-accessibility.cjs`, `signal-atlas-svg-contrast.cjs`, `signal-atlas-browser-zoom.py`, `signal-atlas-production-check.py`, and `signal-atlas-production-browser.cjs`.
- Final read-only verifiers: `/tmp/opencode/signal-atlas-final-browser.cjs` and `signal-atlas-final-data-check.py`.

For a fresh installation, follow [the README's locked setup and test commands](../README.md#development-and-tests). The source-only copy installed dependencies using `uv sync --frozen --extra dev` and `npm --prefix frontend ci`; it did not reuse copied environments, build output, or private data. The final documentation was synchronized after these gates without changing the tested product code.

## Remaining limits

Eight sources are an initial integration set, not all free APIs. Upstream access, quotas, terms, and schemas can change. A cache can be incomplete or stale; missing severity remains unknown. Static inspection is not antivirus, sandboxing, exploit validation, decompilation, or a full code audit. Authentication, TLS, cloud sync, autonomous exploitation, and internet-facing deployment are outside this release. See [the README's research and analysis boundaries](../README.md#research-and-analysis-boundaries).
