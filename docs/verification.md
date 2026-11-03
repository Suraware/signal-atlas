# Signal Atlas verification

Verified on **2026-11-03**. These results apply to this session's source snapshot, not to every future change or deployment. The application remains an early, repository-run release for one researcher or a trusted LAN.

## Combined analyzer and CVE upgrade

The following checks cover delivered product commit `2c1e877`, including dense UTF-16 scanning, complete IPv6 candidates, and cache-first CVE search. Earlier snapshots below are retained as history, not substituted for these gates. The single fresh-context review and its inline fixes are complete. The separate analyzer and CVE commits are public, and the updated original-workspace handoff passed. Delivery documentation is recorded separately from the tested product code.

| Gate | Command | Observed result |
| --- | --- | --- |
| Backend behavior | `.venv/bin/python -m pytest -q` | **104 passed**, 25.38 seconds |
| Python static checks | `.venv/bin/ruff check backend tests scripts` | All checks passed |
| Production interface | `npm --prefix frontend run build` | TypeScript and Vite build passed |
| Browser acceptance | `npm --prefix frontend test` | **42 isolated Firefox tests passed**, 1.4 minutes |

### Complete headings and existing-CVE search

- CVE.org, CIRCL, and NVD fallback headings and explicit titles retain complete plain text within 50,000 characters. Legacy 180/500-character prefixes recover only when matching saved observations agree on an unambiguous extension. Genuine, conflicting, or unknown heading evidence vetoes recovery. Detail, list, and exports leave raw evidence and the SQLite logical dump unchanged.
- Submitting an older uncached CVE retrieves fixed source evidence and opens the detail record. Subsequent submission validates and reuses the local record. Typing, partial identifiers, product/package searches, non-404 cache errors, and malformed successful cache responses do not trigger public lookup.
- Targeted CVE.org/CIRCL HTTP 404s report a missing record rather than a source failure; feed/list-endpoint 404s remain errors. Request budgets are still enforced. The real-browser missing-record regression observes existing persistent budgets rather than resetting or bypassing them.
- Source failures and genuine missing records have distinct feedback. Immediate in-flight guards prevent duplicate requests. Edited queries, navigation round trips, and new drafts prevent stale redirects; a completed result remains available through **Open cached record**. Unsaved-note protection remains effective.
- Full-list/detail headings wrap at 1440px, 720px, and 390px. Untrusted source markup stays plain text. Compact overview previews remain clipped by design.
- The real cached `CVE-2026-111357` reads as a complete **200-character** source heading ending “as exploited in the wild in October 2026.” on both the private backup and the updated original app. Its different merged description and original saved observations remain intact.

Controlled older-CVE fixtures prove application behavior, **not current live availability** at public services. The upgrade verifiers initiated no live intelligence lookup.

### Larger-file measurements

Six disposable-subprocess checks passed with a 45-second diagnostic timeout and a 768 MiB address-space containment budget:

| Input | Inspection time | Process peak RSS |
| --- | ---: | ---: |
| Padded 64 MiB, with late ASCII/UTF-16 indicators and a ZIP signature | 9.946 s | 178.2 MiB |
| Dense ASCII, 1 MiB | 0.182 s | 21.0 MiB |
| Dense ASCII, 64 MiB | 10.017 s | 178.0 MiB |
| Deterministic high-entropy bytes, 64 MiB | 16.826 s | 258.0 MiB |
| Dense UTF-16LE, 64 MiB | 16.491 s | 211.9 MiB |
| Oversized IPv6 scope token with a valid trailing address, 64 MiB | 10.314 s | 178.2 MiB |

The initial dense ASCII 64 MiB check exceeded 45 seconds. Profiling located the oversized-domain regex as the dominant cost. Regression tests now reject false suffix domains, bound retained indicators without losing valid tail candidates, and scan UTF-16 indicators independently of string previews. Heuristic windows are measured in bytes, including multibyte UTF-8 inputs.

The first dense UTF-16 check raised `MemoryError` inside the repeated printable-run regex. A full-size regression reproduced it before the fix. Overlapping 64 KiB match windows now merge byte spans without retaining whole-run regex state; one dense run still produces one preview and retains tail URL/domain/IP indicators. Three-character runs contribute indicators independently of the unchanged six-character preview minimum. Both byte alignments and crossing indicators are covered. The final focused analysis suite passed **39 tests** before the combined suite above.

IPv6 regressions cover compressed addresses, IPv4-mapped addresses, bracketed endpoints, invalid ninth groups, invalid IPv4 tails, token boundaries, and 64/65-character scopes. Oversized scopes are rejected as whole tokens, not truncated into invented addresses. Retained IPv6 candidates are at most 110 characters. Supported Python releases may format IPv4-mapped addresses in hexadecimal or dotted notation.

Two real Firefox multipart uploads of exactly **67,108,864 bytes** passed on the private-backup production server. The padded fixture completed in **11.571 seconds**: its whole-file SHA-256 matched, indicators at 48/60 MiB appeared, and the ZIP offset was **41,943,040**. The oversized-scope fixture completed in **11.346 seconds**, retained only the valid `fe80::2%eth0` tail lead, and returned **3,646 bytes** of JSON. Both results fit desktop/mobile widths; all 512 entropy bars fit. The production API rejected **64 MiB + 1 byte** with HTTP 413.

The server's observed high-water RSS after those checks was **337.1 MiB**. Across **56** concurrent health probes, median latency was **0.024 seconds**, maximum **2.736 seconds**, and no probe failed. These are local measurements for these inputs and this run, **not application time or memory guarantees**. The diagnostic timeout and address-space containment are verifier settings, not application limits. Concurrent requests, different files, hardware, or runtime versions can change the measurements.

### Changed-surface accessibility and production

- **24 axe-core 4.14.0 scans** covered full headings, lab results, pending/error search feedback, malformed-cache and missing-record feedback, and cached-search results at 1440px/720px/390px. They reported zero automated violations, incomplete rules, page/console errors, or external page requests. Lookup-state scans used local controlled responses; they did not contact public intelligence services.
- Native named `figure` semantics replaced an invalid `role="img"` on the entropy figure. Keyboard submission, main-workspace focus, adjacent network descriptions, live busy/error states, measured ≥44px submit targets, and reduced-motion spinner behavior passed.
- Actual **200% Firefox 158.0.1 browser zoom** passed full-list/detail text, cached keyboard search, and a 512-bucket lab result. The viewport changed from **1440px to 720px**, DPR from **1 to 2**. This was not CSS zoom or device emulation. Screenshots were captured and inspected.
- The real launcher used a private backup of **2,062 records** on alternate port **8733**, leaving the original port 8731 server untouched during write/upload testing. Loopback → LAN → loopback verified two restarts, host/origin rejection, unchanged source inventory, disabled automatic refresh, and private storage modes.
- **28 production view/width/origin combinations** and both full-size uploads passed at localhost and host LAN origins. There were no browser errors, failed responses, public lookups, or external page requests. A test note reached revision 3; the linked record's watch state, relationship, and original source evidence survived both restarts on the copy. All three shutdowns logged completion.
- A separate **32-view GET/HEAD-only rehearsal** passed on the private backup before the original server was touched. It verified the reported CVE's complete list/detail/export heading, cached keyboard submission and focus, and original raw evidence. No write, external request, failed request/response, or browser error was observed.
- A read-only comparison after testing matched the original database baseline exactly: **2,062 records, 2,189 evidence rows, zero notes**, logical SHA-256 `e878878800436b9cceefeaa275044d9b44427a3e9a214b40985bd4ea40918d78`.

No physical-device LAN test, assistive-technology user study, full accessibility certification, or independent penetration test is claimed.

### Fresh-context review

One fresh-context read-only review of the combined upgrade completed with no Critical findings. Its four Important findings and the two additional indicator findings entered one inline fix pass, with **19 backend** and **seven Firefox** failing regressions observed first. The fixes cover ambiguous title provenance, malformed successful cache reads, genuine targeted upstream 404s, oversized IPv6 scopes, missing/invented IPv6 forms, and short UTF-16 indicators. All final gates above passed after the fixes; no Critical or Important finding remains in that reviewed scope. This is not a penetration test or a guarantee that no other defects exist.

### Public delivery and updated original-workspace handoff

The repository is [Suraware/signal-atlas](https://github.com/Suraware/signal-atlas), confirmed **PUBLIC** with default branch **main**. The baseline was published first; the upgrades were committed separately and pushed without force:

| Commit | Delivered change |
| --- | --- |
| `bddb30d` | Initial public baseline |
| `3d819fc` | Initial 64 MiB static analyzer upgrade |
| `464463c` | Bounded scans, complete indicators, and entropy-map fixes |
| `2c1e877` | Complete CVE headings and cache-first existing-CVE search |

Fresh pre-push gates passed **104 backend tests**, **42 isolated Firefox tests**, Ruff, production build, and staged whitespace checks. The committed tree matched the verified index. The public remote and clean local `main` both resolved to `2c1e877` after the product push. Private data, environments, build output, and test artifacts are not tracked. Final delivery-evidence updates change documentation only.

At **21:43 UTC**, the identity-checked handoff stopped only the original Signal Atlas process **55147** using its PID file descriptor. Its log confirmed application shutdown completion. `./start.sh --lan --port 8731` then started the updated app as process **104798**, using the original `data/` directory. It serves the current production HTML, JavaScript, and CSS at loopback, localhost, and **http://192.168.0.7:8731**. Automatic refresh remains disabled. No service or network configuration was installed or changed.

The original app passed **32 GET/HEAD-only Firefox view/width/origin combinations** at 1440px and 390px. The complete reported CVE heading appeared in its list, detail, and JSON export. Cached submission focused the main workspace and made no public lookup. Original raw evidence remained available. No page/console error, failed request/response, write request, or external page request was observed. Desktop and narrow screenshots were inspected.

Before shutdown, after shutdown, after startup, and after the read-only checks, every original table count and the complete logical SHA-256 matched the baseline: **2,062 records, 2,189 evidence rows, zero notes**, `e878878800436b9cceefeaa275044d9b44427a3e9a214b40985bd4ea40918d78`. No schema addition, research-note edit, watchlist change, or live intelligence lookup was needed for this handoff. Host LAN access is verified; separate-device reachability remains untested. The listener is still unauthenticated HTTP for a trusted LAN only.

After the clean **21:44 UTC** handoff check, a separate local client requested `POST /api/sync`, which the server accepted. Source-state timestamps show the refresh at **21:45 UTC**. It changed the live cache to **2,064 records and 2,191 evidence rows**; all 2,062 original record IDs remain present, with zero notes and watched records. The verifiers did not issue that request and did not roll back the refresh. A later comparison therefore no longer matches the pre-refresh digest. The preserved handoff snapshots still prove restart integrity; the final report distinguishes that proof from subsequent live-cache activity.

## Initial analyzer snapshot (`3d819fc`)

The Analysis lab was extended and re-verified with tests written first (each observed failing, then passing):

| Gate | Command | Observed result |
| --- | --- | --- |
| Backend behavior | `.venv/bin/python -m pytest tests -q` | 50 tests passed (6 new analysis behaviors + upload-cap pins) |
| Python static checks | `.venv/bin/ruff check backend tests scripts` | All checks passed |
| Production interface | `npm --prefix frontend run build` | TypeScript and Vite build passed |
| Browser acceptance | `npx playwright test` | 19 isolated Firefox tests passed (new larger-artifact flow) |

New verified behaviors: files up to **64 MiB** (request-body ceiling 66 MiB), whole-file strings and indicators (ASCII + UTF-16LE), block entropy map with ≤512 buckets and marked high-entropy regions, up to 100 embedded file signatures located and never extracted, IPv6/domain/base64-run indicator families, and heuristic rules covering the first 16 MiB plus the final 1 MiB with a warning when middle bytes are skipped.

### Analyzer-only follow-up staging

Before committing the follow-up separately from CVE work, a source-only copy of the analyzer-only Git index passed **72 backend tests**, **20 isolated Firefox tests**, Ruff, and the TypeScript/Vite build. Shared CSS/browser files contained only analyzer changes; CVE source adapters, storage, search, and fixtures matched `3d819fc`. This check reused the existing locked dependencies, not a fresh dependency installation. No private data or build output was copied.


## Initial release build and test results

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
- Inspect artifact headers, hashes, whole-file strings and indicators, the entropy map, located embedded file signatures, and bounded PCAP/PCAPNG summaries without executing input or starting a capture.
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

## Initial-release original-workspace handoff

At **14:41 UTC**, `./start.sh --lan --port 8731` was started from `/home/seer/Documents/Opensource` against its original `data/` directory. The production interface and health endpoint responded at loopback, localhost, and the host's LAN address. Automatic refresh remained disabled.

A final isolated Firefox run checked **14 read-only view/width/origin combinations**, plus cached search, raw evidence, and JSON export on both localhost and LAN. It recorded zero page/console errors, failed requests/responses, external page requests, or write requests.

The older live database lacked the audit-cache table. Startup added only the expected empty `query_cache` table. Excluding that single schema addition, the complete logical dump matched the pre-launch SHA-256 exactly: existing records, evidence, source state, search data, and the empty notes/watchlist were unchanged. This launcher is not installed as a system or startup service.

## Initial-release author review and fixes

The user requested inline execution without agents. Review was therefore an author self-review, not an independent code review or security audit.

Focused review covered source failure/cache behavior, identifier and upload validation, plain-text rendering and safe citations, note revisions, browser navigation, startup boundaries, and the lab's no-execution behavior. Reproduced findings received failing regressions before their fixes:

- Invalid definition-list structure, skipped empty-state headings, and malformed encoded routes.
- Graph relationship lines below 3:1 contrast; the failing measurement was **1.433:1** against grid dots. The existing muted color now passes at both widths.
- Malformed OSV batches publishing duplicate/partial rows, replacing a useful cache, or reporting premature success. The entire batch is now validated before publishing results or replacing caches. Two regressions cover existing-cache and no-cache cases.

No reproduced blocker remains in that reviewed scope. Tests and self-review do not establish that the application is free of security defects.

## Session evidence locations

These local reports, temporary verifier scripts, screenshots, and traces are **not repository deliverables** and may be removed with temporary storage:

- Combined upgrade: `/tmp/opencode/signal-atlas-upgrade-checks/large-file-benchmark.json`, `large-file-before.json`, and `large-file-utf16-before.json` preserve the passing measurements and reproduced failures. `original-data-before.json`, `original-data-pre-final-refresh.json`, and `original-data-after-upgrade-tests.json` prove original-data preservation. Earlier JSON reports were copied under `pre-final-refresh-20261103T212201Z` before rerunning the verifiers.
- Changed surfaces: `/tmp/opencode/signal-atlas-upgrade-checks/accessibility/report.json` and `upgrade-browser-zoom.json`, with screenshots and traces. Verifiers: `signal-atlas-upgrade-a11y.cjs`, `signal-atlas-upgrade-browser-zoom.py`, and `signal-atlas-upgrade-accessibility-run.py` under `/tmp/opencode`.
- Upgrade production: `/tmp/opencode/signal-atlas-upgrade-checks/production/report.json` and `browser-report.json`, with three launcher logs, upload fixtures, screenshots, and traces. `production/read-only-rehearsal/browser-report.json` records the 32-view handoff rehearsal. Verifiers: `/tmp/opencode/signal-atlas-upgrade-production.py`, `signal-atlas-upgrade-production-browser.cjs`, and `signal-atlas-upgrade-final-browser.cjs`.
- Analyzer-only staging: `/tmp/opencode/signal-atlas-upgrade-checks/staged-analysis/report.json` and four gate logs; source-only index copy: `/tmp/opencode/signal-atlas-staged-analysis-ez6k6zor/`. Verifier: `/tmp/opencode/signal-atlas-verify-staged-analysis.py`.
- Updated original-app handoff: `/tmp/opencode/signal-atlas-upgrade-checks/handoff/report.json` and `browser-report.json`, with launcher/browser logs, screenshots, and read-only traces. Verifier: `/tmp/opencode/signal-atlas-upgrade-handoff.py`. `original-data-before-delivery.json` records the immediate pre-delivery baseline comparison.
- Public delivery: `/tmp/opencode/signal-atlas-upgrade-checks/delivery/pre-push-gates.json`, `pre-push-firefox.log`, `public-product-handoff.json`, and `report.json`. The final report verifies public visibility, matching clean local/remote HEAD, the running updated process, served asset bytes, preserved restart-integrity snapshots, and separately requested later cache activity. `post-refresh-baseline-check-failed.json` and `post-handoff-data-diagnostic.json` preserve the detected change rather than hide or undo it. Verifier: `/tmp/opencode/signal-atlas-upgrade-delivery.py`.

- Clean installation: `/tmp/opencode/signal-atlas-clean-final-kzqeqiin/`; snapshot metadata: `/tmp/opencode/signal-atlas-clean-final-metadata.json`.
- Accessibility: `/tmp/opencode/signal-atlas-accessibility/report.json`, `svg-contrast.json`, and `browser-zoom.json`, with screenshots and traces in that directory.
- Production and restarts: `/tmp/opencode/signal-atlas-production/report.json` and `browser-report.json`, with launcher logs, screenshots, and Firefox traces.
- Original-workspace handoff: `/tmp/opencode/signal-atlas-final-server/health-report.json`, `browser-report.json`, and `data-integrity.json`, with read-only screenshots/traces. Launcher log: `/tmp/opencode/signal-atlas-user-server.log`.
- Extra session verifiers: `/tmp/opencode/signal-atlas-accessibility.cjs`, `signal-atlas-svg-contrast.cjs`, `signal-atlas-browser-zoom.py`, `signal-atlas-production-check.py`, and `signal-atlas-production-browser.cjs`.
- Final read-only verifiers: `/tmp/opencode/signal-atlas-final-browser.cjs` and `signal-atlas-final-data-check.py`.

For a fresh installation, follow [the README's locked setup and test commands](../README.md#development-and-tests). The source-only copy installed dependencies using `uv sync --frozen --extra dev` and `npm --prefix frontend ci`; it did not reuse copied environments, build output, or private data. The final documentation was synchronized after these gates without changing the tested product code.

## Remaining limits

Eight sources are an initial integration set, not all free APIs. Upstream access, quotas, terms, and schemas can change. A cache can be incomplete or stale; missing severity remains unknown. Static inspection is not antivirus, sandboxing, exploit validation, decompilation, or a full code audit. Authentication, TLS, cloud sync, autonomous exploitation, and internet-facing deployment are outside this release. See [the README's research and analysis boundaries](../README.md#research-and-analysis-boundaries).
