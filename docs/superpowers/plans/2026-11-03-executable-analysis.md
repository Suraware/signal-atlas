# Executable analysis implementation plan

> **For agentic workers:** Use `executing-plans` to implement task by task. User-selected method: inline; do not dispatch implementer agents.

**Goal:** Explain PE/ELF structure and imports with exact evidence offsets in the existing local analysis lab.

**Architecture:** A focused `backend/atlas/executables.py` owns checked binary reads, limits, and PE/ELF parsing. `analyze_file(filename, data)` adds an optional `executable` report without changing current generic analysis or capture behavior. The existing Lab renders the additive contract with semantic tables and native disclosures.

**Tech stack:** Python 3.11+ standard library, FastAPI, React 19/TypeScript, existing CSS, pytest, isolated Playwright Firefox.

**Spec:** `docs/designpowers/briefs/2026-11-03-executable-analysis.md`

## Global constraints
- 64 MiB uploads; no execution/extraction/decompression/network/parser subprocess/new runtime dependency.
- 256 sections; 128 program headers/import descriptors/import libraries; 512 retained imported symbols.
- 20,000 symbol/thunk records and 4,096 dynamic records per file; 512-byte terminated names.
- 64 MiB cumulative section-entropy work; 50 findings; 64 warnings; visible reached limits.
- Exact hexadecimal address/offset strings and decimal declared-size/count strings.
- Preserve CVE behavior, research data, generic indicators/captures, and the deferred graph scope.
- Existing `DESIGN.md` tokens, keyboard-operable labeled tables/disclosures, literal source text, and 200% reflow.

## Review focus
1. A printable API/library name outside an import table must not become a structured import.
2. A virtual-only/ambiguous entry or import address must not map to an arbitrary file range.
3. Missing ELF sections, extended numbering, large integers, NOBITS, and linked-table failures must stay explicit and bounded.
4. Repeated/overlapping ranges and oversized table counts must not cause repeated unbounded entropy or symbol work.
5. Partial/malformed reports and long attacker-controlled names must not break Firefox, hide warnings, execute markup, or overflow the page.

## Task 1: checked PE structure

**Files:** create `backend/atlas/executables.py`, `tests/executable_fixtures.py`, `tests/test_executables.py`; modify `backend/atlas/analysis.py`.

**Interface:** `inspect_executable(data: bytes) -> dict | None`; `analyze_file` adds `executable` only for MZ/ELF inputs. Report includes `format`, `status`, `architecture`, `bitness`, `byte_order`, `kind`, `entry_point`, `sections_declared`, `program_headers_declared`, `sections`, `load_segments`, `imports`, `findings`, `warnings`, and `limits`.

- [x] Write PE32/PE32+ fixture assertions for architecture, entry RVA/address/file offset, section ranges/flags, exact entropy, and non-executable omission. Test zero-filled/overlapping entries, short headers, invalid optional sizes, out-of-file ranges, and section-count limits.
- [x] Run `.venv/bin/python -m pytest tests/test_executables.py -q` and preserve missing-feature failures before production code.
- [x] Implement checked headers/regions, bounded entropy/finding/warning collection, and additive analysis integration.
- [x] Re-run focused tests and existing analysis regressions; fix failures before proceeding.

## Task 2: PE imports

**Files:** same backend/test files.

**Interface:** `imports.libraries` entries have `name`/`offset`; `imports.symbols` entries have `name`, `ordinal`, `library`, `offset`, and `binding`. Offsets identify the library-name bytes and the import record respectively.

- [x] Add named and ordinal import assertions for both thunk widths, OriginalFirstThunk fallback, imported-symbol bait rejection, descriptor/thunk bounds/terminators, missing DLL/name pointers, and record/output caps.
- [x] Observe focused RED failures.
- [x] Decode only mapped normal import structures; keep unsupported delay imports explicit. Reject unterminated/oversized names; never guess ordinal names or runtime IAT contents.
- [x] Re-run focused PE tests and all backend tests.

## Task 3: ELF structure and imports

**Files:** same backend/test files.

**Interface:** same report shape; ELF symbol `library` is null and binding is explicit. `load_segments` carry PT_LOAD file/memory ranges and R/W/X declarations. Sections distinguish NOBITS (zero file bytes) from malformed ranges.

- [x] Add ELF32/64 little/big-endian fixtures with literal expected entry mappings, section names, DT_NEEDED libraries, and undefined symbols; unrelated text must not be imported.
- [x] Add RED cases for sectionless dynamic dependencies, relocatable symbols, extended numbering, huge exact integers, invalid linked indexes/entry sizes, duplicate/ambiguous PT_LOAD mappings, NOBITS, malformed dynamic tables, missing terminators, and scan/output/entropy budgets.
- [x] Implement checked ELF headers/tables and bounded selected structures; preserve unsupported/partial evidence explicitly.
- [x] Run focused tests, deterministic mutation/truncation checks, and independent metadata comparison against benign local compiler outputs.

## Task 4: accessible end-to-end report and delivery proof

**Files:** modify `frontend/src/types.ts`, `frontend/src/pages/Lab.tsx`, `frontend/src/styles.css`, `README.md`; create `frontend/tests/executables.spec.ts` and test-only fixture helpers; update security/delivery documentation and design state.

- [x] Write real-upload Firefox tests for PE/ELF structure, scoped import evidence, invalid/partial warnings, literal long names, existing strings/entropy, named keyboard-scrollable tables, and disclosures at 1440/720/390px.
- [x] Observe browser RED before adding report UI; preserve traces/screenshots outside version control.
- [x] Render the additive contract before generic strings; show all offsets and declared flags in words. Do not label parsed structures or empty imports as safe/clean.
- [x] Run all backend tests, all isolated Firefox tests, Ruff, production build, and `git diff --check`.
- [x] Run changed-surface axe checks, actual 200% Firefox zoom, real benign PE/ELF uploads, and bounded larger-file/hostile-table measurements with preserved artifacts.
- [x] Document capabilities, exact limits, evidence, and omissions; retain existing CVE/graph behavior and research data. Do not rerun the obsolete original-server handoff script.

## Verification budget
Owner: the inline implementer for each claim. No new independent-review claim.
- Format correctness: hand-derived byte fixtures plus `readelf`/`objdump` comparisons; these establish selected static structures, not Windows/Linux loader acceptance.
- Safety/bounds: adversarial count/range/terminator fixtures, deterministic mutations, and disposable-process measurements; no wall-time/memory guarantee.
- API/UI: real local uploads through the isolated SQLite/API server and fresh Firefox contexts; no live intelligence requests or personal browser profile.
- Regression preservation: required complete backend/Firefox suites plus lint/build/whitespace.
- Accessibility: changed-surface automated scans, keyboard interaction, and actual zoom; no assistive-technology user-study/certification claim.

## Baseline
- Clean `main` at `1105268` before changes.
- Existing full backend suite: **104 passed in 47.15s** before implementation.
- Execution remains inline; no production data was edited and no live lookup was initiated.

## Completion evidence
- Full post-fix backend: **220 passed in 57.85s**; isolated Firefox: **60 passed in 2.1m** (18 executable tests); Ruff, isolated TypeScript/Vite build, tracked/new-file whitespace, and local documentation links pass.
- Fresh pre-integration repeat: **220 backend tests in 63.21s**, **60 Firefox tests in 2.1m**, isolated rebuild, Ruff, final whitespace, **23 local documentation links**, and server cleanup pass. Source hashes are retained for all **18 changed files**; no product code changed after the post-fix gates.
- **36** changed-surface axe/keyboard/reflow states and **11** actual 200% Firefox zoom states pass. Three direct API and five fresh-context Firefox compiler-artifact uploads pass, including both exact 64 MiB overlays and the **413** oversize rejection. **15** contained-process post-fix cases pass; verifier limits are not application time/RSS guarantees.
- Author self-review, not independent review: two reproduced mapping/evidence findings were fixed in one RED→GREEN pass (**14 failed/7 passed → 21 passed**), followed by complete green gates. No additional reproduced blocker or deferred Minor was identified.
- Pre-publication original data and assets matched the complete real-upload snapshot, including the separately requested refresh and soft-deleted revision-1 note. Later outside audit-cache entries were preserved in the latest stopped original database, not restored from the older rehearsal copy. The obsolete handoff helper was not executed.
- **Authorized publication and live update are complete:** verified product `0ff4204` was pushed without force at **2026-11-04T00:04:38Z**. Private-backup rehearsal passed; at **00:23 UTC**, only freshly identity-checked PID **104798** was stopped gracefully. Production assets matched exact rehearsed bytes; existing launcher restarted as PID **133311** on **8731**, original data intact and refresh disabled. No service/network change.
- Live localhost/host-LAN acceptance passed **twelve direct API cases**, **32 cached Firefox views**, **six compiler-artifact browser uploads**, **eighteen reflow states**, and **thirty-two keyboard table scrolls**, with zero browser errors/external page requests. The latest full digest matched before/after restart and acceptance: **2,064 records/2,191 evidence rows/two query-cache rows/one soft-deleted note**. Complete cached CVE text/evidence/export and all eight sources remain intact; screenshots were inspected.
- Later outside audit use at **00:27:37 UTC** added one cache row and changed only three OSV request-state fields. Schema, research/search tables, and both older cache rows are unchanged. A separate **00:35 UTC** protected latest-data backup/API baseline preserves **three query-cache rows** without replacing the stopped-database backup or passing restart/acceptance reports. Final checks separate those proofs and reject unverified changes; no product/data restoration.
- Fresh delivery reruns: **220 backend tests in 68.84s**, **60 isolated Firefox tests in 2.3m**, Ruff, and production build pass. Delivery-status documentation changes no tested product bytes. Evidence: [verification.md](../../verification.md#public-delivery-and-live-acceptance--2026-11-04); durable ledger: [progress.md](../../progress.md#executable-analysis-slice--2026-11-03); temporary reports/review/private backups: `/tmp/opencode/signal-atlas-executable-checks/`. No separate-device LAN or new independent-security assurance is claimed.
