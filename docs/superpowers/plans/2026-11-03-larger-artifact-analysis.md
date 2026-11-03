# Larger artifact analysis implementation plan

> Inline execution in this session. Test behaviors before changes; verification gates refresh the existing reports.

**Goal:** Make the Analysis lab actually useful for larger files — a 64 MiB cap, whole-file string and indicator scans, an entropy map, embedded-segment discovery, and richer network indicators — with per-block insight.

## Global constraints
- No execution of analyzed data, no extraction/opening of found segments, no external upload.
- Backends stay bounded: 64 MiB upload, ≤ 512 entropy buckets, ≤ 200 strings per encoding, ≤ 20000 packets, ≤ 100 embedded-segment hits, ≤ 100 indicators per class.
- Same process, same-origin pipeline; no new runtime dependencies, no CDN assets, no telemetry.
- User explicitly wants "actually useful" analysis for larger files, not a bigger number alone.

## Task 1: Whole-file static analysis at 64 MiB
**Files:** `backend/atlas/analysis.py`; `backend/atlas/security.py` (`MAX_BODY` ≥ `MAX_FILE` + multipart overhead); `tests/test_analysis.py`; `tests/test_api.py`.
**Produces:** `analyze_file(filename, data)` at 64 MiB limit (`MAX_FILE=64<<20`) — whole-file ASCII and UTF-16LE strings (`strings`, `strings_utf16`, capped lists), whole-file `sampled_bytes == len(data)`, no "first 1 MiB" warning across ASCII-only scan, error message "Files must be at most 64 MiB".
- [x] Tests RED→GREEN: 64 MiB+1 raises `ValueError` with "64 MiB"; upload-rejection asserts `/api/analyze` 413 and the body limit allows a 64 MiB multipart file.

## Task 2: Entropy map
**Files:** `backend/atlas/analysis.py`; `tests/test_analysis.py`; `frontend/src/types.ts` + `frontend/src/pages/Lab.tsx` (add `entropyMap` type and a named native figure with CSS bars).
**Produces:** `_entropy_map(data)` → `{ "block": bytes, "count": buckets, "values": [≤512 float entropies], "highRegions": [{start, end, blockCount}] }` — 4 KiB is the minimum block size; larger block spans keep the bucket count bounded; consecutive blocks above 7.5 merge into a high-entropy region span, max 20 spans.
- [x] Tests RED→GREEN: deterministic block count, grouped spans for large files, and region merge.

## Task 3: Embedded segment discovery
**Files:** `backend/atlas/analysis.py`; `tests/test_analysis.py`; `frontend/src/types.ts` + `frontend/src/pages/Lab.tsx` (add `segments` list rendering).
**Produces:** `_segments(data) -> [{"type": str, "offset": int}]` scanning signatures (ZIP, 7z, RAR, GZIP, OLE, PE, ELF, PDF, PS/EPS, SQLite, Mach-O) across the file, resuming each signature's search 512 bytes after a hit to skip closely spaced repetitions, never extracting or opening segments, max 100 findings.
- [x] Tests RED→GREEN: deterministic fixture with unaligned staged byte layouts; same-file offset ordering.

## Task 4: Richer indicators + heuristic coverage
**Files:** `backend/atlas/analysis.py`; `tests/test_analysis.py`; `frontend/src/types.ts` + `frontend/src/pages/Lab.tsx` (extend indicator list).
**Produces:** whole-file indicators now include `ipv6`, `domains` (regex-validated hosts, common TLD whitelist), counts (not full dumps) and detection of longer-than-32-char base64 runs standing in for a threshold warning. Heuristic signal rules apply to the first 16 MiB plus the trailing 1 MiB instead of only the first 1 MiB, with a warning when any range is skipped.
- [x] Tests RED→GREEN: UTF-16LE domain/IP strings surface in indicators; IPv6 and base64 threshold detection.
- [x] Follow-up RED→GREEN: oversized domain tokens are rejected without suffix matches; indicator output retention is bounded; UTF-16 indicators outlive preview caps; multibyte UTF-8 does not expand byte-bounded heuristic windows.
- [x] Dense 64 MiB UTF-16 regression reproduced `MemoryError`, then passed under the same 768 MiB diagnostic address-space cap. Overlapping bounded regex windows merge run spans and preserve tail indicators and either byte alignment.

## Task 5: Frontend surfacing + verification
**Files:** `frontend/src/pages/Lab.tsx`, `frontend/src/types.ts`; `frontend/tests/ui.spec.ts` (fixtures with embedded segments and blocky entropy for interactive flow); README + verification notes; clean-copy gates.
- [x] RED→GREEN: UI shows entropy bars, embedded-segment list, UTF-16 string section, updated cap number.
- [x] Follow-up RED→GREEN: native named figure semantics and all 512 entropy bars fit at desktop/mobile widths.
- [x] Run full backend suite, Ruff, frontend build, and Firefox suite; refresh larger-file, accessibility, native zoom, and private-backup production evidence.
- [x] Finish the combined read-only review and its single inline RED→GREEN fix pass.
- [ ] Record delivery and push the separate upgrades after final checks.

## Execution notes
- The public baseline was published before the initial analyzer commit `3d819fc`. That snapshot passed 50 backend tests, 19 Firefox tests, build, Ruff, and whitespace checks. Keep it separate from the CVE changes.
- Follow-up verification: 23 focused analysis tests, then 74 combined backend tests and 35 Firefox tests passed. Five measured file cases, real 64 MiB Firefox upload, 64 MiB+1 production rejection, 18 axe scans, actual 200% zoom, and two private-backup restarts passed. See `docs/verification.md` for measurements and limits.
- Tests use local controlled byte fixtures and isolated Firefox contexts. No analyzed file is executed, extracted, or sent externally. Original research data stayed logically unchanged at 2,062 records, 2,189 evidence rows, and zero notes.
- Ruling: correct stale plan-only entropy fields/SVG and stride wording to the implemented report contract — actual per-block values and a native named figure meet the agreed goal, while signature searches support unaligned hits — cost: no redundant low/high summary fields or SVG rendering are added.
- Final review: one fresh-context read-only review completed. Oversized IPv6 scopes, missing/invented IPv6 forms, and short UTF-16 indicators were included in the single inline correctness pass. Complete-candidate and both-alignment regressions were observed RED→GREEN; the focused analyzer suite passes 39 tests.
- Final refresh: 104 backend tests passed in 28.83 seconds; 42 isolated Firefox tests, Ruff, and the TypeScript/Vite build passed. Six disposable-subprocess measurements passed, including a 64 MiB invalid-scope token with a valid trailing IPv6 lead. Twenty-four changed-surface axe scans and native 200% Firefox zoom passed.
- Private-backup production refresh: both 64 MiB Firefox uploads passed (11.571/11.346 seconds); the scope response retained only the valid tail and was 3,646 bytes. The API rejected 64 MiB + 1 byte with HTTP 413. Twenty-eight production combinations, two restarts, and a separate 32-view GET/HEAD-only rehearsal passed. Fifty-six health probes had no failures. Original table counts and logical SHA-256 remain unchanged; separate commits/push and original-server handoff remain pending.
- Selective staging proof: a source-only copy of the analyzer-only index passed 72 backend tests, 20 isolated Firefox tests, Ruff, and the TypeScript/Vite build before its commit. Shared CSS/browser files contain only the entropy fixes in this snapshot; CVE adapters/store/search/fixtures match the initial analyzer commit exactly. Existing locked dependencies were reused, and no private data or build output was copied.
