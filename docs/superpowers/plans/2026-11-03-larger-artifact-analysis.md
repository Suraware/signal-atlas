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
- [ ] Tests RED: 64 MiB+1 raises `ValueError` with "64 MiB"; upload-rejection asserts `/api/analyze` 413 and body limit allows a 64 MiB file when `MAX_BODY` grows.

## Task 2: Entropy map
**Files:** `backend/atlas/analysis.py`; `tests/test_analysis.py`; `frontend/src/types.ts` + `frontend/src/pages/Lab.tsx` (add `entropyMap` type and accessible SVG bars with ARIA).
**Produces:** `_entropy_map(data)` → `{ "block": bytes, "count": buckets, "values": [≤512 float entropies], "low": span, "high": span, "highRegions": [{start, end, blockCount}] }` — 4 KiB is the minimum block size; fewer buckets for larger files; ≥7.5 averaged consecutive blocks merge into a high-entropy region span, max 20 spans.
- [ ] Tests RED: deterministic block count, block-size reduction for large files, region merge.

## Task 3: Embedded segment discovery
**Files:** `backend/atlas/analysis.py`; `tests/test_analysis.py`; `frontend/src/types.ts` + `frontend/src/pages/Lab.tsx` (add `segments` list rendering).
**Produces:** `_segments(data) -> [{"type": str, "offset": int}]` scanning signatures (ZIP, 7z, RAR, GZIP, OLE, PE, ELF, PDF, PS/EPS, SQLite, Mach-O) at every 512-byte stride for the whole file, deduplicating hits within the same stride, never extracting or opening segments, max 100 findings.
- [ ] Tests RED: deterministic fixture with staged byte layouts; same-file offset ordering.

## Task 4: Richer indicators + heuristic coverage
**Files:** `backend/atlas/analysis.py`; `tests/test_analysis.py`; `frontend/src/types.ts` + `frontend/src/pages/Lab.tsx` (extend indicator list).
**Produces:** whole-file indicators now include `ipv6`, `domains` (regex-validated hosts, common TLD whitelist), counts (not full dumps) and detection of longer-than-32-char base64 runs standing in for a threshold warning. Heuristic signal rules apply to the first 16 MiB plus the trailing 1 MiB instead of only the first 1 MiB, with a warning when any range is skipped.
- [ ] Tests RED: UTF-16LE domain/IP strings surface in indicators; IPv6 and base64 threshold detection.

## Task 5: Frontend surfacing + verification
**Files:** `frontend/src/pages/Lab.tsx`, `frontend/src/types.ts`; `frontend/tests/ui.spec.ts` (fixtures with embedded segments and blocky entropy for interactive flow); README + verification notes; clean-copy gates.
- [ ] RED: following the graph's pattern — UI shows entropy bars, embedded-segment list, UTF-16 string section, updated cap number.
- [ ] Run full backend suite, Ruff, frontend build; run Firefox suite; regenerate screenshots and verification notes.

## Execution notes
- The user already chose inline execution; do not pause between tasks. Gate: 43→N backend tests, 18→19 browser tests.
- Desktop tests remain on Firefox using isolated contexts; no external network calls — attackers' entropy fixture uses deterministic bytes (`b"\x00" * 16` vs `b"high entropy..."` matched patterns only, not real random).
