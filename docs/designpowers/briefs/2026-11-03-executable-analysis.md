# Design brief: executable-aware inspection

## Problem statement
Signal Atlas recognizes PE and ELF headers but does not explain their structure. A researcher cannot distinguish a real import from an unrelated printable string or connect an entry point to file bytes.

## Users
Researchers inspecting unfamiliar Windows EXE/DLL and Linux ELF files locally. Reports must remain usable under cognitive load, with a keyboard, at narrow widths, and at 200% text/browser zoom. No color-only findings or executable source markup.

## Approved direction
The user selected **Executables (Recommended)**: parse sections, imports, entry points, and structural anomalies with precise offsets. Continue implementation inline.

## Scope
- PE32 and PE32+: machine/bitness, image kind, entry-point RVA/address and unambiguous file mapping, section ranges/flags/entropy, normal import descriptors and named/ordinal imports.
- ELF32 and ELF64, either byte order: machine/type, entry-point address and PT_LOAD file mapping, section ranges/flags/entropy, load segments, DT_NEEDED libraries, and undefined global/weak symbols from dynamic symbol tables (or the regular symbol table for relocatable objects).
- ELF extended table numbering is read safely. An ELF without section headers can still show load segments and dynamic dependencies; unavailable section-based symbols are explicitly described.
- Separate parsed/partial/invalid structure states. Preserve useful decoded fields when a later table is malformed. All names are untrusted text, not links or HTML.
- File offsets/addresses use exact hexadecimal strings; declared sizes/counts use decimal strings so malformed 64-bit values cannot lose precision in JavaScript.
- ELF dependency names are not guessed as the owners of individual symbols. Flags describe declarations, not runtime permissions or a malware verdict.

## Constraints
- Existing 64 MiB upload cap; no increase.
- No execution, extraction, decompression, external upload, automatic intelligence lookup, parser subprocess, or new runtime dependency.
- At most 256 section headers, 128 program headers, 128 import libraries, and 512 retained imported symbols.
- At most 20,000 symbol/thunk records and 4,096 dynamic records inspected per file; PE import-descriptor inspection is separately bounded to 128 descriptors.
- Names must terminate within their declared file-backed table/range and within 512 bytes. Reject oversized/unterminated names rather than inventing a truncated import.
- Per-section entropy reads have a cumulative 64 MiB budget with repeated identical spans reused. Overlapping declarations cannot multiply work indefinitely.
- Retain at most 50 structural findings and 64 warnings; explain reached limits. Resource budgets bound configured work, not total wall time/RSS with concurrent requests.

## Existing design system
`DESIGN.md` and `frontend/src/styles.css`; preserve current tokens and report patterns. Put executable structure before strings/heuristic leads. Use named semantic tables and native disclosures for long imported-symbol lists.

## Success criteria
- Synthetic, hand-checked PE/ELF fixtures prove named/ordinal imports, both ELF byte orders, exact entry/section offsets, and rejection of unrelated bait strings.
- Out-of-file, overlapping, zero-filled, invalid-index, oversized-count, truncated, and unterminated-table inputs return bounded partial reports, not HTTP 500s or invented evidence.
- Real benign compiler outputs agree with independent `readelf`/`objdump` metadata; uploaded artifacts are never executed by the application.
- The actual API and isolated Firefox UI render valid, partial, and invalid reports; keyboard disclosures, no page overflow, long literal names, and no remote requests are verified.
- All backend/Firefox regressions, Ruff, the TypeScript/Vite build, and whitespace checks pass. Changed-surface accessibility and actual browser zoom are measured, not asserted.

## Out of scope
Disassembly/decompilation, instruction/data-flow analysis, Mach-O/COFF objects, PE exports/resources/delay imports or signature validation, ELF symbol-version/provider resolution, sectionless dynamic-symbol recovery, reputation lookup, malware scoring, CVE changes, graph redesign, database/schema changes, and service/network configuration.
