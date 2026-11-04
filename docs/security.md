# Security boundaries

## Intended use

Signal Atlas is a local research tool. Default listening is IPv4 loopback on port 8731. `--lan` explicitly binds all IPv4 interfaces on the existing host; it does not configure the network. Only use it on a trusted network with trusted users.

There are **no application accounts, authorization roles, or built-in TLS**. Anyone who can reach the server can read and mutate its workspace, trigger bounded external requests, and export its content. Host validation and browser origin protection are not authentication. Do not expose the port to the internet or forward it from a router. A remote-access deployment would require separately designed authentication, TLS, reverse-proxy trust, and access controls; that is outside this release.

## Untrusted browser content

- React displays notes, source descriptions, original JSON, and extracted strings as text. There is no HTML/Markdown rendering or `dangerouslySetInnerHTML`.
- References must be HTTP(S) URLs without embedded credentials. External links open separately with `noopener noreferrer`; invalid links are not clickable. URL citations are never fetched automatically.
- Responses carry a same-origin Content Security Policy, `nosniff`, frame denial, and a no-referrer policy. Script assets, fonts, images, and API requests stay on the local origin. Inline styles are allowed for layout; inline scripts are not.
- The API rejects unrecognized Host values, foreign `Origin` values, and cross-site Fetch Metadata requests. No permissive CORS headers are enabled. Accepted hosts are loopback, the local hostname, and private IPv4 addresses detected at startup.
- Explicit saves use the latest revision number. Stale updates return HTTP 409 and preserve both the stored note and the editor's draft. Internal navigation and replacing a draft require confirmation; browser unload protection is best-effort. Browser/OS crashes can still lose unsaved content.

## Uploaded files and manifests

- No `eval`, shell command, subprocess execution, module import, dynamic loader, exploit invocation, or document renderer receives uploaded bytes or manifest content.
- Request bodies are capped at 66 MiB, including multipart overhead, with a 30-second upload deadline. Individual artifacts are capped at 64 MiB and inspection runs in a worker thread.
- Artifact content is not saved to the application's data directory or sent to remote services. The multipart library can spool larger uploads to a temporary local file; the upload is closed after each request. Do not treat this as forensic secure erasure or protection from host swap, backups, or OS crash recovery.
- Archive headers are identified but archives are never unpacked. PDF headers are identified but documents are never rendered. PE32/PE32+ and ELF32/ELF64 receive bounded selected-structure parsing; Mach-O remains a header label. No parser result proves loader acceptance or safety.
- Executable parsing uses Python's standard library, without an external parser, subprocess, dynamic loader, extraction, or decompression. It reads at most 256 sections, 128 program headers/PE import descriptors/library records, 20,000 symbol/thunk records, and 4,096 ELF dynamic records. Output retains at most 512 symbols, 50 observations, and 64 warnings. Names must terminate within 512 file-backed bytes. Section entropy has a cumulative 64 MiB read budget, with identical spans reused.
- Incomplete or overlapping address tables cannot establish arbitrary unique file mappings. ELF dependency libraries are separate from undefined symbol providers; unsupported sectionless symbol recovery and PE delay imports remain explicit. Offsets and wide declared values are exact strings; names are escaped as literal text. Partial reports and empty tables are not proof of safety. See [executable capabilities and omissions](../README.md#inspect-a-pe-or-elf-file).
- Strings, indicators, and the entropy map cover the whole file, bounded to 200 strings per encoding, 100 indicators per family, 512 entropy buckets, and 100 located file signatures. Heuristic rules read the first 16 MiB and the final 1 MiB. Capture parsing is bounded to 20,000 packets, 20,000 PCAPNG blocks, 256 interfaces, and 2,000 tracked directional flows; at most 100 flows are displayed. Unsupported link types, IPv6 extensions, or non-IP protocols may remain undecoded.
- IPv6 candidates are validated whole and limited to 110 characters, including at most 64 scope characters. Oversized scopes are rejected, never truncated into valid-looking leads. UTF-16 printable-run matching uses overlapping 64 KiB windows to avoid retaining whole-run regex state. These output and scan limits do not guarantee processing time or peak memory for arbitrary files or concurrent uploads.
- Packet summaries are not deep protocol analysis or full traffic reconstruction. No active packet capture starts. Truncated or malformed captures can produce incomplete summaries with warnings.
- Only explicit exact package coordinates are queried. Dependency ranges, includes, URLs, commands, environment resolution, and installation are not followed. Consent is false by default; enabled OSV queries send only ecosystem, package name, and exact version.
- An empty, failed, partial, or old audit must not be presented as proof of safety. Static heuristics can have false positives and false negatives.

## External requests

Backend requests go only to registered HTTPS endpoints in `backend/atlas/sources.py`. Identifiers are validated and encoded; user URLs cannot choose a destination. Redirects are not followed. Timeouts, payload limits, serialized calls, persistent request budgets, and cache windows bound traffic. Notes and artifacts are never supplied to an external AI, reputation, or vulnerability endpoint. Feed refresh/lookup still reveal the server's public IP and requested public identifiers to those upstream services.

Global search makes no public request while typing. Submitting a complete CVE checks the local cache first; only HTTP 404 permits the existing public lookup. Partial identifiers and product/package searches remain local. Connection failures, other cache errors, and malformed successful cache responses are not permission to query upstream services.

HTTP 404 from a targeted CVE.org or CIRCL record endpoint means the record was not found. Feed/list-endpoint 404s still report source failures. Neither path bypasses the persistent request budget or erases existing cached evidence.

## Local storage

SQLite uses WAL transactions, parameterized queries, and atomic note-revision checks. New data directories are created with mode `0700` and the database with `0600`; existing directory permissions are left as supplied by the user. OS accounts, disk encryption, and backups remain the host owner's responsibility.

Deleted notes remain in SQLite and can be restored. They are omitted from normal library views and exports, not securely erased. JSON/Markdown exports contain potentially sensitive research and references. Share them only intentionally; advisory text and notes may also contain prompt-injection instructions, so treat exported content as untrusted data when giving it to an agent.

The cache preserves older records when upstream requests fail or a record disappears. It is not an immutable evidence archive or a continuously correct inventory. Check source timestamps and vendor guidance before acting on a finding.

## Limitations and disclosure

This release has no independent penetration test, malicious-file sandbox, threat-intelligence completeness guarantee, multi-user authorization, per-client abuse quota, or malware verdict. It is not appropriate for untrusted LAN clients. Automated tests and source review establish only the behaviors they exercise.

For a security report, first arrange a private channel with the project owner. No private security-reporting address is configured yet. Use the [public issue tracker](https://github.com/Suraware/signal-atlas/issues) only for nonsensitive bug reports. Do not disclose secrets, live targets, or weaponized samples there.
