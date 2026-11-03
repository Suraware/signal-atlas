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
- Archive headers are identified but archives are never unpacked. PDF headers are identified but documents are never rendered. PE, ELF, and Mach-O labels identify headers, not validated executable structure.
- Strings, indicators, and the entropy map cover the whole file, bounded to 200 strings per encoding, 100 indicators per family, 512 entropy buckets, and 100 located file signatures. Heuristic rules read the first 16 MiB and the final 1 MiB. Capture parsing is bounded to 20,000 packets, 20,000 PCAPNG blocks, 256 interfaces, and 2,000 tracked directional flows; at most 100 flows are displayed. Unsupported link types, IPv6 extensions, or non-IP protocols may remain undecoded.
- Packet summaries are not deep protocol analysis or full traffic reconstruction. No active packet capture starts. Truncated or malformed captures can produce incomplete summaries with warnings.
- Only explicit exact package coordinates are queried. Dependency ranges, includes, URLs, commands, environment resolution, and installation are not followed. Consent is false by default; enabled OSV queries send only ecosystem, package name, and exact version.
- An empty, failed, partial, or old audit must not be presented as proof of safety. Static heuristics can have false positives and false negatives.

## External requests

Backend requests go only to registered HTTPS endpoints in `backend/atlas/sources.py`. Identifiers are validated and encoded; user URLs cannot choose a destination. Redirects are not followed. Timeouts, payload limits, serialized calls, persistent request budgets, and cache windows bound traffic. Notes and artifacts are never supplied to an external AI, reputation, or vulnerability endpoint. Feed refresh/lookup still reveal the server's public IP and requested public identifiers to those upstream services.

## Local storage

SQLite uses WAL transactions, parameterized queries, and atomic note-revision checks. New data directories are created with mode `0700` and the database with `0600`; existing directory permissions are left as supplied by the user. OS accounts, disk encryption, and backups remain the host owner's responsibility.

Deleted notes remain in SQLite and can be restored. They are omitted from normal library views and exports, not securely erased. JSON/Markdown exports contain potentially sensitive research and references. Share them only intentionally; advisory text and notes may also contain prompt-injection instructions, so treat exported content as untrusted data when giving it to an agent.

The cache preserves older records when upstream requests fail or a record disappears. It is not an immutable evidence archive or a continuously correct inventory. Check source timestamps and vendor guidance before acting on a finding.

## Limitations and disclosure

This release has no independent penetration test, malicious-file sandbox, threat-intelligence completeness guarantee, multi-user authorization, per-client abuse quota, or malware verdict. It is not appropriate for untrusted LAN clients. Automated tests and source review establish only the behaviors they exercise.

For a security report, first arrange a private channel with the project owner. No hosted issue tracker or private security-reporting address is configured yet. Avoid public disclosure of secrets, live targets, or weaponized samples.
