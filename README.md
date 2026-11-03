# Signal Atlas

A local-first workspace for security research. Public vulnerability intelligence, source-linked notes, dependency checks, and evidence relationships live in one SQLite database on your machine.

**No accounts, API keys, cloud AI, telemetry, or browser CDN assets.** This is an early, repository-run release for a single researcher or a trusted LAN, not an internet-facing collaboration service.

## What it does

- Search and filter correlated CVE/GHSA/OSV records; inspect raw source evidence, dates, references, and a local watchlist.
- Submit a complete CVE to open its cached record or retrieve it from public sources when it is missing. Read complete source headings, including proven legacy text recovered offline.
- Refresh eight public, unauthenticated sources: CISA KEV, GitHub Advisories, NVD, Exploit-DB metadata, FIRST EPSS, CVE.org, CIRCL, and OSV.
- Write or import plain Markdown notes; tag them, cite URLs, and link CVE mentions. Save with revision-conflict protection, or delete and restore a note.
- Browse documented relationships as a diagram and an accessible table.
- Audit up to 100 exact package versions from npm files, Python requirements, or a CycloneDX JSON SBOM. Remote OSV queries require explicit consent; previous queries can be read offline.
- Inspect files up to 64 MiB: headers, hashes, whole-file entropy map, printable ASCII and UTF-16 strings, embedded file-signature discovery, network indicators, heuristic source-code leads, and bounded PCAP/PCAPNG summaries. **Nothing is executed.**
- Export source-linked intelligence and notes as JSON or Markdown for offline review or an agent's context.

Eight sources are an initial integration set, **not all free APIs**. Each has a bounded ingestion strategy. A missing CVSS score remains unknown; KEV evidence, public PoC metadata, EPSS probability, and a researcher's assessment are separate signals. None establishes that your system is affected.

### Find an existing CVE

Enter a complete identifier, such as `CVE-2014-0160`, in **Search intelligence** and submit. A valid cached record opens without public requests. Only a local HTTP 404 permits the existing bounded public lookup, which saves any returned evidence locally. Source failures are reported. Failed reads and malformed successful cache responses never start a public request.

Typing, partial identifiers, and product/package searches stay local. Complete headings are preserved up to 50,000 characters. Older clipped headings are extended only when matching saved source evidence agrees on the missing text. Ambiguous headings stay unchanged; reading them does not rewrite the database.

## Quick start

Prerequisites: Linux/macOS with Bash, Python 3.11+, [uv](https://docs.astral.sh/uv/getting-started/installation/), and Node.js 22.12+ with npm. Dependency installation needs internet access; browsing cached records does not.

Clone the [public repository](https://github.com/Suraware/signal-atlas), then install from its folder:

```bash
git clone https://github.com/Suraware/signal-atlas.git
cd signal-atlas
uv sync --frozen --extra dev
npm --prefix frontend ci
npm --prefix frontend run build
./start.sh
```

Open **http://127.0.0.1:8731**. The launcher also works when called by its full path from another directory. Stop it with **Ctrl+C**.

Python dependencies are locked in `uv.lock`; frontend dependencies are locked in `frontend/package-lock.json`. The launcher does not install packages, alter network settings, or refresh feeds implicitly. A new workspace starts empty: select **Refresh sources** to fetch its first bounded batch. Existing cached data is retained across restarts.

### LAN access

```bash
./start.sh --lan
```

This explicitly binds to `0.0.0.0:8731` and prints the host's detected private IPv4 address, for example `http://192.168.0.7:8731`. Open that URL from a device on the same trusted network. It does **not** create a Wi-Fi network or change the router or firewall. Other-device reachability depends on the network's existing rules.

**Anyone who can reach this listener can read, edit, delete, restore, and export the workspace. There is no authentication or built-in TLS.** Do not use public Wi-Fi, forward this port, expose it to the internet, or store secrets in a shared workspace. Host/origin checks reduce browser attacks; they are not user access control. See [security boundaries](docs/security.md).

Optional settings:

```bash
./start.sh --lan --port 8731 --refresh-minutes 60
./start.sh --data-dir /absolute/path/to/private-research
./start.sh --help
```

`--refresh-minutes` opts into public requests on startup and thereafter; `0` (the default) disables them. Nonzero intervals must be at least 15 minutes. Source-specific cache windows and request budgets still apply. Use **Refresh evidence** or **Look up identifier** for targeted enrichment rather than assuming that a feed refresh fetched every CVE.

## Research and analysis boundaries

- Notes are displayed as text, not rendered HTML. Source URLs are citations only and are never fetched automatically. Save explicitly; unsaved drafts are not recovered after a crash.
- Each vulnerability retains the **latest cached observation per source**, not an immutable history. Conservative merged signals can retain older information: inspect individual observations and consult current vendor guidance.
- Note revisions prevent stale updates but are not a version-history browser. Deletion is reversible, not secure erasure. After the undo notification is dismissed, a known note ID can still be restored through the local API.
- npm ranges, unpinned requirements, includes, URLs, and install commands are skipped, never resolved or executed. Python environment markers are not evaluated. CycloneDX supports npm, PyPI, Maven, crates.io, Go, NuGet, and RubyGems package URLs with exact versions; this is not a general-purpose dependency resolver.
- OSV receives only package names, ecosystems, and exact versions when consent is enabled. Cached results show their original check date. No matches means “no matches returned,” not “safe.”
- Uploaded artifacts never go to an external service and are not retained after the request. The multipart library may spool larger uploads to a temporary local file before closing it. This is static, best-effort inspection—not antivirus, a sandbox, decompilation, exploit validation, or a full code audit.
- Strings, indicators, and the entropy map scan the whole file. Results retain up to 200 strings per encoding (240-character previews), 100 indicators per family, 512 entropy buckets, and 20 high-entropy regions. Heuristic rules read the first 16 MiB and the final 1 MiB, and a warning names any skipped middle range.
- IPv6 leads are validated as complete candidates, not fragments of malformed addresses. Scope identifiers are limited to 64 characters. UTF-16 indicator scans include short runs independently of the six-character string-preview minimum.
- Captures are limited to 20,000 packets and 100 displayed directional conversations. At most 100 embedded file signatures are shown; closely spaced repetitions of the same signature are skipped. Signatures are never extracted or opened. No live capture, stream reassembly, packet payload interpretation, or decryption is performed.
- Larger inspections take seconds and use additional memory. The 64 MiB file limit is not a processing-time or memory guarantee, especially with concurrent uploads. See the [measured larger-file checks](docs/verification.md#larger-file-measurements).
- JSON exports include original source evidence; Markdown is a readable summary. Whole-workspace exports contain at most 10,000 vulnerabilities and all active notes. Exports do not include the OSV query cache or deleted notes and are not full database backups.

## Local data and backups

By default `data/atlas.sqlite3` holds intelligence, notes, watchlist state, source status, and audit caches. The launcher anchors `data/` to the project folder; `--data-dir` selects a different directory. Local data, virtual environments, builds, and test output are ignored by Git.

For a complete backup, stop the server, then copy the entire data directory to a private location. Restore with the server stopped, or start against the backed-up directory with `--data-dir`. Do not copy only a live SQLite file: WAL sidecars can contain recent writes. A new directory is created with mode `0700`, and the database with `0600`; existing directory permissions are not changed.

## Development and tests

The production Python process serves both `frontend/dist/` and `/api`. Rebuild the frontend and restart the server after interface changes.

```bash
uv sync --frozen --extra dev
.venv/bin/python -m pytest -q
.venv/bin/ruff check backend tests scripts
npm --prefix frontend run build
npm --prefix frontend exec -- playwright install firefox
npm --prefix frontend test
```

Firefox tests use fresh browser contexts and a real, isolated SQLite/API server on port `8732`. External HTTP is replaced with controlled fixtures; the suite does not contact public intelligence services or touch `data/`. Screenshots and traces are saved to `test-results/` on failure. Build before testing because these checks exercise production assets.

For hot reload, run the backend on its default loopback port in one terminal and `npm --prefix frontend run dev` in another. The Vite proxy forwards local API requests; use the production launcher for LAN verification. The API schema is available at `/api/openapi.json` without remote Swagger assets.

See [source inventory and limits](docs/sources.md), [security boundaries](docs/security.md), [contribution guide](CONTRIBUTING.md), and [verification evidence](docs/verification.md).

## License

Signal Atlas code is [MIT licensed](LICENSE). Third-party advisories, references, and data retain their upstream licenses and terms. This repository does not redistribute the private SQLite cache or claim ownership of feed content.
