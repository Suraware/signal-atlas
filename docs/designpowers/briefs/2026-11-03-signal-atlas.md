# Design brief: Signal Atlas

## Problem
Security researchers have advisories, exploit signals, technical documentation, and notes scattered across databases. They need a searchable local workspace that preserves source links and works without a cloud account.

## Users
- Researchers triaging vulnerabilities who need to distinguish published severity, known exploitation, and probabilistic risk.
- Maintainers checking exact dependency versions without uploading their repositories.
- Researchers collecting documents and observations, including keyboard, screen-reader, low-vision, and mobile/LAN users.

## Direction
An evidence-led research workbench: a quiet light canvas, dark blue navigation, strong table hierarchy, concise text, and an explicit provenance trail. The graph is an alternate way to inspect real relationships, never a substitute for readable lists.

Alternatives considered: a terminal-only tool (cheap but poor discovery), a graph-first canvas (expressive but cognitively expensive), and an evidence-first web workbench (chosen for search, triage, and LAN usability).

## Constraints
- User requested a build in this session at `/home/seer/Documents/Opensource`.
- Use only free, unauthenticated intelligence APIs or public data feeds. No remote AI dependency, telemetry, or CDN assets.
- SQLite and Markdown exports remain local. Sync is bounded, explicit, and resilient to unavailable sources.
- LAN mode binds to the existing LAN; no router, firewall, or public deployment changes.
- Never execute suspicious files, fetch user-supplied URLs, run exploits, or submit uploaded files to third parties.
- Aim for visible labels, 44px targets, semantic headings, keyboard access, and AA text contrast. Test actual behavior rather than asserting compliance.

## Success
Sync real public data; search it; inspect evidence for a CVE; create and retrieve a linked note offline; navigate actual relationships; audit exact package versions; inspect a binary and a PCAP without execution; export the local research context; serve on the host's LAN address.

## Scope
First version supports CISA KEV, FIRST EPSS, CVE.org, NVD, OSV, GitHub advisories, CIRCL, and Exploit-DB metadata where reachable without authentication. Feed status must report errors and rate limits truthfully.

Not in this release: internet-scale crawling, cloud synchronization, arbitrary document URL fetching, autonomous exploitation, sandbox detonation, packet capture, collaboration accounts, or an AI model. A source-linked context export gives agents reliable input without needing any cloud service.

## Approval and assumptions
The user requested planning followed by building directly in this session. No style reference was supplied. Technical defaults and the workbench direction are implementation assumptions, not recorded personal preferences.
