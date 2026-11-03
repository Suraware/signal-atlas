# Public intelligence sources

Signal Atlas uses eight public, unauthenticated APIs/data feeds. This is a bounded initial set, not exhaustive coverage. Endpoint availability, schemas, upstream quotas, and terms can change. No connector sends API keys, authorization headers, private notes, or uploaded artifacts.

## Connector inventory

| Source | Public endpoint | Default refresh coverage | Cache window / local minimum interval |
| --- | --- | --- | --- |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Catalog entries, capped at 5,000; exploitation flag, actions, vendors/products, ransomware field, references | 1 hour / 60 seconds |
| GitHub Advisories | `https://api.github.com/advisories` | Latest 60 reviewed advisories, sorted by publication; CVE/GHSA aliases and package metadata | 1 hour / 60 seconds |
| NIST NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0` | One page of 50 CVEs modified within the last seven days; targeted CVE lookup | 1 hour / 6.5 seconds |
| Exploit-DB metadata | `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | At most 16 MiB / 100,000 CSV rows; selects 200 CVE groups by newest metadata publication date | 24 hours / 300 seconds |
| FIRST EPSS | `https://api.first.org/data/v1/epss` | Up to 100 priority CVEs already cached locally, plus targeted lookups; missing scores remain missing | 24 hours / 3 seconds |
| CVE.org / CVE Program | `https://cveawg.mitre.org/api/cve/{CVE}` | One selected cached CVE per refresh, plus targeted enrichment; CNA/ADP context | 1 hour / 0.5 seconds |
| CIRCL Vulnerability-Lookup | `https://vulnerability.circl.lu/api/cve/{CVE}` | One selected cached CVE per refresh, plus targeted CVE enrichment | 1 hour / 3 seconds |
| OSV.dev | `https://api.osv.dev/v1/vulns/{ID}` and `/querybatch` | One cached GitHub alias per refresh; advisory-ID lookup; consent-based batch queries for at most 100 exact package versions | Advisory: 1 hour; audit: 24 hours / 0.2 seconds |

The NVD page is **not** a complete seven-day feed, and is not sorted by risk or modification time. CVE.org, CIRCL, and OSV refreshes are deliberate small enrichments, not full-database downloads. Repeat global refreshes reuse source-level cache windows. Use targeted identifier lookup to fill a particular record's gaps.

## Requests and failure handling

- Fixed HTTPS endpoints only; user-supplied URLs are never fetched. Redirects are rejected.
- Each request has an 8-second connection timeout, bounded read timeouts, and a 30–35-second outer fetch deadline. Responses are capped at 8 MiB, or 16 MiB for Exploit-DB.
- Feed refreshes, targeted lookups, and OSV batches share a serial request lock. Local minimum request intervals survive restarts in SQLite.
- GitHub's no-key budget is 60 requests/hour/IP; NVD's is 5 requests/30 seconds. Other callers on the same IP may consume the shared upstream quota.
- HTTP 403/429 are reported as source errors and honor numeric `Retry-After` and reported exhaustion/reset information. Immediate individual retries cannot bypass the local budget. Cache windows are application choices, not upstream entitlement to a quota.
- Where an upstream endpoint returns an ETag, subsequent requests to that same URL can revalidate the cache. A failed fetch or invalid schema does not erase existing records.
- Source status describes the last recorded operation, not a continuous live health check. “Cached” does not mean complete, up to date for every CVE, or reachable right now. The displayed batch count is not total database coverage.

## Reading the signals

- **KEV** means the cached CISA observation reports catalogued exploitation, not that a local host was tested.
- **Public PoC metadata** means Exploit-DB metadata references an exploit page. The code is never fetched or run. It does not imply confirmed active exploitation.
- **CVSS/severity** is published impact information. Correlation conservatively chooses the highest cached rating; check individual observations and current vendor guidance.
- **EPSS** is a dated probability model for observed exploitation in the next 30 days, not severity or a promise about a specific environment.
- **Research status** is the local author's assessment. It does not alter public source evidence.

Latest raw observations are retained per record/source, not as an immutable timeline. Withdrawn/rejected records are not ingested on refresh; older cached observations are not automatically purged. Treat the cache as research evidence, not an authoritative current affectedness or remediation verdict.

## Terms and attribution

The MIT license applies to this application's code, not third-party intelligence. Review upstream terms before redistribution or high-volume use; follow the record's references for attribution and current corrections:

- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [GitHub advisory API documentation](https://docs.github.com/en/rest/security-advisories/global-advisories) and [API rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [NVD developer guidance](https://nvd.nist.gov/developers/start-here) and [vulnerability API](https://nvd.nist.gov/developers/vulnerabilities)
- [Exploit-DB upstream repository and license](https://gitlab.com/exploit-database/exploitdb)
- [FIRST EPSS API](https://www.first.org/epss/api)
- [CVE Program terms of use](https://www.cve.org/Legal/TermsOfUse)
- [CIRCL Vulnerability-Lookup documentation](https://vulnerability.circl.lu/documentation)
- [OSV API documentation](https://google.github.io/osv.dev/api/) and [OSV data sources](https://osv.dev/list)

## Verified initial availability

On **2026-11-03**, all eight chosen endpoints returned HTTP 200 without credentials. [Probe output](api-probes.json) records request URLs, response sizes/types, and reported budget headers. A legacy GitHub Exploit-DB mirror returned 404 and is not a configured connector.

The [initial live sync](initial-sync.json), recorded at 13:07 UTC, cached **2,052 correlated vulnerabilities**, including **1,766 KEV records**. The successful batch counts were CISA 1,766; GitHub 60; NVD 50; Exploit-DB 200; EPSS 99; CVE.org 1; CIRCL 1; OSV 1. Counts overlap through correlation and are observations from that run, not a current global inventory.

Test fixtures—including the xz KEV flag and the fixture OSV response—are controlled test data and must not be read as live intelligence.
