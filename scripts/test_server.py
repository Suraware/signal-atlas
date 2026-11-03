"""Isolated integration server: real SQLite/API, fixed external HTTP fixtures."""

import sys
import tempfile
from pathlib import Path

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from atlas.app import create_app  # noqa: E402

OLDER_ID = "CVE-2014-0160"
OLDER_DESCRIPTION = (
    "OpenSSL Heartbleed allows a remote peer to read memory through a malformed TLS heartbeat request. "
    "This fixed integration record demonstrates that a published older CVE can be retrieved even when it is absent from the local cache."
)
LEGACY_ID = "CVE-2025-10001"
MISSING_ID = "CVE-1999-99999"
LEGACY_HEADING = (
    "A configuration broker trusts client-supplied settings and allows privilege escalation. "
    "The complete source observation must remain readable in the list and the detail heading, including its final sentence. "
    "Researchers must distinguish this source-specific heading from a different merged catalog description. "
    "Untrusted markup is text, not an instruction: <script>window.UNTRUSTED_HEADING_EXECUTED = true</script>. "
    + "X" * 220 + " Full source heading ends here."
)


def cve_fixture(identifier, description, published):
    return {
        "cveMetadata": {"cveId": identifier, "state": "PUBLISHED", "datePublished": published},
        "containers": {"cna": {
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": [{"cvssV3_1": {"baseScore": 7.5}}],
        }},
    }


# Exact endpoints only. These responses are fixtures, not live source evidence.
PUBLIC_FIXTURES = {}
for identifier, description, published in [
    (OLDER_ID, OLDER_DESCRIPTION, "2014-04-07T00:00:00Z"),
    ("CVE-2024-3094", "XZ Utils supply-chain compromise", "2024-03-29T00:00:00Z"),
]:
    for endpoint in ["https://cveawg.mitre.org/api/cve/", "https://vulnerability.circl.lu/api/cve/"]:
        PUBLIC_FIXTURES[endpoint + identifier] = cve_fixture(identifier, description, published)
    PUBLIC_FIXTURES["https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + identifier] = {
        "vulnerabilities": [{"cve": {
            "id": identifier, "published": published,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
        }}],
    }
    PUBLIC_FIXTURES["https://api.first.org/data/v1/epss?cve=" + identifier] = {
        "data": [{"cve": identifier, "epss": "0.1", "percentile": "0.9", "date": "2026-11-03"}],
    }
    PUBLIC_FIXTURES["https://api.github.com/advisories?cve_id=" + identifier + "&per_page=10"] = []

MISSING_RECORD_ENDPOINTS = {
    "https://cveawg.mitre.org/api/cve/" + MISSING_ID,
    "https://vulnerability.circl.lu/api/cve/" + MISSING_ID,
}
PUBLIC_FIXTURES["https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + MISSING_ID] = {"vulnerabilities": []}
PUBLIC_FIXTURES["https://api.first.org/data/v1/epss?cve=" + MISSING_ID] = {"data": []}
PUBLIC_FIXTURES["https://api.github.com/advisories?cve_id=" + MISSING_ID + "&per_page=10"] = []


def external_fixture(request):
    if request.method == "POST" and str(request.url) == "https://api.osv.dev/v1/querybatch":
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm", "modified": "2026-01-01T00:00:00Z"}]}]})
    if request.method == "GET" and str(request.url) in MISSING_RECORD_ENDPOINTS:
        return httpx.Response(404, json={"error": "Controlled missing public record"})
    if request.method == "GET" and str(request.url) in PUBLIC_FIXTURES:
        return httpx.Response(200, json=PUBLIC_FIXTURES[str(request.url)])
    raise AssertionError(f"UI tests must not perform live external requests: {request.url}")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="signal-atlas-test-", dir="/tmp/opencode") as directory:
        app = create_app(directory, transport=httpx.MockTransport(external_fixture), frontend_dir=ROOT / "frontend" / "dist")
        app.state.store.upsert_record({
            "id": "CVE-2024-3094", "title": "XZ Utils supply-chain compromise", "description": "Controlled integration fixture for an xz supply-chain investigation.",
            "severity": "CRITICAL", "cvss": 10, "epss": 0.909, "epss_date": "2026-11-03", "kev": True,
            "vendors": ["Tukaani"], "products": ["xz Utils"], "cwes": ["CWE-506"],
            "references": [{"url": "https://www.cve.org/CVERecord?id=CVE-2024-3094", "label": "CVE.org primary record"}],
        }, "cve", {"fixture": True, "cveId": "CVE-2024-3094"})
        app.state.store.upsert_record({
            "id": LEGACY_ID, "title": LEGACY_HEADING[:180], "description": LEGACY_HEADING,
        }, "cve", cve_fixture(LEGACY_ID, LEGACY_HEADING, "2025-01-01T00:00:00Z"))
        app.state.store.upsert_record({
            "id": LEGACY_ID, "title": "Different catalog heading", "description": "A different catalog description. " * 32,
        }, "cisa", {"fixture": True, "vulnerabilityName": "Different catalog heading"})
        uvicorn.run(app, host="127.0.0.1", port=8732, log_level="warning")
