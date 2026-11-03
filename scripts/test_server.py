"""Isolated integration server: real SQLite/API, fixed external HTTP fixtures."""

import sys
import tempfile
from pathlib import Path

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from atlas.app import create_app  # noqa: E402


def external_fixture(request):
    if str(request.url) == "https://api.osv.dev/v1/querybatch":
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm", "modified": "2026-01-01T00:00:00Z"}]}]})
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
        uvicorn.run(app, host="127.0.0.1", port=8732, log_level="warning")
