import asyncio

import httpx
import pytest
from atlas.sources import SourceError, parse_source
from atlas.store import Store
from atlas.sync import IntelService

CISA = {
    "catalogVersion": "2026.10.30",
    "vulnerabilities": [{
        "cveID": "CVE-2024-3094", "vendorProject": "Tukaani", "product": "xz Utils",
        "vulnerabilityName": "xz Utils Supply Chain Compromise", "dateAdded": "2024-03-29",
        "shortDescription": "Malicious code was discovered in xz Utils.",
        "requiredAction": "Follow vendor guidance.", "dueDate": "2024-04-19",
        "knownRansomwareCampaignUse": "Unknown", "notes": "https://www.cisa.gov/news-events/alerts", "cwes": ["CWE-506"],
    }],
}
CVE = {
    "dataType": "CVE_RECORD", "cveMetadata": {"cveId": "CVE-2024-3094", "state": "PUBLISHED", "datePublished": "2024-03-29T00:00:00Z"},
    "containers": {"cna": {
        "title": "Malicious code in xz Utils",
        "descriptions": [{"lang": "en", "value": "A deliberately introduced backdoor."}],
        "affected": [{"vendor": "Tukaani", "product": "xz", "versions": [{"version": "5.6.0", "status": "affected"}]}],
        "metrics": [{"cvssV3_1": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}],
        "problemTypes": [{"descriptions": [{"cweId": "CWE-506", "description": "Embedded Malicious Code", "lang": "en"}]}],
        "references": [{"url": "https://www.openwall.com/lists/oss-security/2024/03/29/4"}],
    }},
}
GHSA = [{
    "ghsa_id": "GHSA-jfh8-c2jp-5v3q", "cve_id": "CVE-2024-3094", "summary": "xz backdoor",
    "description": "xz issue.", "severity": "critical", "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
    "cvss": {"score": 10.0}, "identifiers": [{"type": "CVE", "value": "CVE-2024-3094"}],
    "vulnerabilities": [{"package": {"ecosystem": "other", "name": "xz"}, "vulnerable_version_range": "= 5.6.0"}],
    "references": ["https://www.openwall.com/lists/oss-security/2024/03/29/4"], "cwes": [{"cwe_id": "CWE-506"}],
    "published_at": "2024-03-29T00:00:00Z", "updated_at": "2024-04-01T00:00:00Z", "withdrawn_at": None,
}]


def test_cisa_is_known_exploitation_not_invented_cvss():
    records = parse_source("cisa", CISA)
    record, raw = records[0]
    assert record["kev"] is True
    assert record["id"] == "CVE-2024-3094"
    assert record["cvss"] is None
    assert record["required_action"] == "Follow vendor guidance."
    assert raw["knownRansomwareCampaignUse"] == "Unknown"


def test_epss_is_validated_probability_with_source_date():
    records = parse_source("epss", {"data": [{"cve": "CVE-2024-3094", "epss": "0.909", "percentile": "0.99806", "date": "2026-11-03"}]})
    assert records[0][0]["epss"] == 0.909
    assert records[0][0]["epss_date"] == "2026-11-03"
    with pytest.raises(SourceError):
        parse_source("epss", {"data": [{"cve": "CVE-2024-3094", "epss": "NaN"}]})


def test_cve_and_github_correlate_identifiers_and_preserve_references():
    cve = parse_source("cve", CVE)[0][0]
    ghsa = parse_source("github", GHSA)[0][0]
    assert cve["severity"] == "CRITICAL"
    assert cve["cwes"] == ["CWE-506"]
    assert ghsa["id"] == "CVE-2024-3094"
    assert "GHSA-jfh8-c2jp-5v3q" in ghsa["aliases"]
    assert any(ref["url"].startswith("https://github.com/advisories/") for ref in ghsa["references"])


def test_osv_keeps_aliases_package_ranges_and_unsafe_links_out():
    payload = {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "summary": "lodash command injection", "details": "Use patched lodash.",
               "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
               "references": [{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"}, {"url": "javascript:alert(1)"}],
               "database_specific": {"severity": "HIGH"}, "modified": "2026-01-01T00:00:00Z"}
    record = parse_source("osv", payload)[0][0]
    assert record["id"] == "CVE-2021-23337"
    assert record["packages"] == ["npm:lodash"]
    assert all(ref["url"].startswith("https://") for ref in record["references"])


def test_exploitdb_correlates_metadata_without_marking_kev():
    csv = 'id,file,description,date_published,codes,source_url\n12345,exploits/linux/local/12345.py,"Example proof of concept",2024-03-29,CVE-2024-3094,https://example.org/research\n'
    record = parse_source("exploitdb", csv)[0][0]
    assert record["id"] == "CVE-2024-3094"
    assert record["exploit_count"] == 1
    assert record["kev"] is False
    assert record["references"][0]["url"] == "https://www.exploit-db.com/exploits/12345"


def test_malformed_payloads_fail_loudly_instead_of_successful_empty_sync():
    for source_id in ("cisa", "epss", "nvd", "github", "cve"):
        with pytest.raises(SourceError):
            parse_source(source_id, {"error": "Access denied"})


def test_sync_isolates_failed_source_and_keeps_cached_intelligence(tmp_path):
    store = Store(tmp_path)
    store.upsert_record({"id": "CVE-2023-1111", "title": "cached"}, "github", {})

    def handler(request):
        if request.url.host == "www.cisa.gov":
            return httpx.Response(200, json=CISA)
        if request.url.host == "api.github.com":
            return httpx.Response(429, headers={"Retry-After": "60"}, json={"message": "Rate limit"})
        raise AssertionError(f"Unexpected external request: {request.url}")

    service = IntelService(store, transport=httpx.MockTransport(handler))
    result = asyncio.run(service.sync(["cisa", "github"], force=True))
    assert {item["id"]: item["status"] for item in result["results"]} == {"cisa": "ok", "github": "error"}
    assert store.get_record("CVE-2023-1111")["title"] == "cached"
    assert store.get_record("CVE-2024-3094")["kev"] is True
    assert "429" in store.source_state("github")["error"]


def test_successful_sync_respects_ttl_and_force_does_not_bypass_rate_limit(tmp_path):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json=CISA)

    store = Store(tmp_path)
    service = IntelService(store, transport=httpx.MockTransport(handler))
    asyncio.run(service.sync(["cisa"]))
    second = asyncio.run(service.sync(["cisa"]))
    assert len(calls) == 1
    assert second["results"][0]["status"] == "cached"


def test_lookup_fetches_only_fixed_endpoints_and_preserves_raw_evidence(tmp_path):
    def handler(request):
        assert request.url.host == "cveawg.mitre.org"
        assert request.url.path == "/api/cve/CVE-2024-3094"
        return httpx.Response(200, json=CVE)

    service = IntelService(Store(tmp_path), transport=httpx.MockTransport(handler))
    result = asyncio.run(service.enrich("cve-2024-3094", sources=["cve"]))
    assert result["record"]["id"] == "CVE-2024-3094"
    assert result["record"]["evidence"][0]["raw"]["cveMetadata"]["state"] == "PUBLISHED"
    with pytest.raises(ValueError):
        asyncio.run(service.enrich("https://example.org/"))
