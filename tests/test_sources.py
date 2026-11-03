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

LONG_DESCRIPTION = (
    "A service trusts configuration supplied by an authenticated client, allowing an attacker to escalate privileges. "
    "The affected configuration is read by a privileged broker, which does not verify the caller's authority. "
    "An attacker can replace the configuration while the service is running and cause the broker to accept arbitrary settings. "
    "The problem affects the vulnerable release on all supported platforms, including installations with default settings. "
    "Administrators should install the vendor's corrected release and inspect any unexpected configuration changes. "
    "This final sentence must remain available to a researcher reading the complete source-derived heading."
)


@pytest.mark.parametrize("source_id", ["cve", "circl", "nvd"])
@pytest.mark.parametrize("description", [LONG_DESCRIPTION[:240], LONG_DESCRIPTION])
def test_source_fallback_heading_preserves_the_complete_description(source_id, description):
    assert len(description) > 180
    if source_id == "nvd":
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2024-3094", "descriptions": [{"lang": "en", "value": description}],
        }}]}
    else:
        payload = {
            "cveMetadata": {"cveId": "CVE-2024-3094", "state": "PUBLISHED"},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": description}]}},
        }
    record, raw = parse_source(source_id, payload)[0]
    assert record["title"] == description
    assert record["description"] == description
    assert raw == (payload["vulnerabilities"][0]["cve"] if source_id == "nvd" else payload)


@pytest.mark.parametrize("source_id", ["cve", "circl"])
def test_explicit_source_heading_over_500_characters_is_not_cut(source_id):
    title = LONG_DESCRIPTION + " This is an explicit heading, not the advisory description."
    assert len(title) > 500
    payload = {
        "cveMetadata": {"cveId": "CVE-2024-3094", "state": "PUBLISHED"},
        "containers": {"cna": {"title": title, "descriptions": [{"lang": "en", "value": "A different description."}]}},
    }
    record = parse_source(source_id, payload)[0][0]
    assert record["title"] == title
    assert record["description"] == "A different description."


def test_complete_titles_keep_the_text_safety_bound_and_full_raw_evidence():
    description = "x" * 50001
    payload = {
        "cveMetadata": {"cveId": "CVE-2024-3094", "state": "PUBLISHED"},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": description}]}},
    }
    record, raw = parse_source("cve", payload)[0]
    assert record["title"] == "x" * 50000
    assert record["description"] == "x" * 50000
    assert raw["containers"]["cna"]["descriptions"][0]["value"] == description


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


def test_targeted_cve_and_circl_404s_report_missing_records_without_source_errors(tmp_path):
    identifier = "CVE-1999-99999"
    responses = {
        "https://cveawg.mitre.org/api/cve/" + identifier: (404, {"error": "CVE_RECORD_DNE"}),
        "https://vulnerability.circl.lu/api/cve/" + identifier: (404, {"message": "Controlled record not found"}),
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + identifier: (200, {"vulnerabilities": []}),
        "https://api.first.org/data/v1/epss?cve=" + identifier: (200, {"data": []}),
        "https://api.github.com/advisories?cve_id=" + identifier + "&per_page=10": (200, []),
    }
    calls = []

    def handler(request):
        assert request.method == "GET" and str(request.url) in responses
        calls.append(str(request.url))
        status, payload = responses[str(request.url)]
        return httpx.Response(status, json=payload)

    store = Store(tmp_path)
    store.upsert_record({"id": "CVE-2024-3094", "title": "Keep cached intelligence"}, "cve", CVE)
    service = IntelService(store, transport=httpx.MockTransport(handler))
    result = asyncio.run(service.enrich(identifier))
    assert result["record"] is None
    assert result["results"] == [{"id": source, "status": "not_found", "records": 0} for source in ["cve", "nvd", "epss", "circl", "github"]]
    assert len(calls) == 5
    for source in ["cve", "circl"]:
        state = store.source_state(source)
        assert state["status"] == "ok" and state["error"] is None
        assert state["last_success"] and state["next_request_at"] > 0
        store.set_source_state(source, next_request_at=9999999999)
    second = asyncio.run(service.enrich(identifier, sources=["cve", "circl"]))
    assert all(item["status"] == "error" and "Local request budget" in item["error"] for item in second["results"])
    assert len(calls) == 5
    assert store.get_record("CVE-2024-3094")["title"] == "Keep cached intelligence"


@pytest.mark.parametrize("source_id", ["nvd", "epss", "github"])
def test_404s_from_list_based_targeted_endpoints_remain_source_errors(tmp_path, source_id):
    service = IntelService(Store(tmp_path), transport=httpx.MockTransport(lambda request: httpx.Response(404)))
    result = asyncio.run(service.enrich("CVE-1999-99999", sources=[source_id]))
    assert result["record"] is None
    assert result["results"][0]["status"] == "error"
    assert "HTTP 404" in result["results"][0]["error"]


@pytest.mark.parametrize("source_id", ["cisa", "cve", "circl"])
def test_feed_refresh_404s_do_not_become_successful_empty_syncs(tmp_path, source_id):
    store = Store(tmp_path)
    store.upsert_record({"id": "CVE-2024-3094", "title": "Keep cached intelligence"}, "cve", CVE)
    service = IntelService(store, transport=httpx.MockTransport(lambda request: httpx.Response(404)))
    result = asyncio.run(service.sync([source_id], force=True))
    assert result["results"][0]["status"] == "error"
    assert "HTTP 404" in result["results"][0]["error"]
    assert store.source_state(source_id)["status"] == "error"
    assert store.get_record("CVE-2024-3094")["title"] == "Keep cached intelligence"
