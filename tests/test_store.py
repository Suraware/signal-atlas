from pathlib import Path

import pytest
from atlas.store import ConflictError, Store


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path)


def test_aliases_correlate_evidence_without_duplicate_vulnerabilities(store):
    store.upsert_record({"id": "GHSA-jfh8-c2jp-5v3q", "title": "xz research", "severity": "HIGH"}, "github", {})
    store.upsert_record(
        {
            "id": "CVE-2024-3094",
            "aliases": ["GHSA-jfh8-c2jp-5v3q"],
            "title": "Malicious code in xz Utils",
            "description": "A source-linked supply-chain vulnerability.",
            "severity": "CRITICAL",
            "cvss": 10.0,
        },
        "cve",
        {"cveMetadata": {"cveId": "CVE-2024-3094"}},
    )
    records = store.list_records()
    assert records["total"] == 1
    record = store.get_record("GHSA-jfh8-c2jp-5v3q")
    assert record["id"] == "CVE-2024-3094"
    assert record["severity"] == "CRITICAL"
    assert set(record["source_ids"]) == {"github", "cve"}
    assert len(record["evidence"]) == 2


def test_refresh_retains_known_exploitation_and_other_source_links(store):
    store.upsert_record(
        {"id": "CVE-2024-3094", "kev": True, "references": [{"url": "https://www.cisa.gov/", "label": "CISA"}]},
        "cisa",
        {"knownRansomwareCampaignUse": "Unknown"},
    )
    store.upsert_record({"id": "CVE-2024-3094", "epss": 0.42, "severity": "CRITICAL"}, "epss", {})
    record = store.get_record("CVE-2024-3094")
    assert record["kev"] is True
    assert record["epss"] == 0.42
    assert record["references"][0]["url"] == "https://www.cisa.gov/"
    assert record["evidence"][0]["fetched_at"]


def test_search_and_filters_are_literal_bounded_and_persist(store, tmp_path):
    store.upsert_record({"id": "CVE-2024-3094", "title": "xz backdoor", "severity": "CRITICAL", "kev": True}, "cisa", {})
    store.upsert_record({"id": "CVE-2023-1111", "title": "Harmless test fixture", "severity": "LOW"}, "cve", {})
    assert store.list_records(q="xz")["total"] == 1
    assert store.list_records(q="CVE-2024-3094")["items"][0]["id"] == "CVE-2024-3094"
    assert store.list_records(q="' OR 1=1 --")["total"] == 0
    assert store.list_records(q='" : * (')["total"] == 0
    assert store.list_records(severity="CRITICAL", kev=True)["total"] == 1
    assert store.list_records(limit=1)["total"] == 2
    assert len(store.list_records(limit=1)["items"]) == 1
    reopened = Store(tmp_path)
    assert reopened.get_record("CVE-2024-3094")["title"] == "xz backdoor"


def test_note_links_are_extracted_and_revision_prevents_overwrites(store):
    note = store.save_note({"title": "xz investigation", "body": "Check CVE-2024-3094 and cve-2024-3094.", "tags": ["linux", "linux"]})
    assert note["links"] == ["CVE-2024-3094"]
    assert note["tags"] == ["linux"]
    assert note["status"] == "unverified"
    assert note["revision"] == 1
    updated = store.save_note({"title": "xz evidence", "body": note["body"], "revision": 1}, note["id"])
    assert updated["revision"] == 2
    with pytest.raises(ConflictError):
        store.save_note({"title": "stale overwrite", "body": "oops", "revision": 1}, note["id"])
    assert store.list_notes(q="evidence")[0]["title"] == "xz evidence"


def test_note_delete_and_restore_preserve_content_and_export(store):
    note = store.save_note({"title": "Local research", "body": "Evidence remains local."})
    store.delete_note(note["id"])
    assert store.list_notes() == []
    restored = store.restore_note(note["id"])
    assert restored["body"] == "Evidence remains local."
    exported = store.export_context()
    assert exported["notes"][0]["title"] == "Local research"
    assert exported["schema_version"] == 1
    assert Path(store.data_dir, "atlas.sqlite3").exists()


def test_graph_reports_real_relationships_and_note_evidence(store):
    store.upsert_record(
        {"id": "CVE-2024-3094", "title": "xz", "vendors": ["Tukaani"], "products": ["xz"], "cwes": ["CWE-506"]},
        "cve",
        {},
    )
    store.save_note({"title": "Investigation", "body": "Evidence for CVE-2024-3094"})
    graph = store.graph(focus="CVE-2024-3094")
    ids = {node["id"] for node in graph["nodes"]}
    assert "vuln:CVE-2024-3094" in ids
    assert "weakness:CWE-506" in ids
    assert any(edge["relation"] == "documents" for edge in graph["edges"])
    assert all(edge["source"] in ids and edge["target"] in ids for edge in graph["edges"])


def test_unknown_records_are_not_fabricated_and_watch_is_persistent(store):
    assert store.get_record("CVE-2024-0000") is None
    store.upsert_record({"id": "CVE-2024-3094", "title": "xz"}, "cve", {})
    store.set_watched("CVE-2024-3094", True)
    assert store.list_records(watched=True)["total"] == 1
    assert store.stats()["watched"] == 1


def test_source_state_does_not_erase_cached_records(store):
    store.upsert_record({"id": "CVE-2024-3094", "title": "xz"}, "cisa", {})
    store.set_source_state("cisa", status="ok", records=1, last_success="2026-11-03T00:00:00Z")
    store.set_source_state("cisa", status="error", error="Timeout")
    state = store.source_state("cisa")
    assert state["last_success"] == "2026-11-03T00:00:00Z"
    assert state["error"] == "Timeout"
    assert store.list_records()["total"] == 1


@pytest.mark.parametrize("source_id, legacy_limit", [("cve", 180), ("circl", 180), ("nvd", 180), ("cve", 500), ("nvd", 500)])
def test_legacy_heading_recovers_from_its_own_source_without_writing_research(store, source_id, legacy_limit):
    identifier = "CVE-2026-111357"
    description = (
        "A privileged broker trusts configuration from an authenticated client and allows privilege escalation. "
        "The attacker can change settings accepted by the broker without proving permission to change them. "
        "Affected installations include default configurations and configurations with optional integrations enabled. "
        "The issue is confined to the vulnerable releases listed by the vendor and must be investigated against the deployed environment. "
        "Researchers should read the original observation and distinguish it from a different catalog summary. "
        "The complete heading ends with this source-specific evidence."
    )
    assert len(description) > 500
    raw = ({"id": identifier, "descriptions": [{"lang": "en", "value": description}]} if source_id == "nvd" else {
        "cveMetadata": {"cveId": identifier, "state": "PUBLISHED"},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": description}]}},
    })
    store.upsert_record({"id": identifier, "title": description[:legacy_limit], "description": description}, source_id, raw)
    unrelated = "A different catalog description. " * 30
    store.upsert_record({"id": identifier, "title": "Catalog heading", "description": unrelated, "kev": True}, "cisa", {"catalog": True})
    store.set_watched(identifier, True)
    note = store.save_note({"title": "Local investigation", "body": "Research for " + identifier})
    with store.connection() as conn:
        before = list(conn.iterdump())
    record = store.get_record(identifier)
    assert record["title"] == description
    assert record["description"] == unrelated
    assert record["watched"] is True
    assert record["notes"] == [note]
    observation = next(item for item in record["evidence"] if item["source_id"] == source_id)
    assert observation["record"]["title"] == description[:legacy_limit]
    assert observation["raw"] == raw
    assert store.list_records(q=identifier)["items"][0]["title"] == description
    assert store.export_context(identifier)["vulnerabilities"][0]["title"] == description
    assert store.export_context()["vulnerabilities"][0]["title"] == description
    with store.connection() as conn:
        assert list(conn.iterdump()) == before


def test_legacy_normalization_cut_on_an_explicit_title_recovers_from_raw_title(store):
    title = "An explicit source title with important details. " * 12 + "The full title ends here."
    assert len(title) > 500
    raw = {
        "cveMetadata": {"cveId": "CVE-2024-3094", "state": "PUBLISHED"},
        "containers": {"cna": {"title": title, "descriptions": [{"lang": "en", "value": "Different advisory context."}]}},
    }
    store.upsert_record({"id": "CVE-2024-3094", "title": title[:500], "description": "Different advisory context."}, "cve", raw)
    assert store.get_record("CVE-2024-3094")["title"] == title


@pytest.mark.parametrize("source_id", ["cve", "circl"])
def test_genuine_180_character_source_title_is_not_replaced_by_description(store, source_id):
    title = "A" * 180
    description = title + " This additional text belongs to the description, not the title."
    raw = {
        "cveMetadata": {"cveId": "CVE-2024-3094", "state": "PUBLISHED"},
        "containers": {"cna": {"title": title, "descriptions": [{"lang": "en", "value": description}]}},
    }
    store.upsert_record({"id": "CVE-2024-3094", "title": title, "description": description}, source_id, raw)
    assert store.get_record("CVE-2024-3094")["title"] == title


def test_unrelated_source_prefix_cannot_replace_a_genuine_catalog_heading(store):
    title = "A" * 180
    description = title + " Some unrelated text with the same opening."
    raw = {
        "cveMetadata": {"cveId": "CVE-2024-3094", "state": "PUBLISHED"},
        "containers": {"cna": {"title": "A different short source title", "descriptions": [{"lang": "en", "value": description}]}},
    }
    store.upsert_record({"id": "CVE-2024-3094", "title": "A different short source title", "description": description}, "cve", raw)
    store.upsert_record({"id": "CVE-2024-3094", "title": title}, "cisa", {"vulnerabilityName": title})
    assert store.get_record("CVE-2024-3094")["title"] == title


@pytest.mark.parametrize("source_id", ["cve", "circl", "cisa"])
@pytest.mark.parametrize("legacy_limit", [180, 500])
def test_matching_legacy_fallback_cannot_replace_another_sources_genuine_title(store, source_id, legacy_limit):
    identifier = "CVE-2024-3094"
    title = "A" * legacy_limit
    raw_title = ({"cveID": identifier, "vulnerabilityName": title} if source_id == "cisa" else {
        "cveMetadata": {"cveId": identifier, "state": "PUBLISHED"},
        "containers": {"cna": {"title": title, "descriptions": [{"lang": "en", "value": "Different CNA context."}]}},
    })
    store.upsert_record({"id": identifier, "title": title}, source_id, raw_title)
    fallback = title + " This suffix belongs only to the NVD fallback description."
    raw_fallback = {"id": identifier, "descriptions": [{"lang": "en", "value": fallback}]}
    store.upsert_record({"id": identifier, "title": title, "description": fallback}, "nvd", raw_fallback)
    store.set_watched(identifier, True)
    note = store.save_note({"title": "Preserve the source heading", "body": identifier})
    with store.connection() as conn:
        before = list(conn.iterdump())
    record = store.get_record(identifier)
    assert record["title"] == title
    assert record["description"] == fallback
    assert record["watched"] is True and record["notes"] == [note]
    assert store.list_records(q=identifier)["items"][0]["title"] == title
    assert store.export_context(identifier)["vulnerabilities"][0]["title"] == title
    assert {item["source_id"]: item["raw"] for item in record["evidence"]} == {source_id: raw_title, "nvd": raw_fallback}
    with store.connection() as conn:
        assert list(conn.iterdump()) == before


def test_conflicting_full_source_headings_leave_ambiguous_legacy_provenance_unchanged(store):
    identifier, title = "CVE-2024-3094", "A" * 180
    cve_description = title + " This is the CNA description."
    nvd_description = title + " This different suffix is from NVD."
    raw = {
        "cveMetadata": {"cveId": identifier, "state": "PUBLISHED"},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": cve_description}]}},
    }
    store.upsert_record({"id": identifier, "title": title, "description": cve_description}, "cve", raw)
    store.upsert_record({"id": identifier, "title": title, "description": nvd_description}, "nvd", {
        "id": identifier, "descriptions": [{"lang": "en", "value": nvd_description}],
    })
    assert store.get_record(identifier)["title"] == title
