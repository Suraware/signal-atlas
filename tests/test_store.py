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
