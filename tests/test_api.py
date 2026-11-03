import asyncio
import json

import httpx
import pytest
from atlas.app import create_app
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path):
    def no_network(request):
        raise AssertionError(f"Unrequested external request: {request.url}")
    app = create_app(tmp_path, allowed_hosts={"testserver"}, transport=httpx.MockTransport(no_network))
    with TestClient(app) as client:
        yield client


def test_local_health_search_and_invalid_inputs(client):
    assert client.get("/api/health").json()["storage"] == "local"
    assert client.get("/api/vulnerabilities").json()["total"] == 0
    assert client.get("/api/vulnerabilities", params={"q": "x" * 301}).status_code == 422
    assert client.get("/api/vulnerabilities/not-an-id").status_code == 400
    assert client.post("/api/lookup", json={"identifier": "https://example.org"}).status_code == 400
    assert client.post("/api/sync", json={"sources": ["unregistered"]}).status_code == 400


def test_foreign_origin_and_rebinding_hosts_cannot_read_or_change_local_data(client):
    assert client.post("/api/notes", headers={"Origin": "https://evil.example"}, json={"title": "attack"}).status_code == 403
    assert client.get("/api/notes", headers={"Origin": "null"}).status_code == 403
    assert client.get("/api/stats", headers={"Host": "evil.example"}).status_code == 400
    assert client.get("/api/stats", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    response = client.get("/api/notes")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "access-control-allow-origin" not in response.headers


def test_note_crud_revision_conflict_unsafe_links_and_restore(client):
    response = client.post("/api/notes", json={"title": "Research", "body": "CVE-2024-3094 <script>alert(1)</script>", "tags": ["xz"]})
    assert response.status_code == 201
    note = response.json()
    assert note["links"] == ["CVE-2024-3094"]
    assert "<script>" in note["body"]
    update = client.put(f"/api/notes/{note['id']}", json={"title": "Updated", "body": note["body"], "revision": 1})
    assert update.status_code == 200
    assert client.put(f"/api/notes/{note['id']}", json={"title": "Stale", "revision": 1}).status_code == 409
    assert client.post("/api/notes", json={"title": "Bad link", "source_urls": ["javascript:alert(1)"]}).status_code == 400
    assert client.delete(f"/api/notes/{note['id']}").status_code == 200
    assert client.get("/api/notes").json() == []
    assert client.post(f"/api/notes/{note['id']}/restore").status_code == 200
    assert client.get("/api/notes").json()[0]["title"] == "Updated"


def test_artifact_upload_body_limit_tracks_the_64_mib_analysis_cap(client):
    from atlas.analysis import MAX_FILE
    from atlas.security import MAX_BODY

    assert MAX_BODY >= MAX_FILE + (1 << 20)
    response = client.post("/api/analyze", files={"file": ("big.bin", b"A" * (MAX_FILE + 1))})
    assert response.status_code == 413
    assert "64 MiB" in response.json()["detail"]


def test_export_is_a_download_with_source_linked_local_context(client):
    client.post("/api/notes", json={"title": "A finding", "body": "Source: https://example.org"})
    response = client.get("/api/export")
    assert "attachment" in response.headers["content-disposition"]
    assert response.json()["source_linked"] is True
    assert response.json()["notes"][0]["title"] == "A finding"
    markdown = client.get("/api/export", params={"format": "markdown"})
    assert "# A finding" in markdown.text


def test_file_analysis_has_upload_caps_and_does_not_save_artifacts(client):
    from atlas.analysis import MAX_FILE
    from atlas.security import MAX_BODY

    response = client.post("/api/analyze", files={"file": ("sample.bin", b"hello static research\x00", "application/octet-stream")})
    assert response.status_code == 200
    assert response.json()["execution"] == "never"
    response = client.post("/api/analyze", files={"file": ("large", b"x" * (MAX_FILE + 1))})
    assert response.status_code == 413
    assert client.post("/api/notes", content=b"x" * (MAX_BODY + 1), headers={"content-type": "application/json"}).status_code == 413


def test_dependency_audit_requires_consent_and_reuses_cached_results_offline(tmp_path):
    calls = []
    failing = [False]

    def handler(request):
        assert request.url == "https://api.osv.dev/v1/querybatch"
        assert request.method == "POST"
        assert "authorization" not in request.headers
        body = json.loads(request.content)
        assert body == {"queries": [{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"}]}
        calls.append(body)
        if failing[0]:
            raise httpx.ConnectError("Offline", request=request)
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm", "modified": "2026-01-01T00:00:00Z"}]}]})

    app = create_app(tmp_path, allowed_hosts={"testserver"}, transport=httpx.MockTransport(handler))
    request = {"format": "npm", "content": '{"dependencies":{"lodash":"4.17.20"}}', "allow_network": False}
    with TestClient(app) as client:
        offline = client.post("/api/audit", json=request)
        assert offline.status_code == 200
        assert offline.json()["results"][0]["status"] == "not_cached"
        assert calls == []
        request["allow_network"] = True
        response = client.post("/api/audit", json=request)
        assert response.status_code == 200
        assert response.json()["results"][0]["vulnerabilities"][0]["id"] == "GHSA-35jh-r3h4-6jhm"
        failing[0] = True
        request["allow_network"] = False
        cached = client.post("/api/audit", json=request).json()
        assert cached["results"][0]["status"] == "cached"
        assert cached["results"][0]["checked_at"]
        assert len(calls) == 1


def test_chunked_body_cannot_bypass_upload_limit(client):
    from atlas.security import MAX_BODY

    chunk = 1024 * 1024
    count = MAX_BODY // chunk + 2

    def body():
        for _ in range(count):
            yield b"x" * chunk
    response = client.post("/api/notes", content=body(), headers={"content-type": "application/json"})
    assert response.status_code == 413


def test_shutdown_cancels_background_sync_without_mutating_task_iteration(tmp_path):
    async def waiting(request):
        await asyncio.Event().wait()
    app = create_app(tmp_path, allowed_hosts={"testserver"}, transport=httpx.MockTransport(waiting))
    with TestClient(app) as client:
        assert client.post("/api/sync", json={"sources": ["cisa"]}).status_code == 202
        assert client.get("/api/sync").json()["running"] is True


def test_invalid_osv_match_is_reported_as_failed_check_not_clean_result(tmp_path):
    def handler(request):
        return httpx.Response(200, json={"results": [{"vulns": [{"modified": "2026-01-01"}]}]})
    app = create_app(tmp_path, allowed_hosts={"testserver"}, transport=httpx.MockTransport(handler))
    with TestClient(app) as client:
        response = client.post("/api/audit", json={"format": "npm", "content": '{"dependencies":{"lodash":"4.17.20"}}', "allow_network": True})
        assert response.status_code == 200
        assert response.json()["results"][0]["status"] == "error"
        assert response.json()["warnings"]


@pytest.mark.parametrize("has_cache", [False, True])
def test_malformed_osv_batch_cannot_publish_partial_rows_or_replace_cache(tmp_path, has_cache):
    def handler(request):
        assert request.url == "https://api.osv.dev/v1/querybatch"
        assert json.loads(request.content) == {"queries": [
            {"package": {"name": "first-package", "ecosystem": "npm"}, "version": "1.0.0"},
            {"package": {"name": "second-package", "ecosystem": "npm"}, "version": "2.0.0"},
        ]}
        return httpx.Response(200, json={"results": [{"vulns": []}, {"vulns": [{"modified": "2026-01-01"}]}]})

    app = create_app(tmp_path, allowed_hosts={"testserver"}, transport=httpx.MockTransport(handler))
    store = app.state.store
    first_key = '{"ecosystem":"npm","name":"first-package","version":"1.0.0"}'
    second_key = '{"ecosystem":"npm","name":"second-package","version":"2.0.0"}'
    old_matches = [{"id": "GHSA-35jh-r3h4-6jhm", "modified": "2026-01-01T00:00:00Z", "url": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"}]
    if has_cache:
        store.put_cache("osv-package", first_key, old_matches)
        with store.connection() as conn:
            conn.execute("UPDATE query_cache SET fetched_at=? WHERE scope=? AND key=?", ("2000-01-01T00:00:00Z", "osv-package", first_key))
    before = store.get_cache("osv-package", first_key)
    with TestClient(app) as client:
        response = client.post("/api/audit", json={"format": "npm", "content": '{"dependencies":{"first-package":"1.0.0","second-package":"2.0.0"}}', "allow_network": True})
        assert response.status_code == 200
        report = response.json()
        assert store.source_state("osv")["status"] == "error"
        assert "last_success" not in store.source_state("osv")
        assert len(report["results"]) == 2
        assert [(row["name"], row["status"]) for row in report["results"]] == [("first-package", "cached" if has_cache else "error"), ("second-package", "error")]
        assert report["packages_checked"] == (1 if has_cache else 0)
        assert report["results"][0]["vulnerabilities"] == (old_matches if has_cache else [])
        assert report["warnings"]
        assert store.get_cache("osv-package", first_key) == before
        assert store.get_cache("osv-package", second_key) is None
