"""Bounded public HTTP requests, feed caching, and explicitly requested enrichment."""

import asyncio
import json
import time
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import httpx

from .models import normalize_id, utcnow
from .sources import SOURCES, SourceError, parse_source


class _RecordNotFound(Exception):
    """A targeted record endpoint returned HTTP 404, not a feed failure."""


class IntelService:
    def __init__(self, store, transport=None):
        self.store = store
        self.transport = transport
        self._lock = asyncio.Lock()
        self.running = False
        self.results = []
        self.started_at = None
        self.finished_at = None

    def source_inventory(self):
        return [{**asdict(source), **self.store.source_state(source.id), "no_key": True} for source in SOURCES.values()]

    def status(self):
        return {"running": self.running, "started_at": self.started_at, "finished_at": self.finished_at, "results": self.results}

    def _client(self):
        return httpx.AsyncClient(
            transport=self.transport, timeout=httpx.Timeout(25, connect=8), follow_redirects=False,
            headers={"User-Agent": "SignalAtlas/0.1 (local-first open-source research)", "Accept": "application/json"},
        )

    async def _request(self, client, source_id, url, *, params=None, body=None, allow_not_found=False):
        source = SOURCES[source_id]
        state = self.store.source_state(source_id)
        now = time.time()
        if state.get("next_request_at", 0) > now:
            raise SourceError(f"Local request budget: retry in {int(state['next_request_at'] - now) + 1} seconds.")
        self.store.set_source_state(source_id, next_request_at=now + source.interval)
        headers = {}
        if body is None and state.get("etag") and state.get("etag_url") == str(httpx.URL(url, params=params)):
            headers["If-None-Match"] = state["etag"]
        async with client.stream("POST" if body is not None else "GET", url, params=params, json=body, headers=headers) as response:
            if response.status_code == 304:
                return None
            if response.status_code == 404 and allow_not_found:
                raise _RecordNotFound
            if response.status_code in {429, 403}:
                retry = response.headers.get("retry-after", "60")
                try:
                    seconds = min(86400, max(source.interval, float(retry)))
                except ValueError:
                    seconds = 60
                if response.headers.get("x-ratelimit-remaining") == "0":
                    try:
                        seconds = max(seconds, float(response.headers.get("x-ratelimit-reset", "0")) - now)
                    except ValueError:
                        pass
                self.store.set_source_state(source_id, next_request_at=now + seconds)
            if response.status_code >= 400:
                raise SourceError(f"HTTP {response.status_code} from {source.name}. Cached data is retained.")
            if response.status_code >= 300:
                raise SourceError(f"Unexpected HTTP {response.status_code} redirect from {source.name}; fixed endpoints only.")
            cap = 16 * 1024 * 1024 if source_id == "exploitdb" else 8 * 1024 * 1024
            chunks, size = [], 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > cap:
                    raise SourceError(f"{source.name} response exceeds the {cap // 1024 // 1024} MiB limit.")
                chunks.append(chunk)
            content = b"".join(chunks)
            if response.headers.get("etag") and body is None:
                self.store.set_source_state(source_id, etag=response.headers["etag"], etag_url=str(response.url))
            if response.headers.get("x-ratelimit-remaining") is not None:
                self.store.set_source_state(source_id, rate_remaining=response.headers["x-ratelimit-remaining"])
            if source_id == "exploitdb":
                return content.decode("utf-8-sig", errors="replace")
            try:
                return json.loads(content)
            except (ValueError, UnicodeError) as exc:
                raise SourceError(f"{source.name} did not return valid JSON.") from exc

    async def _fetch_feed(self, client, source_id):
        source = SOURCES[source_id]
        if source_id == "cisa" or source_id == "exploitdb":
            return await self._request(client, source_id, source.url)
        if source_id == "github":
            return await self._request(client, source_id, source.url, params={"per_page": 60, "type": "reviewed", "sort": "published", "direction": "desc"})
        if source_id == "nvd":
            now = datetime.now(UTC)
            return await self._request(client, source_id, source.url, params={
                "lastModStartDate": (now - timedelta(days=7)).isoformat(timespec="seconds"),
                "lastModEndDate": now.isoformat(timespec="seconds"), "resultsPerPage": 50,
            })
        records = self.store.list_records(limit=100)["items"]
        cves = [record["id"] for record in records if record["id"].startswith("CVE-")]
        if source_id == "epss":
            if not cves:
                return {"data": []}
            return await self._request(client, source_id, source.url, params={"cve": ",".join(cves[:100])})
        if source_id in {"cve", "circl"}:
            if not cves:
                return "SKIP"
            return await self._request(client, source_id, source.url + "/" + cves[0])
        if source_id == "osv":
            advisories = self.store.list_records(source="github", limit=10)["items"]
            alias = next((alias for record in advisories for alias in record["aliases"] if alias.startswith("GHSA-")), None)
            if not alias:
                return "SKIP"
            return await self._request(client, source_id, source.url + "/vulns/" + alias)
        raise ValueError("Unsupported feed.")

    @staticmethod
    def _fresh(value, ttl):
        if not value:
            return False
        try:
            return (datetime.now(UTC) - datetime.fromisoformat(value)).total_seconds() < ttl
        except ValueError:
            return False

    async def sync(self, source_ids=None, force=False):
        source_ids = list(dict.fromkeys(source_ids or list(SOURCES)))
        if any(source not in SOURCES for source in source_ids):
            raise ValueError("Choose a registered public source.")
        if self._lock.locked():
            return self.status()
        async with self._lock:
            self.running = True
            self.results = []
            self.started_at = utcnow()
            try:
                async with self._client() as client:
                    for source_id in source_ids:
                        state = self.store.source_state(source_id)
                        if not force and self._fresh(state.get("last_success"), SOURCES[source_id].ttl):
                            self.results.append({"id": source_id, "status": "cached", "records": state.get("records", 0)})
                            continue
                        self.store.set_source_state(source_id, status="syncing", error=None)
                        try:
                            payload = await asyncio.wait_for(self._fetch_feed(client, source_id), timeout=35)
                            if payload == "SKIP":
                                self.store.set_source_state(source_id, status="idle", error=None)
                                self.results.append({"id": source_id, "status": "skipped", "records": 0, "message": "Sync primary feeds first or look up an identifier."})
                                continue
                            if payload is None:
                                count = state.get("records", 0)
                            else:
                                parsed = await asyncio.to_thread(parse_source, source_id, payload)
                                count = await asyncio.to_thread(self.store.upsert_records, parsed, source_id)
                            self.store.set_source_state(source_id, status="ok", records=count, last_success=utcnow(), error=None)
                            self.results.append({"id": source_id, "status": "ok", "records": count})
                        except (SourceError, httpx.HTTPError, TimeoutError) as exc:
                            error = str(exc)[:300] or "The source timed out. Cached data is retained."
                            self.store.set_source_state(source_id, status="error", error=error)
                            self.results.append({"id": source_id, "status": "error", "error": error, "records": state.get("records", 0)})
            finally:
                self.running = False
                self.finished_at = utcnow()
        return self.status()

    async def enrich(self, identifier, sources=None):
        identifier = normalize_id(identifier)
        if sources is None:
            sources = ["cve", "nvd", "epss", "circl", "github"] if identifier.startswith("CVE-") else ["osv", "github"] if identifier.startswith("GHSA-") else ["osv"]
        if any(source_id not in {"cve", "nvd", "epss", "circl", "github", "osv"} for source_id in sources):
            raise ValueError("This source supports feed sync, not targeted lookup.")
        results = []
        async with self._lock, self._client() as client:
            for source_id in sources:
                source = SOURCES[source_id]
                existing = self.store.get_record(identifier)
                cached = next((item for item in (existing or {}).get("evidence", []) if item["source_id"] == source_id), None)
                if cached and self._fresh(cached["fetched_at"], source.ttl):
                    results.append({"id": source_id, "status": "cached", "records": 1})
                    continue
                try:
                    params = None
                    if source_id in {"cve", "circl"}:
                        if not identifier.startswith("CVE-"):
                            continue
                        url = source.url + "/" + quote(identifier, safe="")
                    elif source_id == "nvd":
                        url, params = source.url, {"cveId": identifier}
                    elif source_id == "epss":
                        url, params = source.url, {"cve": identifier}
                    elif source_id == "github":
                        if identifier.startswith("CVE-"):
                            url, params = source.url, {"cve_id": identifier, "per_page": 10}
                        else:
                            url = source.url + "/" + quote(identifier, safe="")
                    else:
                        osv_id = next((alias for alias in (existing or {}).get("aliases", []) if alias.startswith("GHSA-")), identifier)
                        url = source.url + "/vulns/" + quote(osv_id, safe="")
                    payload = await asyncio.wait_for(self._request(client, source_id, url, params=params, allow_not_found=source_id in {"cve", "circl"}), timeout=30)
                    parsed = parse_source(source_id, payload) if payload is not None else []
                    count = await asyncio.to_thread(self.store.upsert_records, parsed, source_id)
                    self.store.set_source_state(source_id, status="ok", last_success=utcnow(), error=None)
                    results.append({"id": source_id, "status": "ok" if count else "not_found", "records": count})
                except _RecordNotFound:
                    self.store.set_source_state(source_id, status="ok", last_success=utcnow(), error=None)
                    results.append({"id": source_id, "status": "not_found", "records": 0})
                except (SourceError, httpx.HTTPError, TimeoutError) as exc:
                    error = str(exc)[:300] or "The source timed out."
                    self.store.set_source_state(source_id, status="error", error=error)
                    results.append({"id": source_id, "status": "error", "error": error})
        return {"record": self.store.get_record(identifier), "results": results}

    async def query_osv(self, packages):
        async with self._lock, self._client() as client:
            queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]} for p in packages]
            payload = await asyncio.wait_for(self._request(client, "osv", SOURCES["osv"].url + "/querybatch", body={"queries": queries}), timeout=30)
            if not isinstance(payload, dict) or not isinstance(payload.get("results"), list) or len(payload["results"]) != len(packages):
                raise SourceError("OSV returned an invalid package-query response.")
            return payload["results"]

    async def audit(self, manifest, allow_network=False):
        from .analysis import parse_manifest

        parsed = parse_manifest(manifest["format"], manifest["content"])
        results, pending = [], []
        for package in parsed["packages"]:
            key = self.store._json(package)
            cached = self.store.get_cache("osv-package", key)
            if cached and (not allow_network or self._fresh(cached["fetched_at"], 86400)):
                results.append({**package, "status": "cached", "checked_at": cached["fetched_at"], "vulnerabilities": cached["payload"]})
            elif not allow_network:
                results.append({**package, "status": "not_cached", "checked_at": None, "vulnerabilities": [], "message": "Enable the OSV query to check this package version."})
            else:
                pending.append((package, key, cached))
        if pending:
            try:
                responses = await self.query_osv([item[0] for item in pending])
                validated, batch_warnings = [], []
                for (package, key, _), response in zip(pending, responses, strict=True):
                    if not isinstance(response, dict) or not isinstance(response.get("vulns", []), list):
                        raise SourceError("OSV returned invalid vulnerability matches.")
                    matches = []
                    for vulnerability in response.get("vulns", [])[:200]:
                        if not isinstance(vulnerability, dict) or not vulnerability.get("id"):
                            raise SourceError("OSV returned a match without a vulnerability identifier; no clean result can be inferred.")
                        try:
                            identifier = normalize_id(vulnerability["id"])
                        except ValueError as exc:
                            raise SourceError("OSV returned an invalid vulnerability identifier.") from exc
                        matches.append({"id": identifier, "modified": vulnerability.get("modified"), "url": "https://osv.dev/vulnerability/" + quote(identifier, safe="")})
                    if response.get("next_page_token"):
                        batch_warnings.append("OSV has more matches for " + package["name"] + "; the displayed result is incomplete. Inspect the advisory site.")
                    validated.append((package, key, matches))
                # Validate the whole batch before replacing caches or reporting success.
                self.store.set_source_state("osv", status="ok", last_success=utcnow(), error=None)
                parsed["warnings"].extend(batch_warnings)
                for package, key, matches in validated:
                    self.store.put_cache("osv-package", key, matches)
                    results.append({**package, "status": "ok", "checked_at": utcnow(), "vulnerabilities": matches})
            except (SourceError, httpx.HTTPError, TimeoutError) as exc:
                error = str(exc)[:250] or "OSV is unreachable. Cached results are retained."
                parsed["warnings"].append(error)
                self.store.set_source_state("osv", status="error", error=error)
                for package, _, cached in pending:
                    results.append({**package, "status": "cached" if cached else "error", "checked_at": cached["fetched_at"] if cached else None, "vulnerabilities": cached["payload"] if cached else [], "message": "Remote check failed; this is cached evidence, not a fresh clean bill of health."})
        return {**parsed, "results": results, "packages_checked": sum(item["status"] in {"ok", "cached"} for item in results), "affected_packages": sum(bool(item["vulnerabilities"]) for item in results), "network_allowed": allow_network}
