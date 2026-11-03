"""SQLite owns local evidence, aliases, revisioned notes, and feed state."""

import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from .models import CVE_IN_TEXT, merge_records, normalize_id, normalize_record, safe_url, unique, utcnow
from .sources import SourceError, parse_source


class ConflictError(Exception):
    """A note changed after the client last read its revision."""


class Store:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.data_dir / "atlas.sqlite3"
        self._lock = threading.RLock()
        with self.connection() as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS records (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL, severity TEXT NOT NULL,
                    kev INTEGER NOT NULL DEFAULT 0, watched INTEGER NOT NULL DEFAULT 0,
                    published TEXT, modified TEXT, fetched_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS aliases (
                    alias TEXT PRIMARY KEY, record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
                    source_id TEXT NOT NULL, raw TEXT NOT NULL, normalized TEXT NOT NULL, fetched_at TEXT NOT NULL,
                    PRIMARY KEY (record_id, source_id)
                );
                CREATE TABLE IF NOT EXISTS source_state (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS notes (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL, revision INTEGER NOT NULL,
                    updated_at TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS query_cache (
                    scope TEXT NOT NULL, key TEXT NOT NULL, payload TEXT NOT NULL, fetched_at TEXT NOT NULL,
                    PRIMARY KEY(scope,key)
                );
                CREATE VIRTUAL TABLE IF NOT EXISTS record_search USING fts5(id UNINDEXED, text);
                CREATE INDEX IF NOT EXISTS records_priority ON records(kev, severity, modified);
                CREATE INDEX IF NOT EXISTS evidence_source ON evidence(source_id);
            """)
        self.path.chmod(0o600)

    @contextmanager
    def connection(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _json(value):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    def _upsert(self, conn, incoming, source_id, raw):
        normalized = normalize_record(incoming)
        aliases = normalized["aliases"]
        placeholders = ",".join("?" for _ in aliases)
        rows = conn.execute(
            f"SELECT DISTINCT r.* FROM records r JOIN aliases a ON r.id=a.record_id WHERE a.alias IN ({placeholders})",
            aliases,
        ).fetchall()
        merged = {}
        watched = False
        for row in rows:
            merged = merge_records(merged, json.loads(row["payload"]))
            watched = watched or bool(row["watched"])
        merged = merge_records(merged, normalized)
        canonical = next((a for a in merged["aliases"] if a.startswith("CVE-")), normalized["id"])
        merged["id"] = canonical
        now = utcnow()
        conn.execute(
            """INSERT INTO records(id,payload,severity,kev,watched,published,modified,fetched_at)
               VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
               payload=excluded.payload,severity=excluded.severity,kev=excluded.kev,
               watched=excluded.watched,published=excluded.published,modified=excluded.modified,
               fetched_at=excluded.fetched_at""",
            (canonical, self._json(merged), merged["severity"], int(merged["kev"]), int(watched), merged["published"], merged["modified"], now),
        )
        for row in rows:
            if row["id"] != canonical:
                for evidence in conn.execute("SELECT * FROM evidence WHERE record_id=?", (row["id"],)).fetchall():
                    conn.execute(
                        "INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?)",
                        (canonical, evidence["source_id"], evidence["raw"], evidence["normalized"], evidence["fetched_at"]),
                    )
                conn.execute("DELETE FROM record_search WHERE id=?", (row["id"],))
                conn.execute("DELETE FROM records WHERE id=?", (row["id"],))
        for alias in merged["aliases"]:
            conn.execute("INSERT INTO aliases VALUES(?,?) ON CONFLICT(alias) DO UPDATE SET record_id=excluded.record_id", (alias, canonical))
        conn.execute(
            """INSERT INTO evidence VALUES(?,?,?,?,?) ON CONFLICT(record_id,source_id)
               DO UPDATE SET raw=excluded.raw,normalized=excluded.normalized,fetched_at=excluded.fetched_at""",
            (canonical, source_id, self._json(raw), self._json(normalized), now),
        )
        conn.execute("DELETE FROM record_search WHERE id=?", (canonical,))
        search_text = " ".join([merged["id"], merged["title"], merged["description"], *merged["aliases"], *merged["vendors"], *merged["products"], *merged["packages"], *merged["cwes"]])
        conn.execute("INSERT INTO record_search(id,text) VALUES(?,?)", (canonical, search_text))
        return canonical

    def upsert_record(self, record, source_id, raw=None):
        with self._lock, self.connection() as conn:
            canonical = self._upsert(conn, record, source_id, raw or {})
        return canonical

    def upsert_records(self, records, source_id):
        with self._lock, self.connection() as conn:
            for record, raw in records:
                self._upsert(conn, record, source_id, raw)
        return len(records)

    def _summary(self, conn, row):
        result = json.loads(row["payload"])
        result["source_ids"] = [item[0] for item in conn.execute("SELECT source_id FROM evidence WHERE record_id=? ORDER BY source_id", (row["id"],))]
        title = result["title"]
        if len(title) in (180, 500):
            # Tied normalized headings do not identify the source that supplied them.
            # Recover only when matching evidence agrees; genuine or unknown titles veto it.
            candidates = set()
            for item in conn.execute("SELECT source_id,raw,normalized FROM evidence WHERE record_id=?", (row["id"],)):
                if json.loads(item["normalized"]).get("title") != title:
                    continue
                if item["source_id"] not in {"cve", "circl", "nvd"}:
                    candidates.add(title)
                    continue
                raw = json.loads(item["raw"])
                payload = {"vulnerabilities": [{"cve": raw}]} if item["source_id"] == "nvd" else raw
                try:
                    observations = parse_source(item["source_id"], payload)
                except SourceError:
                    candidates.add(title)
                    continue
                candidates.update([observation["title"] for observation, _ in observations if observation["id"] in result["aliases"]] or [title])
            if len(candidates) == 1:
                candidate = next(iter(candidates))
                if candidate.startswith(title) and len(candidate) > len(title):
                    result["title"] = candidate
        result["fetched_at"] = row["fetched_at"]
        result["watched"] = bool(row["watched"])
        return result

    def list_records(self, q="", severity=None, kev=None, watched=None, source=None, limit=50, offset=0):
        clauses, params = [], []
        if q.strip():
            tokens = re.findall(r"[\w-]+", q[:300], re.UNICODE)[:20]
            if not tokens:
                return {"items": [], "total": 0, "limit": limit, "offset": offset}
            match = " AND ".join('"' + token.replace('"', '""') + '"' for token in tokens)
            clauses.append("id IN (SELECT id FROM record_search WHERE record_search MATCH ?)")
            params.append(match)
        if severity:
            clauses.append("severity=?")
            params.append(severity.upper())
        for field, value in (("kev", kev), ("watched", watched)):
            if value is not None:
                clauses.append(f"{field}=?")
                params.append(int(value))
        if source:
            clauses.append("id IN (SELECT record_id FROM evidence WHERE source_id=?)")
            params.append(source)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        limit, offset = max(1, min(int(limit), 200)), max(0, int(offset))
        with self.connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM records" + where, params).fetchone()[0]
            rows = conn.execute(
                "SELECT * FROM records" + where + " ORDER BY watched DESC, kev DESC, CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC, COALESCE(modified,published,fetched_at) DESC, id ASC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
            return {"items": [self._summary(conn, row) for row in rows], "total": total, "limit": limit, "offset": offset}

    def get_record(self, identifier):
        identifier = normalize_id(identifier)
        with self.connection() as conn:
            row = conn.execute("SELECT r.* FROM records r JOIN aliases a ON r.id=a.record_id WHERE a.alias=?", (identifier,)).fetchone()
            if not row:
                return None
            result = self._summary(conn, row)
            result["evidence"] = [
                {"source_id": item["source_id"], "fetched_at": item["fetched_at"], "raw": json.loads(item["raw"]), "record": json.loads(item["normalized"])}
                for item in conn.execute("SELECT * FROM evidence WHERE record_id=? ORDER BY source_id", (row["id"],))
            ]
            result["notes"] = [note for note in self.list_notes() if any(alias in note["links"] for alias in result["aliases"])]
            return result

    def save_note(self, note, note_id=None):
        now = utcnow()
        with self._lock, self.connection() as conn:
            existing = conn.execute("SELECT * FROM notes WHERE id=? AND deleted=0", (note_id,)).fetchone() if note_id else None
            if note_id and not existing:
                raise KeyError("Note not found.")
            if existing and note.get("revision") != existing["revision"]:
                raise ConflictError("This note changed. Reload it before saving again.")
            old = json.loads(existing["payload"]) if existing else {}
            title = str(note.get("title", old.get("title", ""))).strip()
            body = str(note.get("body", old.get("body", "")))
            if not title or len(title) > 200 or len(body) > 200000:
                raise ValueError("Provide a title up to 200 characters and a body up to 200,000 characters.")
            status = note.get("status", old.get("status", "unverified"))
            if status not in {"unverified", "in-progress", "verified"}:
                raise ValueError("Choose unverified, in-progress, or verified status.")
            tags = unique(str(tag).strip()[:60] for tag in note.get("tags", old.get("tags", [])) if str(tag).strip())[:30]
            sources = []
            for url in note.get("source_urls", old.get("source_urls", [])):
                if not safe_url(url):
                    raise ValueError("Source links must be valid HTTP or HTTPS URLs without credentials.")
                sources.append(url)
            links = unique(match.upper() for match in CVE_IN_TEXT.findall(title + " " + body))
            for link in note.get("links", []):
                links.append(normalize_id(link))
            result = {
                "id": note_id or str(uuid4()), "title": title, "body": body, "tags": tags,
                "links": unique(links)[:100], "source_urls": unique(sources)[:100], "status": status,
                "revision": old.get("revision", 0) + 1, "created_at": old.get("created_at", now), "updated_at": now,
            }
            conn.execute(
                "INSERT INTO notes(id,payload,revision,updated_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,revision=excluded.revision,updated_at=excluded.updated_at",
                (result["id"], self._json(result), result["revision"], now),
            )
            return result

    def list_notes(self, q=""):
        with self.connection() as conn:
            notes = [json.loads(row[0]) for row in conn.execute("SELECT payload FROM notes WHERE deleted=0 ORDER BY updated_at DESC,id")]
        q = q.strip().casefold()[:300]
        return [note for note in notes if not q or q in (note["title"] + " " + note["body"] + " " + " ".join(note["tags"])).casefold()]

    def get_note(self, note_id):
        with self.connection() as conn:
            row = conn.execute("SELECT payload FROM notes WHERE id=? AND deleted=0", (note_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def delete_note(self, note_id):
        with self._lock, self.connection() as conn:
            if not conn.execute("UPDATE notes SET deleted=1 WHERE id=? AND deleted=0", (note_id,)).rowcount:
                raise KeyError("Note not found.")

    def restore_note(self, note_id):
        with self._lock, self.connection() as conn:
            if not conn.execute("UPDATE notes SET deleted=0 WHERE id=? AND deleted=1", (note_id,)).rowcount:
                raise KeyError("Deleted note not found.")
        return self.get_note(note_id)

    def graph(self, focus=None, limit=35):
        if focus:
            item = self.get_record(focus)
            records = [item] if item else []
        else:
            records = self.list_records(limit=min(60, max(1, limit)))["items"]
        nodes, edges = {}, []

        def node(identifier, label, kind, **extra):
            nodes[identifier] = {"id": identifier, "label": label, "kind": kind, **extra}
            return identifier

        def edge(source, target, relation):
            edges.append({"source": source, "target": target, "relation": relation})

        alias_nodes = {}
        for record in records:
            vid = node("vuln:" + record["id"], record["id"], "vulnerability", severity=record["severity"], kev=record["kev"])
            for alias in record["aliases"]:
                alias_nodes[alias] = vid
            for field, kind, relation in (("vendors", "vendor", "affects vendor"), ("products", "product", "affects"), ("cwes", "weakness", "classified as"), ("packages", "package", "affects package"), ("source_ids", "source", "reported by")):
                for value in record.get(field, [])[:5]:
                    edge(vid, node(kind + ":" + value, value, kind), relation)
        for note in self.list_notes():
            matches = [alias_nodes[alias] for alias in note["links"] if alias in alias_nodes]
            if matches or (not focus and len(nodes) < 100):
                nid = node("note:" + note["id"], note["title"], "note", status=note["status"])
                for match in unique(matches):
                    edge(nid, match, "documents")
                for url in note.get("source_urls", [])[:5]:
                    edge(nid, node("reference:" + url, urlsplit_label(url), "reference", url=url), "cites")
        return {"nodes": list(nodes.values()), "edges": edges, "focus": focus, "limited": not focus, "record_limit": limit}

    def set_watched(self, identifier, watched):
        with self._lock, self.connection() as conn:
            changed = conn.execute("UPDATE records SET watched=? WHERE id=(SELECT record_id FROM aliases WHERE alias=?)", (int(watched), normalize_id(identifier))).rowcount
            if not changed:
                raise KeyError("Vulnerability not found.")
        return self.get_record(identifier)

    def stats(self):
        with self.connection() as conn:
            row = conn.execute("SELECT COUNT(*) total,COALESCE(SUM(kev),0) known_exploited,COALESCE(SUM(watched),0) watched,MAX(fetched_at) last_updated FROM records").fetchone()
            counts = {item[0]: item[1] for item in conn.execute("SELECT severity,COUNT(*) FROM records GROUP BY severity")}
            sources = [json.loads(item[0]) for item in conn.execute("SELECT payload FROM source_state")]
            notes = conn.execute("SELECT COUNT(*) FROM notes WHERE deleted=0").fetchone()[0]
        result = dict(row)
        result.update({"notes": notes, "critical": counts.get("CRITICAL", 0), "severity_counts": counts, "sources_cached": sum(bool(item.get("last_success")) for item in sources)})
        return result

    def set_source_state(self, source_id, **values):
        with self._lock, self.connection() as conn:
            existing = conn.execute("SELECT payload FROM source_state WHERE id=?", (source_id,)).fetchone()
            state = json.loads(existing[0]) if existing else {"id": source_id, "status": "idle", "records": 0}
            state.update(values)
            state["last_attempt"] = utcnow()
            conn.execute("INSERT INTO source_state VALUES(?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", (source_id, self._json(state)))
            return state

    def source_state(self, source_id):
        with self.connection() as conn:
            row = conn.execute("SELECT payload FROM source_state WHERE id=?", (source_id,)).fetchone()
            return json.loads(row[0]) if row else {"id": source_id, "status": "idle", "records": 0}

    def get_cache(self, scope, key):
        with self.connection() as conn:
            row = conn.execute("SELECT payload,fetched_at FROM query_cache WHERE scope=? AND key=?", (scope, key)).fetchone()
            return {"payload": json.loads(row[0]), "fetched_at": row[1]} if row else None

    def put_cache(self, scope, key, payload):
        with self._lock, self.connection() as conn:
            conn.execute("INSERT INTO query_cache VALUES(?,?,?,?) ON CONFLICT(scope,key) DO UPDATE SET payload=excluded.payload,fetched_at=excluded.fetched_at", (scope, key, self._json(payload), utcnow()))

    def export_context(self, identifier=None):
        if identifier:
            item = self.get_record(identifier)
            records = [item] if item else []
            aliases = set(item["aliases"]) if item else set()
            notes = [note for note in self.list_notes() if aliases.intersection(note["links"])]
        else:
            with self.connection() as conn:
                ids = [row[0] for row in conn.execute("SELECT id FROM records ORDER BY id LIMIT 10000")]
            records = []
            with self.connection() as conn:
                for identifier in ids:
                    row = conn.execute("SELECT * FROM records WHERE id=?", (identifier,)).fetchone()
                    record = self._summary(conn, row)
                    record["evidence"] = [
                        {"source_id": evidence["source_id"], "fetched_at": evidence["fetched_at"], "raw": json.loads(evidence["raw"]), "record": json.loads(evidence["normalized"])}
                        for evidence in conn.execute("SELECT * FROM evidence WHERE record_id=?", (identifier,))
                    ]
                    records.append(record)
            notes = self.list_notes()
        return {"schema_version": 1, "exported_at": utcnow(), "vulnerabilities": records, "notes": notes, "source_linked": True}


def urlsplit_label(url):
    from urllib.parse import urlsplit

    return urlsplit(url).hostname or url
