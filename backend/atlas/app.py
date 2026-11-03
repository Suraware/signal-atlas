"""Same-origin HTTP surface for cached research and intentional remote queries."""

import asyncio
import json
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .analysis import MAX_FILE, analyze_file
from .models import normalize_id, utcnow
from .security import LocalSecurityMiddleware, trusted_hosts
from .sources import SOURCES
from .store import ConflictError, Store
from .sync import IntelService


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoteInput(InputModel):
    title: str | None = Field(default=None, max_length=200)
    body: str | None = Field(default=None, max_length=200000)
    tags: list[str] | None = Field(default=None, max_length=30)
    links: list[str] | None = Field(default=None, max_length=100)
    source_urls: list[str] | None = Field(default=None, max_length=100)
    status: Literal["unverified", "in-progress", "verified"] | None = None
    revision: int | None = Field(default=None, ge=1)


class SyncInput(InputModel):
    sources: list[str] | None = Field(default=None, max_length=8)
    force: bool = False


class LookupInput(InputModel):
    identifier: str = Field(min_length=3, max_length=100)


class WatchInput(InputModel):
    watched: bool


class AuditInput(InputModel):
    format: Literal["npm", "requirements", "cyclonedx"]
    content: str = Field(max_length=200000)
    allow_network: bool = False


def create_app(data_dir, *, allowed_hosts=None, transport=None, frontend_dir=None, refresh_seconds=0):
    store = Store(data_dir)
    service = IntelService(store, transport=transport)
    tasks = set()
    sync_task = None

    @asynccontextmanager
    async def lifespan(app):
        if refresh_seconds:
            async def refresh_loop():
                while True:
                    await service.sync()
                    await asyncio.sleep(refresh_seconds)
            task = asyncio.create_task(refresh_loop())
            tasks.add(task)
        yield
        closing_tasks = list(tasks)
        for task in closing_tasks:
            task.cancel()
        for task in closing_tasks:
            with suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="Signal Atlas local research API", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.state.store = store
    app.state.intel = service
    app.add_middleware(LocalSecurityMiddleware, allowed_hosts=allowed_hosts or trusted_hosts())

    @app.exception_handler(ValueError)
    async def invalid_value(request: Request, exc: ValueError):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(ConflictError)
    async def conflict(request: Request, exc: ConflictError):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(KeyError)
    async def not_found(request: Request, exc: KeyError):
        return JSONResponse({"detail": str(exc).strip("'")}, status_code=404)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.1.0", "storage": "local", "network": "intentional public queries", "refresh_seconds": refresh_seconds}

    @app.get("/api/stats")
    def stats():
        return {**store.stats(), "sync_running": service.running, "refresh_seconds": refresh_seconds}

    @app.get("/api/vulnerabilities")
    def vulnerabilities(q: str = Query(default="", max_length=300), severity: Literal["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None, kev: bool | None = None, watched: bool | None = None, source: str | None = None, limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
        if source and source not in SOURCES:
            raise ValueError("Choose a registered source.")
        return store.list_records(q=q, severity=severity, kev=kev, watched=watched, source=source, limit=limit, offset=offset)

    @app.get("/api/vulnerabilities/{identifier}")
    def vulnerability(identifier: str):
        result = store.get_record(identifier)
        if not result:
            raise HTTPException(404, "This identifier is not cached. Use public lookup to fetch it.")
        return result

    @app.patch("/api/vulnerabilities/{identifier}/watch")
    def watch(identifier: str, data: WatchInput):
        return store.set_watched(identifier, data.watched)

    @app.post("/api/lookup")
    async def lookup(data: LookupInput):
        return await service.enrich(data.identifier)

    @app.get("/api/sources")
    def sources():
        return service.source_inventory()

    @app.get("/api/sync")
    def sync_status():
        return {**service.status(), "running": service.running or (sync_task is not None and not sync_task.done())}

    @app.post("/api/sync", status_code=202)
    async def sync(data: SyncInput):
        nonlocal sync_task
        if data.sources and any(source not in SOURCES for source in data.sources):
            raise ValueError("Choose a registered public source.")
        if service.running or (sync_task is not None and not sync_task.done()):
            return {**service.status(), "running": True}
        sync_task = asyncio.create_task(service.sync(data.sources, force=data.force))
        tasks.add(sync_task)
        sync_task.add_done_callback(tasks.discard)
        return {"running": True, "results": [], "message": "Public source refresh started. Existing cached records stay available."}

    @app.get("/api/notes")
    def notes(q: str = Query(default="", max_length=300)):
        return store.list_notes(q)

    @app.get("/api/notes/{note_id}")
    def note(note_id: str):
        result = store.get_note(note_id)
        if not result:
            raise HTTPException(404, "Note not found.")
        return result

    @app.post("/api/notes", status_code=201)
    def create_note(data: NoteInput):
        return store.save_note(data.model_dump(exclude_none=True, exclude_unset=True))

    @app.put("/api/notes/{note_id}")
    def update_note(note_id: str, data: NoteInput):
        return store.save_note(data.model_dump(exclude_none=True, exclude_unset=True), note_id)

    @app.delete("/api/notes/{note_id}")
    def delete_note(note_id: str):
        store.delete_note(note_id)
        return {"deleted": True, "restorable": True}

    @app.post("/api/notes/{note_id}/restore")
    def restore_note(note_id: str):
        return store.restore_note(note_id)

    @app.get("/api/graph")
    def graph(focus: str | None = None, limit: int = Query(default=20, ge=1, le=60)):
        if focus:
            normalize_id(focus)
        return store.graph(focus=focus, limit=limit)

    @app.post("/api/audit")
    async def audit(data: AuditInput):
        return await service.audit(data.model_dump(), data.allow_network)

    @app.post("/api/analyze")
    async def analyze(file: UploadFile = File(...)):
        try:
            content = await file.read(MAX_FILE + 1)
            if len(content) > MAX_FILE:
                raise HTTPException(413, "Files must be at most 8 MiB.")
            return await asyncio.to_thread(analyze_file, file.filename or "artifact", content)
        finally:
            await file.close()

    @app.get("/api/export")
    def export(identifier: str | None = None, format: Literal["json", "markdown"] = "json"):
        if identifier:
            normalize_id(identifier)
        context = store.export_context(identifier)
        headers = {"Content-Disposition": f'attachment; filename="signal-atlas-{utcnow()[:10]}.{ "json" if format == "json" else "md" }"'}
        if format == "json":
            return Response(json.dumps(context, ensure_ascii=False, indent=2), media_type="application/json", headers=headers)
        lines = ["# Signal Atlas research export", f"\nExported: {context['exported_at']}", "\nUnverified notes are hypotheses, not confirmed findings."]
        for record in context["vulnerabilities"]:
            lines.extend([f"\n## {record['id']}: {record['title']}", record["description"], f"\nSeverity: {record['severity']}. Known exploited: {record['kev']}."])
            lines.extend(f"- {ref['label']}: {ref['url']}" for ref in record["references"])
        for note in context["notes"]:
            lines.extend([f"\n# {note['title']}", f"\nStatus: {note['status']}; revision {note['revision']}", "\n" + note["body"]])
            lines.extend(f"- Source: {url}" for url in note.get("source_urls", []))
        return Response("\n".join(lines) + "\n", media_type="text/markdown", headers=headers)

    frontend = Path(frontend_dir) if frontend_dir else Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if (frontend / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="assets")

    @app.get("/favicon.svg", include_in_schema=False)
    def favicon():
        path = frontend / "favicon.svg"
        return FileResponse(path, media_type="image/svg+xml") if path.is_file() else Response(status_code=204)

    @app.get("/", include_in_schema=False)
    def index():
        if (frontend / "index.html").is_file():
            return FileResponse(frontend / "index.html", headers={"Cache-Control": "no-cache"})
        return JSONResponse({"detail": "Build the local interface with: npm --prefix frontend run build. The API is running."}, status_code=503)

    return app
