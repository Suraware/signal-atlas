"""Trusted-host, same-origin, and streaming body limits for local/LAN use."""

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from starlette.responses import JSONResponse

MAX_BODY = 9 * 1024 * 1024


def lan_addresses():
    values = set()
    try:
        values.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # A UDP connect selects the local route; no packet is transmitted.
            sock.connect(("192.0.2.1", 9))
            values.add(sock.getsockname()[0])
    except OSError:
        pass
    return sorted(value for value in values if ipaddress.ip_address(value).is_private and not ipaddress.ip_address(value).is_loopback)


def trusted_hosts():
    return {"localhost", "127.0.0.1", "::1", socket.gethostname().lower(), *lan_addresses()}


class BodyTooLarge(Exception):
    pass


class LocalSecurityMiddleware:
    def __init__(self, app, allowed_hosts):
        self.app = app
        self.allowed_hosts = {host.lower().strip("[]") for host in allowed_hosts}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {key.decode("latin1").lower(): value.decode("latin1") for key, value in scope.get("headers", [])}
        host = headers.get("host", "")
        try:
            host_parts = urlsplit("http://" + host)
            hostname = host_parts.hostname
            if host_parts.username or host_parts.password or host_parts.path or host_parts.query or hostname not in self.allowed_hosts:
                raise ValueError
            host_parts.port
        except ValueError:
            return await JSONResponse({"detail": "This host is not allowed. Use the server's localhost or displayed LAN address."}, status_code=400)(scope, receive, send)
        origin = headers.get("origin")
        if headers.get("sec-fetch-site") == "cross-site" or (origin is not None and origin.rstrip("/") != scope.get("scheme", "http") + "://" + host):
            return await JSONResponse({"detail": "Foreign-origin requests cannot access this local research workspace."}, status_code=403)(scope, receive, send)
        try:
            size = int(headers.get("content-length", "0"))
            if size > MAX_BODY or size < 0:
                raise BodyTooLarge
        except (ValueError, BodyTooLarge):
            return await JSONResponse({"detail": "Request body exceeds the 9 MiB limit."}, status_code=413)(scope, receive, send)
        application_receive = receive
        if scope["method"] in {"POST", "PUT", "PATCH"}:
            body = bytearray()
            try:
                async with asyncio.timeout(30):
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return
                        chunk = message.get("body", b"")
                        if len(body) + len(chunk) > MAX_BODY:
                            raise BodyTooLarge
                        body.extend(chunk)
                        if not message.get("more_body", False):
                            break
            except BodyTooLarge:
                return await JSONResponse({"detail": "Request body exceeds the 9 MiB limit."}, status_code=413)(scope, receive, send)
            except TimeoutError:
                return await JSONResponse({"detail": "Upload timed out. Try a smaller file on a stable local connection."}, status_code=408)(scope, receive, send)
            consumed = False

            async def replay_receive():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            application_receive = replay_receive

        async def secure_send(message):
            if message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers.extend([
                    (b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
                ])
                if scope["path"].startswith("/api/"):
                    response_headers.append((b"cache-control", b"no-store"))
                message["headers"] = response_headers
            await send(message)

        await self.app(scope, application_receive, secure_send)
