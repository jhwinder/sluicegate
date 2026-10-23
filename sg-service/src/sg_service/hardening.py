from __future__ import annotations

import os

DEFAULT_MAX_REQUEST_BYTES = 5 * 1024 * 1024
HSTS_VALUE = b"max-age=31536000"

_SECURITY_HEADERS = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
)


def max_request_bytes() -> int:
    raw = os.environ.get("SG_MAX_REQUEST_BYTES", "").strip()
    return int(raw) if raw else DEFAULT_MAX_REQUEST_BYTES


class _TooLarge(Exception):
    pass


class HardeningMiddleware:
    """Rejects oversized request bodies and adds security headers (HSTS only on HTTPS)."""

    def __init__(self, app, max_bytes: int | None = None):
        self.app = app
        self.max_bytes = max_bytes if max_bytes is not None else max_request_bytes()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(scope, send)
            return

        received = 0
        response_started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _TooLarge()
            return message

        async def secured_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in _SECURITY_HEADERS:
                    if name not in present:
                        headers.append((name, value))
                if scope.get("scheme") == "https":
                    headers.append((b"strict-transport-security", HSTS_VALUE))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, limited_receive, secured_send)
        except _TooLarge:
            if response_started:
                raise
            await self._reject(scope, send)

    async def _reject(self, scope, send):
        body = b'{"detail":"Request body too large"}'
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"connection", b"close")]
        headers += list(_SECURITY_HEADERS)
        if scope.get("scheme") == "https":
            headers.append((b"strict-transport-security", HSTS_VALUE))
        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": body})
