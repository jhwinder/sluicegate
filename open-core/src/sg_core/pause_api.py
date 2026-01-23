"""FastAPI surface for the PAUSE primitive.

This module exposes a small HTTP/API contract so agents and UIs can:
  - Inspect a pause token
  - Approve/deny a paused action
  - Wait for resolution via SSE
  - Subscribe via WebSocket

It is designed to sit *next to* SluiceGate core.

Typical usage:

    notifier = InMemoryPauseNotifier()
    gate = Gate(policy_engine=..., audit_sink=..., pause_notifier=notifier)
    app = create_pause_app(gate)

Then run with:
    uvicorn pause_api:app --reload
or mount into an existing FastAPI app.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import Body, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from starlette.responses import StreamingResponse

from .decision_loop import Gate, InMemoryPauseNotifier


def _jsonable(obj: Any) -> Any:
    """Best-effort conversion of dataclasses / nested objects to JSONable structures."""
    if hasattr(obj, "__dict__"):
        return {k: _jsonable(v) for k, v in obj.__dict__.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    return obj


def create_pause_app(gate: Gate, *, app: Optional[FastAPI] = None) -> FastAPI:
    """Create (or augment) a FastAPI app with PAUSE endpoints."""

    api = app or FastAPI(title="SluiceGate PAUSE API", version="0.1")

    # Ensure we have a notifier we can subscribe to.
    notifier: Optional[InMemoryPauseNotifier]
    if gate.pause_notifier is None:
        notifier = InMemoryPauseNotifier()
        gate.pause_notifier = notifier
    elif isinstance(gate.pause_notifier, InMemoryPauseNotifier):
        notifier = gate.pause_notifier
    else:
        notifier = None

    def _require_pause(token: str):
        rec = gate.get_pause(token)
        if not rec:
            raise HTTPException(status_code=404, detail="Unknown resume_token")
        return rec

    @api.get("/pause/{token}")
    def get_pause(token: str):
        rec = _require_pause(token)
        decision = gate.resolve_pause(token)
        return JSONResponse({"pause": _jsonable(rec), "decision": _jsonable(decision)})

    @api.get("/pause/{token}/decision")
    def get_pause_decision(token: str):
        _require_pause(token)
        decision = gate.resolve_pause(token)
        return JSONResponse(_jsonable(decision))

    @api.post("/pause/{token}/approve")
    def approve_pause(
        token: str,
        approver: str = Body(..., embed=True),
        comment: str = Body("", embed=True),
    ):
        rec = gate.approve(token, approver=approver, comment=comment)
        if not rec:
            raise HTTPException(status_code=404, detail="Unknown resume_token")
        return JSONResponse(_jsonable(rec))

    @api.post("/pause/{token}/deny")
    def deny_pause(
        token: str,
        approver: str = Body(..., embed=True),
        comment: str = Body("", embed=True),
    ):
        rec = gate.deny(token, approver=approver, comment=comment)
        if not rec:
            raise HTTPException(status_code=404, detail="Unknown resume_token")
        return JSONResponse(_jsonable(rec))

    async def _sse_stream(token: str) -> AsyncGenerator[bytes, None]:
        """Server-Sent Events stream for pause updates."""
        if notifier is None:
            raise HTTPException(status_code=500, detail="Pause notifier does not support subscriptions")

        rec = _require_pause(token)
        loop = asyncio.get_running_loop()
        q: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()

        def _on_event(payload: Dict[str, Any]) -> None:
            loop.call_soon_threadsafe(q.put_nowait, payload)

        unsubscribe = notifier.subscribe(token, _on_event)

        # Initial state
        initial = {
            "resume_token": rec.resume_token,
            "status": rec.status,
            "created_at": rec.created_at,
            "timeout_at": rec.timeout_at,
            "resolved_at": rec.resolved_at,
            "policy_hash": rec.policy_hash,
            "reason_code": rec.reason_code,
            "approver": rec.approver,
            "approver_comment": rec.approver_comment,
            "message": rec.message,
            "ts": time.time(),
        }
        yield (f"event: pause\ndata: {json.dumps(initial)}\n\n").encode("utf-8")

        try:
            while True:
                payload = await q.get()
                payload = dict(payload)
                payload.setdefault("ts", time.time())
                yield (f"event: pause\ndata: {json.dumps(payload)}\n\n").encode("utf-8")

                # If resolved, terminate stream.
                if payload.get("status") in ("APPROVED", "DENIED", "EXPIRED"):
                    break
        finally:
            try:
                unsubscribe()
            except Exception:
                pass

    @api.get("/pause/{token}/events")
    async def pause_events(token: str):
        # We validate token within the generator.
        return StreamingResponse(_sse_stream(token), media_type="text/event-stream")

    @api.websocket("/ws/pause/{token}")
    async def pause_ws(websocket: WebSocket, token: str):
        if notifier is None:
            await websocket.close(code=1011)
            return

        rec = gate.get_pause(token)
        if not rec:
            await websocket.close(code=1008)
            return

        await websocket.accept()
        loop = asyncio.get_running_loop()
        q: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()

        def _on_event(payload: Dict[str, Any]) -> None:
            loop.call_soon_threadsafe(q.put_nowait, payload)

        unsubscribe = notifier.subscribe(token, _on_event)
        try:
            # Send initial state
            await websocket.send_json({"type": "pause", "payload": _jsonable(rec)})

            while True:
                payload = await q.get()
                await websocket.send_json({"type": "pause", "payload": payload})

                if payload.get("status") in ("APPROVED", "DENIED", "EXPIRED"):
                    break
        except WebSocketDisconnect:
            pass
        finally:
            try:
                unsubscribe()
            except Exception:
                pass
            try:
                await websocket.close()
            except Exception:
                pass

    return api


# Convenience: if someone runs `uvicorn pause_api:app`, this will error unless they
# overwrite `app` with a real Gate instance. We provide a minimal placeholder.
app = FastAPI(title="SluiceGate PAUSE API (placeholder)")
