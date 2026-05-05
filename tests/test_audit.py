"""11.4 Integration tests for audit middleware."""

import asyncio
import uuid
from datetime import datetime

import pytest
from fastapi import FastAPI, Request


from app.platform.auth.audit import AuditMiddleware
from app.platform.auth.models import ApiKeyContext, AuditLog


class MockRepo:
    """Minimal stub for audit log capture."""

    def __init__(self):
        self.entries = []

    async def write_audit_log(self, entry: AuditLog) -> None:
        self.entries.append(entry)


def _make_audit_app(repo=None, enabled=True):
    app = FastAPI()

    _repo = repo or MockRepo()

    def _get_repo():
        return _repo

    app.add_middleware(AuditMiddleware, get_repo=_get_repo, enabled=enabled)

    @app.get("/v1/chat/completions")
    async def chat():
        return {"choices": []}

    @app.get("/v1/models")
    async def models():
        return {"data": []}

    @app.get("/webui/chat")
    async def webui():
        return {"message": "hello"}

    return app, _repo


# We need async test client for ASGI middleware
from starlette.testclient import TestClient


class TestAuditMiddleware:
    def test_captures_v1_request(self):
        repo = MockRepo()
        app, repo = _make_audit_app(repo=repo)
        client = TestClient(app)

        client.get("/v1/chat/completions")

        import time
        time.sleep(0.05)

        assert len(repo.entries) >= 1
        entry = repo.entries[0]
        assert entry.endpoint == "/v1/chat/completions"
        assert entry.method == "GET"
        assert entry.status_code == 200

    def test_skips_non_v1_paths(self):
        repo = MockRepo()
        app, repo = _make_audit_app(repo=repo)
        client = TestClient(app)

        client.get("/webui/chat")

        import time
        time.sleep(0.05)

        assert len(repo.entries) == 0

    def test_disabled_middleware_skips(self):
        repo = MockRepo()
        app, repo = _make_audit_app(repo=repo, enabled=False)
        client = TestClient(app)

        client.get("/v1/chat/completions")

        import time
        time.sleep(0.05)

        assert len(repo.entries) == 0

    def test_middleware_does_not_block_response(self):
        """Even if repo is broken, response still returns."""
        app = FastAPI()
        app.add_middleware(AuditMiddleware, get_repo=lambda: None, enabled=True)

        @app.get("/v1/test")
        async def test():
            return {"ok": True}

        client = TestClient(app)
        resp = client.get("/v1/test")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
