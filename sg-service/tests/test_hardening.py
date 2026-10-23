from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from sg_service.hardening import HardeningMiddleware


def make_client(max_bytes: int = 100, base_url: str = "http://testserver") -> TestClient:
    app = FastAPI()

    @app.post("/echo")
    async def echo(request: Request):
        return {"size": len(await request.body())}

    app.add_middleware(HardeningMiddleware, max_bytes=max_bytes)
    return TestClient(app, base_url=base_url)


def test_security_headers_added_without_hsts_on_http():
    response = make_client().post("/echo", content=b"x")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "strict-transport-security" not in response.headers


def test_hsts_on_https():
    response = make_client(base_url="https://testserver").post("/echo", content=b"x")
    assert response.headers["strict-transport-security"].startswith("max-age=")


def test_oversized_body_rejected_by_content_length():
    response = make_client().post("/echo", content=b"x" * 101)
    assert response.status_code == 413
    assert response.headers["x-content-type-options"] == "nosniff"


def test_oversized_chunked_body_rejected():
    def chunks():
        for _ in range(11):
            yield b"x" * 10

    response = make_client().post("/echo", content=chunks())
    assert response.status_code == 413


def test_body_at_limit_accepted():
    assert make_client().post("/echo", content=b"x" * 100).json() == {"size": 100}
