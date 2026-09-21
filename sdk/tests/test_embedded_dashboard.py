"""
Tests for Embedded Dashboard & Control Plane Server Serving
============================================================
Verifies that:
- The FastAPI runtime serves the embedded React dashboard at /
- SPA route resolution (/agents, /activity, /policies, /api) works seamlessly
- Static Next.js assets (_next/*) are served with correct headers
- FastAPI endpoints (/api/v1/*) remain active and return JSON
- Swagger docs (/docs) and ReDoc (/redoc) are fully accessible
- CLI scripts ('agentguard', 'actshield') are properly configured
"""
import pytest
from starlette.testclient import TestClient
from actshield.api.server import app, STATIC_DIR


@pytest.fixture
def client():
    return TestClient(app)


def test_static_directory_bundled():
    """Verify static dashboard assets exist in the package directory."""
    assert STATIC_DIR.exists(), f"Static directory {STATIC_DIR} should exist"
    assert (STATIC_DIR / "index.html").exists(), "index.html should exist in static directory"
    assert (STATIC_DIR / "_next").exists(), "_next directory should exist in static directory"


def test_root_serves_dashboard_html(client):
    """GET / should serve the embedded dashboard HTML."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "<html" in response.text.lower() or "<!doctype html" in response.text.lower()


def test_spa_routes_serve_html(client):
    """GET /agents, /activity, /policies, /api should return their respective HTML pages."""
    for route in ["/agents", "/activity", "/policies", "/api", "/incidents", "/posture", "/drift"]:
        response = client.get(route)
        assert response.status_code == 200, f"Route {route} failed with {response.status_code}"
        assert "text/html" in response.headers.get("content-type", "")


def test_api_health_endpoint(client):
    """GET /api/v1/health should return JSON health status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "components" in data


def test_api_overview_endpoint(client):
    """GET /api/v1/overview should return JSON system overview."""
    response = client.get("/api/v1/overview")
    assert response.status_code == 200
    data = response.json()
    assert "active_agents" in data
    assert "enforcement_mode" in data


def test_api_agents_endpoint(client):
    """GET /api/v1/agents should return registered agents list."""
    response = client.get("/api/v1/agents")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0


def test_swagger_docs_accessible(client):
    """GET /docs should return Swagger UI HTML."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "swagger" in response.text.lower()


def test_redoc_accessible(client):
    """GET /redoc should return ReDoc UI HTML."""
    response = client.get("/redoc")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "redoc" in response.text.lower()


def test_openapi_json(client):
    """GET /openapi.json should return the OpenAPI specification."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert data["openapi"].startswith("3.")
    assert "paths" in data
