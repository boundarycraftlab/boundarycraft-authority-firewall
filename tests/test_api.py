from fastapi.testclient import TestClient

from api.index import app


def test_health_is_public():
    response = TestClient(app).get("/api")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_review_requires_service_token(monkeypatch):
    monkeypatch.setenv("BOUNDARYCRAFT_SERVICE_TOKEN", "test-secret")
    response = TestClient(app).post(
        "/api/review",
        params={"token": "wrong"},
        json={"action": "Summarize this file without changing it"},
    )
    assert response.status_code == 401


def test_review_returns_a_hashed_receipt(monkeypatch):
    monkeypatch.setenv("BOUNDARYCRAFT_SERVICE_TOKEN", "test-secret")
    response = TestClient(app).post(
        "/api/review",
        params={"token": "test-secret"},
        json={"action": "Deploy release 42 to production"},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["decision"] == "review"
    assert result["score"] >= 60
    assert len(result["requestSha256"]) == 64
    assert len(result["receiptSha256"]) == 64
