import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
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


def test_attest_returns_a_verifiable_ed25519_signature(monkeypatch):
    private_key = bytes(range(1, 33))
    monkeypatch.setenv("BOUNDARYCRAFT_SERVICE_TOKEN", "test-secret")
    monkeypatch.setenv(
        "BOUNDARYCRAFT_ATTESTATION_PRIVATE_KEY",
        base64.b64encode(private_key).decode("ascii"),
    )
    response = TestClient(app).post(
        "/api/attest",
        params={"token": "test-secret"},
        json={
            "action": "Transfer 20 USDC on Base",
            "claimed_authority": "treasury operator",
            "nonce": "buyer-job-42",
        },
    )
    assert response.status_code == 200
    result = response.json()
    attestation = result.pop("attestation")
    canonical_result = json.dumps(
        result,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(attestation["publicKeyBase64"])
    )
    public_key.verify(base64.b64decode(attestation["signatureBase64"]), canonical_result)
    assert result["nonce"] == "buyer-job-42"
    assert attestation["algorithm"] == "Ed25519"
    assert len(attestation["keyId"]) == 24


def test_attest_fails_closed_without_a_signing_key(monkeypatch):
    monkeypatch.setenv("BOUNDARYCRAFT_SERVICE_TOKEN", "test-secret")
    monkeypatch.delenv("BOUNDARYCRAFT_ATTESTATION_PRIVATE_KEY", raising=False)
    response = TestClient(app).post(
        "/api/attest",
        params={"token": "test-secret"},
        json={"action": "Publish a release"},
    )
    assert response.status_code == 503


def test_attestation_key_endpoint_is_public(monkeypatch):
    private_key = bytes(range(1, 33))
    monkeypatch.setenv(
        "BOUNDARYCRAFT_ATTESTATION_PRIVATE_KEY",
        base64.b64encode(private_key).decode("ascii"),
    )
    response = TestClient(app).get("/api/attestation-key")
    assert response.status_code == 200
    assert response.json()["schema"] == "boundarycraft-ed25519-attestation-v1"
