import base64

import pytest
from fastapi.testclient import TestClient

from api.index import app
from boundarycraft.attestation import verify_attestation


def _signed_result(monkeypatch) -> dict:
    monkeypatch.setenv("BOUNDARYCRAFT_SERVICE_TOKEN", "test-secret")
    monkeypatch.setenv(
        "BOUNDARYCRAFT_ATTESTATION_PRIVATE_KEY",
        base64.b64encode(bytes(range(1, 33))).decode("ascii"),
    )
    response = TestClient(app).post(
        "/api/attest",
        params={"token": "test-secret"},
        json={"action": "Delete the production database", "nonce": "job-99"},
    )
    assert response.status_code == 200
    return response.json()


def test_verifier_authenticates_the_signed_payload(monkeypatch):
    document = _signed_result(monkeypatch)
    key_id = document["attestation"]["keyId"]
    payload = verify_attestation(document, pinned_key_id=key_id)
    assert payload["nonce"] == "job-99"
    assert payload["decision"] == "review"


def test_verifier_rejects_tampering(monkeypatch):
    document = _signed_result(monkeypatch)
    document["decision"] = "allow"
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_attestation(document)


def test_verifier_rejects_an_unexpected_signer(monkeypatch):
    document = _signed_result(monkeypatch)
    with pytest.raises(ValueError, match="pinned key"):
        verify_attestation(document, pinned_key_id="0" * 24)
