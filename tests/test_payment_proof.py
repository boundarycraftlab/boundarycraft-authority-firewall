import base64

import httpx
from fastapi.testclient import TestClient

from api.index import app
from boundarycraft.attestation import verify_attestation
from boundarycraft.payment_proof import NATIVE_USDC_CONTRACT, TRANSFER_TOPIC

RECIPIENT = "0x11655B2d3012D5590278E20c9b119E687a26db79"
TX_HASH = "0x" + "a" * 64


class FakeRpcResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self.payload


def _topic(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


def _mock_rpc(monkeypatch, *, transfer_amount: int = 20_000_000) -> None:
    receipt = {
        "blockNumber": "0x64",
        "status": "0x1",
        "transactionHash": TX_HASH,
        "logs": [
            {
                "address": NATIVE_USDC_CONTRACT,
                "data": hex(transfer_amount),
                "logIndex": "0x3",
                "topics": [
                    TRANSFER_TOPIC,
                    _topic("0x00000000000000000000000000000000000000ab"),
                    _topic(RECIPIENT),
                ],
            }
        ],
    }
    results = {
        "eth_chainId": "0x2105",
        "eth_blockNumber": "0x68",
        "eth_getTransactionReceipt": receipt,
    }

    def fake_post(url, *, json, timeout):
        assert url == "https://mainnet.base.org"
        assert timeout == 12
        return FakeRpcResponse({"jsonrpc": "2.0", "id": 1, "result": results[json["method"]]})

    monkeypatch.setattr("boundarycraft.payment_proof.httpx.post", fake_post)


def _configure(monkeypatch) -> None:
    monkeypatch.setenv("BOUNDARYCRAFT_SERVICE_TOKEN", "test-secret")
    monkeypatch.setenv(
        "BOUNDARYCRAFT_ATTESTATION_PRIVATE_KEY",
        base64.b64encode(bytes(range(1, 33))).decode("ascii"),
    )


def test_payment_proof_verifies_exact_native_base_usdc_transfer(monkeypatch):
    _configure(monkeypatch)
    _mock_rpc(monkeypatch)
    response = TestClient(app).post(
        "/api/payment-proof",
        params={"token": "test-secret"},
        json={
            "tx_hash": TX_HASH,
            "expected_recipient": RECIPIENT,
            "expected_amount_usdc": "20",
            "min_confirmations": 3,
            "nonce": "invoice-42",
        },
    )
    assert response.status_code == 200
    document = response.json()
    verified = verify_attestation(document, pinned_key_id=document["attestation"]["keyId"])
    assert verified["schema"] == "boundarycraft-base-usdc-payment-proof-v1"
    assert verified["decision"] == "verified"
    assert verified["confirmations"] == 5
    assert verified["checks"]["exactNativeUsdcTransferFound"] is True
    assert verified["transferMatches"][0]["amountUsdc"] == "20"
    assert verified["request"]["nonce"] == "invoice-42"


def test_payment_proof_rejects_a_different_amount(monkeypatch):
    _configure(monkeypatch)
    _mock_rpc(monkeypatch, transfer_amount=19_000_000)
    response = TestClient(app).post(
        "/api/payment-proof",
        params={"token": "test-secret"},
        json={
            "tx_hash": TX_HASH,
            "expected_recipient": RECIPIENT,
            "expected_amount_usdc": "20",
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "not_verified"
    assert response.json()["transferMatches"] == []


def test_payment_proof_rejects_fraction_beyond_usdc_precision(monkeypatch):
    _configure(monkeypatch)
    response = TestClient(app).post(
        "/api/payment-proof",
        params={"token": "test-secret"},
        json={
            "tx_hash": TX_HASH,
            "expected_recipient": RECIPIENT,
            "expected_amount_usdc": "0.0000001",
        },
    )
    assert response.status_code == 422


def test_payment_proof_maps_rpc_failure_to_bad_gateway(monkeypatch):
    _configure(monkeypatch)

    def fail_post(url, *, json, timeout):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr("boundarycraft.payment_proof.httpx.post", fail_post)
    response = TestClient(app).post(
        "/api/payment-proof",
        params={"token": "test-secret"},
        json={
            "tx_hash": TX_HASH,
            "expected_recipient": RECIPIENT,
            "expected_amount_usdc": "20",
        },
    )
    assert response.status_code == 502
    assert response.json()["detail"] == "Base RPC request failed"
