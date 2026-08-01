from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from boundarycraft.classifier import RiskClassifier  # noqa: E402
from boundarycraft.payment_proof import (  # noqa: E402
    PaymentProofRpcError,
    verify_base_usdc_payment,
)
from boundarycraft.threat_model import build_threat_model  # noqa: E402

POLICY_VERSION = "boundarycraft-authority-v1"
ATTESTATION_SCHEMA = "boundarycraft-ed25519-attestation-v1"
CANONICALIZATION = "utf8-json-sort-keys-v1"


class ReviewInput(BaseModel):
    action: str = Field(min_length=1, max_length=6000)
    context: str | None = Field(default=None, max_length=3000)
    claimed_authority: str | None = Field(default=None, max_length=1000)
    nonce: str | None = Field(default=None, min_length=1, max_length=128)


class ThreatModelInput(ReviewInput):
    workflow_name: str = Field(min_length=1, max_length=200)
    assets: list[str] = Field(default_factory=list, max_length=20)
    trust_boundaries: list[str] = Field(default_factory=list, max_length=20)
    controls_present: list[str] = Field(default_factory=list, max_length=20)


class PaymentProofInput(BaseModel):
    tx_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    expected_recipient: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    expected_amount_usdc: Decimal = Field(gt=0)
    min_confirmations: int = Field(default=1, ge=0, le=100)
    nonce: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("expected_amount_usdc")
    @classmethod
    def amount_has_native_usdc_precision(cls, value: Decimal) -> Decimal:
        scaled = value * Decimal(1_000_000)
        if scaled != scaled.to_integral_value():
            raise ValueError("expected_amount_usdc supports at most 6 decimal places")
        return value


app = FastAPI(
    title="BoundaryCraft Authority Firewall",
    version="0.1.0",
    description="Deterministic authority-risk reviews for AI-agent actions.",
)


@app.get("/api")
def health() -> dict[str, str]:
    return {
        "service": "BoundaryCraft Authority Firewall",
        "status": "ok",
        "policyVersion": POLICY_VERSION,
        "attestationSchema": ATTESTATION_SCHEMA,
    }


def _require_service_token(token: str) -> None:
    expected_token = os.getenv("BOUNDARYCRAFT_SERVICE_TOKEN", "")
    if not expected_token:
        raise HTTPException(status_code=503, detail="service token is not configured")
    if not token or not hmac.compare_digest(token, expected_token):
        raise HTTPException(status_code=401, detail="invalid service token")


def _canonical_json(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _attestation_key(*, required: bool) -> Ed25519PrivateKey | None:
    encoded_key = os.getenv("BOUNDARYCRAFT_ATTESTATION_PRIVATE_KEY", "")
    if not encoded_key:
        if required:
            raise HTTPException(status_code=503, detail="attestation key is not configured")
        return None
    try:
        raw_key = base64.b64decode(encoded_key, validate=True)
        if len(raw_key) != 32:
            raise ValueError("Ed25519 private keys must contain 32 raw bytes")
        return Ed25519PrivateKey.from_private_bytes(raw_key)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=503, detail="attestation key is invalid") from exc


def _public_key_record(private_key: Ed25519PrivateKey) -> dict[str, str]:
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "algorithm": "Ed25519",
        "canonicalization": CANONICALIZATION,
        "keyId": hashlib.sha256(public_bytes).hexdigest()[:24],
        "publicKeyBase64": base64.b64encode(public_bytes).decode("ascii"),
        "schema": ATTESTATION_SCHEMA,
    }


def _build_review(payload: ReviewInput) -> dict[str, object]:
    review_text = payload.action
    if payload.context:
        review_text += f"\nContext: {payload.context}"
    if payload.claimed_authority:
        review_text += f"\nClaimed authority: {payload.claimed_authority}"

    assessment = RiskClassifier.from_env().assess(review_text)
    issued_at = datetime.now(timezone.utc).isoformat()
    request_body: dict[str, object] = {
        "action": payload.action,
        "claimedAuthority": payload.claimed_authority,
        "context": payload.context,
        "nonce": payload.nonce,
    }
    request_hash = hashlib.sha256(_canonical_json(request_body).encode("utf-8")).hexdigest()
    receipt_body = {
        "decision": assessment.decision.value,
        "issuedAt": issued_at,
        "nonce": payload.nonce,
        "policyVersion": POLICY_VERSION,
        "reasons": list(assessment.reasons),
        "requestSha256": request_hash,
        "score": assessment.score,
        "schema": ATTESTATION_SCHEMA,
        "source": assessment.source,
        "summary": assessment.summary,
    }
    return {
        **receipt_body,
        "receiptSha256": hashlib.sha256(_canonical_json(receipt_body).encode("utf-8")).hexdigest(),
    }


def _sign_document(document: dict[str, object]) -> dict[str, object]:
    private_key = _attestation_key(required=True)
    assert private_key is not None
    signature = private_key.sign(_canonical_json(document).encode("utf-8"))
    return {
        **document,
        "attestation": {
            **_public_key_record(private_key),
            "signatureBase64": base64.b64encode(signature).decode("ascii"),
        },
    }


@app.get("/api/attestation-key")
def attestation_key() -> dict[str, str]:
    private_key = _attestation_key(required=True)
    assert private_key is not None
    return _public_key_record(private_key)


@app.post("/api/review")
def review(payload: ReviewInput, token: str = Query(default="")) -> dict[str, object]:
    _require_service_token(token)
    return _build_review(payload)


@app.post("/api/attest")
def attest(payload: ReviewInput, token: str = Query(default="")) -> dict[str, object]:
    _require_service_token(token)
    return _sign_document(_build_review(payload))


@app.post("/api/threat-model")
def threat_model(payload: ThreatModelInput, token: str = Query(default="")) -> dict[str, object]:
    _require_service_token(token)
    review_text = payload.action
    if payload.context:
        review_text += f"\nContext: {payload.context}"
    if payload.claimed_authority:
        review_text += f"\nClaimed authority: {payload.claimed_authority}"
    assessment = RiskClassifier.from_env().assess(review_text)
    result = build_threat_model(
        workflow_name=payload.workflow_name,
        action=payload.action,
        context=payload.context,
        claimed_authority=payload.claimed_authority,
        assets=payload.assets,
        trust_boundaries=payload.trust_boundaries,
        controls_present=payload.controls_present,
        nonce=payload.nonce,
        assessment=assessment,
        issued_at=datetime.now(timezone.utc).isoformat(),
        policy_version=POLICY_VERSION,
    )
    return _sign_document(result)


@app.post("/api/payment-proof")
def payment_proof(payload: PaymentProofInput, token: str = Query(default="")) -> dict[str, object]:
    _require_service_token(token)
    try:
        result = verify_base_usdc_payment(
            tx_hash=payload.tx_hash,
            expected_recipient=payload.expected_recipient,
            expected_amount_raw=int(payload.expected_amount_usdc * Decimal(1_000_000)),
            min_confirmations=payload.min_confirmations,
            nonce=payload.nonce,
            issued_at=datetime.now(timezone.utc).isoformat(),
            rpc_url=os.getenv("BOUNDARYCRAFT_BASE_RPC_URL", "https://mainnet.base.org"),
        )
    except PaymentProofRpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return _sign_document(result)
