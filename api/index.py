from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from boundarycraft.classifier import RiskClassifier  # noqa: E402

POLICY_VERSION = "boundarycraft-authority-v1"


class ReviewInput(BaseModel):
    action: str = Field(min_length=1, max_length=6000)
    context: str | None = Field(default=None, max_length=3000)
    claimed_authority: str | None = Field(default=None, max_length=1000)


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
    }


@app.post("/api/review")
def review(payload: ReviewInput, token: str = Query(default="")) -> dict[str, object]:
    expected_token = os.getenv("BOUNDARYCRAFT_SERVICE_TOKEN", "")
    if not expected_token:
        raise HTTPException(status_code=503, detail="service token is not configured")
    if not token or not hmac.compare_digest(token, expected_token):
        raise HTTPException(status_code=401, detail="invalid service token")

    review_text = payload.action
    if payload.context:
        review_text += f"\nContext: {payload.context}"
    if payload.claimed_authority:
        review_text += f"\nClaimed authority: {payload.claimed_authority}"

    assessment = RiskClassifier.from_env().assess(review_text)
    issued_at = datetime.now(timezone.utc).isoformat()
    request_hash = hashlib.sha256(review_text.encode("utf-8")).hexdigest()
    receipt_body = {
        "decision": assessment.decision.value,
        "score": assessment.score,
        "summary": assessment.summary,
        "reasons": list(assessment.reasons),
        "source": assessment.source,
        "policyVersion": POLICY_VERSION,
        "requestSha256": request_hash,
        "issuedAt": issued_at,
    }
    canonical_receipt = json.dumps(
        receipt_body,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return {
        **receipt_body,
        "receiptSha256": hashlib.sha256(canonical_receipt.encode("utf-8")).hexdigest(),
    }
