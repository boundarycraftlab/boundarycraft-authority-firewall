from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from .models import RiskAssessment

THREAT_MODEL_SCHEMA = "boundarycraft-authority-threat-model-v1"

_CLASS_PATTERNS: dict[str, tuple[str, ...]] = {
    "financial": (
        "pay ",
        "payment",
        "transfer",
        "send funds",
        "purchase",
        "wallet",
        "usdc",
        "crypto",
    ),
    "production": ("deploy", "production", "prod ", "release", "infrastructure"),
    "destructive": ("delete", "drop database", "destroy", "remove all", "overwrite"),
    "publication": ("publish", "post publicly", "send email", "announce", "message"),
    "access": (
        "grant access",
        "revoke access",
        "rotate key",
        "change password",
        "permission",
        "credential",
        "secret",
    ),
}

_SCENARIOS: dict[str, tuple[dict[str, str], ...]] = {
    "generic": (
        {
            "id": "AUTH-01",
            "title": "Spoofed or insufficient authority",
            "severity": "high",
            "attackPath": (
                "An instruction is treated as authorization even though the sender, scope, or "
                "approval channel is not independently verified."
            ),
            "requiredControl": (
                "Verify the approver identity, allowed scope, and authority through an independent "
                "channel before execution."
            ),
            "verificationTest": (
                "Submit the same request from an untrusted identity and from the originating "
                "channel; both attempts must fail closed."
            ),
        },
        {
            "id": "INT-01",
            "title": "Approval-to-execution payload tampering",
            "severity": "high",
            "attackPath": (
                "A target, amount, artifact, or parameter changes after approval but before the "
                "side effect is executed."
            ),
            "requiredControl": (
                "Bind approval to a canonical request digest and reject execution if any bound "
                "field changes."
            ),
            "verificationTest": (
                "Modify one approved field after authorization; the executor must detect a digest "
                "mismatch and stop."
            ),
        },
        {
            "id": "REPLAY-01",
            "title": "Replay or duplicate execution",
            "severity": "high",
            "attackPath": (
                "A valid approval or signed result is reused to perform the same side effect more "
                "than once."
            ),
            "requiredControl": (
                "Use a unique nonce, expiration, and atomic consumption record for every approved "
                "operation."
            ),
            "verificationTest": (
                "Replay an already consumed nonce; the second execution must be rejected without "
                "causing a side effect."
            ),
        },
        {
            "id": "TOCTOU-01",
            "title": "State changes between review and execution",
            "severity": "medium",
            "attackPath": (
                "Permissions, ownership, balances, or target state change after review, making the "
                "previous decision unsafe."
            ),
            "requiredControl": (
                "Revalidate security-critical preconditions immediately before execution and set a "
                "short approval lifetime."
            ),
            "verificationTest": (
                "Change one required precondition after approval; execution must require a fresh "
                "review."
            ),
        },
    ),
    "financial": (
        {
            "id": "PAY-01",
            "title": "Wrong network, asset, recipient, or amount",
            "severity": "critical",
            "attackPath": (
                "Ambiguous or substituted settlement fields route value to the wrong chain, token "
                "contract, address, or amount."
            ),
            "requiredControl": (
                "Require explicit chain ID, asset contract, recipient, amount, decimals, and a "
                "human-readable confirmation bound to the approval digest."
            ),
            "verificationTest": (
                "Mutate each settlement field independently; every altered request must require "
                "new authorization."
            ),
        },
        {
            "id": "PAY-02",
            "title": "False or incomplete payment evidence",
            "severity": "high",
            "attackPath": (
                "A transaction hash, wallet balance, bridged token, or pending transfer is "
                "mistaken for final settlement in the required asset."
            ),
            "requiredControl": (
                "Verify final on-chain receipt status, chain ID, token contract, transfer event, "
                "recipient, amount, and confirmations against an authoritative RPC."
            ),
            "verificationTest": (
                "Provide evidence from a wrong chain or token contract; the verifier must "
                "reject it."
            ),
        },
    ),
    "production": (
        {
            "id": "DEPLOY-01",
            "title": "Artifact or environment substitution",
            "severity": "critical",
            "attackPath": (
                "A different build, commit, image, account, region, or environment is deployed "
                "from the one that was reviewed."
            ),
            "requiredControl": (
                "Pin the artifact digest and deployment target in the approval, then verify "
                "both at deploy time."
            ),
            "verificationTest": (
                "Attempt deployment with a different artifact digest or environment; the pipeline "
                "must stop before mutation."
            ),
        },
        {
            "id": "DEPLOY-02",
            "title": "Unrecoverable failed rollout",
            "severity": "high",
            "attackPath": (
                "A faulty change reaches production without a tested rollback path, health "
                "gate, or blast-radius limit."
            ),
            "requiredControl": (
                "Use staged rollout, health checks, a tested rollback, and an explicit stop "
                "condition."
            ),
            "verificationTest": (
                "Force a canary health-check failure; rollout must halt and restore the last known "
                "good artifact."
            ),
        },
    ),
    "destructive": (
        {
            "id": "DEST-01",
            "title": "Destructive scope expansion",
            "severity": "critical",
            "attackPath": (
                "A broad selector, path, wildcard, or mistaken tenant causes deletion beyond the "
                "approved target."
            ),
            "requiredControl": (
                "Resolve and display exact targets, enforce a narrow allowlist, and require a "
                "dry run plus recoverable backup."
            ),
            "verificationTest": (
                "Add one out-of-scope target to the selector; validation must reject the complete "
                "operation."
            ),
        },
    ),
    "publication": (
        {
            "id": "PUB-01",
            "title": "Recipient or content substitution",
            "severity": "high",
            "attackPath": (
                "The destination, audience, attachment, or final content changes after human "
                "review."
            ),
            "requiredControl": (
                "Bind the exact content digest, attachment digests, audience, and delivery "
                "channel to the approval."
            ),
            "verificationTest": (
                "Change the recipient or one content byte; sending must stop pending new approval."
            ),
        },
    ),
    "access": (
        {
            "id": "ACCESS-01",
            "title": "Privilege escalation or stale authorization",
            "severity": "critical",
            "attackPath": (
                "A broader role than intended is granted, or an old approval remains valid "
                "after the requester's authority changes."
            ),
            "requiredControl": (
                "Enforce least privilege, bind the exact principal and role, set expiration, and "
                "recheck approver authority at execution."
            ),
            "verificationTest": (
                "Request a superset role or execute after approver revocation; both attempts "
                "must fail."
            ),
        },
        {
            "id": "ACCESS-02",
            "title": "Credential exposure in workflow evidence",
            "severity": "high",
            "attackPath": (
                "Secrets enter prompts, logs, receipts, error messages, or marketplace responses."
            ),
            "requiredControl": (
                "Pass secrets through a scoped secret store, redact logs, and never include raw "
                "credentials in signed artifacts."
            ),
            "verificationTest": (
                "Inject a synthetic secret into each input path; logs and outputs must contain "
                "only a redacted marker."
            ),
        },
    ),
}


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _unique(values: Sequence[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = " ".join(value.split())
        marker = cleaned.casefold()
        if cleaned and marker not in seen:
            seen.add(marker)
            result.append(cleaned)
    return result


def _risk_classes(text: str, assessment: RiskAssessment) -> list[str]:
    normalized = " ".join(text.lower().split())
    classes = [
        name
        for name, patterns in _CLASS_PATTERNS.items()
        if any(pattern in normalized for pattern in patterns)
    ]
    if "ambiguous authority" in assessment.reasons or not classes:
        classes.append("ambiguous-authority")
    return classes


def build_threat_model(
    *,
    workflow_name: str,
    action: str,
    context: str | None,
    claimed_authority: str | None,
    assets: Sequence[str],
    trust_boundaries: Sequence[str],
    controls_present: Sequence[str],
    nonce: str | None,
    assessment: RiskAssessment,
    issued_at: str,
    policy_version: str,
) -> dict[str, Any]:
    """Build a deterministic, rules-based authority threat model for one workflow."""

    normalized_assets = _unique(assets)
    normalized_boundaries = _unique(trust_boundaries)
    normalized_controls = _unique(controls_present)
    combined_text = "\n".join(
        value
        for value in (
            action,
            context,
            claimed_authority,
            " ".join(normalized_assets),
            " ".join(normalized_boundaries),
        )
        if value
    )
    classes = _risk_classes(combined_text, assessment)

    scenarios = [dict(item) for item in _SCENARIOS["generic"]]
    for risk_class in classes:
        scenarios.extend(dict(item) for item in _SCENARIOS.get(risk_class, ()))

    request = {
        "action": action,
        "assets": normalized_assets,
        "claimedAuthority": claimed_authority,
        "context": context,
        "controlsPresent": normalized_controls,
        "nonce": nonce,
        "trustBoundaries": normalized_boundaries,
        "workflowName": workflow_name,
    }
    request_hash = hashlib.sha256(_canonical_json(request).encode("utf-8")).hexdigest()
    required_controls = list(dict.fromkeys(item["requiredControl"] for item in scenarios))
    verification_tests = [
        {"scenarioId": item["id"], "test": item["verificationTest"]} for item in scenarios
    ]

    assumptions = [
        "The supplied workflow description is complete and accurate.",
        "The executor can enforce a fail-closed authorization decision before side effects.",
        "Listed controls are treated as claims until independently tested.",
    ]
    if not normalized_boundaries:
        assumptions.append(
            "Trust boundaries were not supplied; identity and execution are separate."
        )
    if not normalized_assets:
        assumptions.append("Assets were not supplied; affected data and systems require discovery.")

    receipt_body: dict[str, Any] = {
        "assessment": {
            "decision": assessment.decision.value,
            "reasons": list(assessment.reasons),
            "score": assessment.score,
            "source": assessment.source,
            "summary": assessment.summary,
        },
        "assumptions": assumptions,
        "attackScenarios": scenarios,
        "confidence": "automated-rules-based",
        "issuedAt": issued_at,
        "methodology": (
            "BoundaryCraft deterministic authority-boundary analysis; this is an automated model, "
            "not a penetration test or certification."
        ),
        "nonce": nonce,
        "policyVersion": policy_version,
        "request": request,
        "requestSha256": request_hash,
        "requiredControls": required_controls,
        "riskClasses": classes,
        "schema": THREAT_MODEL_SCHEMA,
        "verificationTests": verification_tests,
    }
    return {
        **receipt_body,
        "receiptSha256": hashlib.sha256(_canonical_json(receipt_body).encode("utf-8")).hexdigest(),
    }
