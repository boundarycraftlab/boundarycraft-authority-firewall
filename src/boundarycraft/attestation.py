from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALGORITHM = "Ed25519"
CANONICALIZATION = "utf8-json-sort-keys-v1"


def canonical_attestation_payload(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def verify_attestation(
    document: Mapping[str, Any],
    *,
    pinned_key_id: str | None = None,
) -> dict[str, Any]:
    """Verify a BoundaryCraft signed result and return its authenticated payload.

    The returned dictionary excludes the untrusted ``attestation`` metadata. A caller that knows
    the expected service identity should pass ``pinned_key_id`` rather than trusting an arbitrary
    public key carried inside the response.
    """

    attestation = document.get("attestation")
    if not isinstance(attestation, Mapping):
        raise ValueError("attestation metadata is missing")
    if attestation.get("algorithm") != ALGORITHM:
        raise ValueError("unsupported attestation algorithm")
    if attestation.get("canonicalization") != CANONICALIZATION:
        raise ValueError("unsupported attestation canonicalization")

    try:
        public_bytes = base64.b64decode(str(attestation["publicKeyBase64"]), validate=True)
        signature = base64.b64decode(str(attestation["signatureBase64"]), validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("attestation key or signature is invalid") from exc

    if len(public_bytes) != 32 or len(signature) != 64:
        raise ValueError("attestation key or signature has the wrong length")

    computed_key_id = hashlib.sha256(public_bytes).hexdigest()[:24]
    claimed_key_id = str(attestation.get("keyId", ""))
    if claimed_key_id != computed_key_id:
        raise ValueError("attestation key ID does not match its public key")
    if pinned_key_id is not None and computed_key_id != pinned_key_id:
        raise ValueError("attestation was not signed by the pinned key")

    payload = {key: value for key, value in document.items() if key != "attestation"}
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature,
            canonical_attestation_payload(payload),
        )
    except InvalidSignature as exc:
        raise ValueError("attestation signature verification failed") from exc
    return payload
