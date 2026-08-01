from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any

import httpx

BASE_CHAIN_ID = 8453
BASE_RPC_URL = "https://mainnet.base.org"
NATIVE_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
PAYMENT_PROOF_SCHEMA = "boundarycraft-base-usdc-payment-proof-v1"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
USDC_DECIMALS = 6


class PaymentProofRpcError(RuntimeError):
    pass


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _rpc(method: str, params: list[Any], *, rpc_url: str) -> Any:
    try:
        response = httpx.post(
            rpc_url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            timeout=12,
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise PaymentProofRpcError("Base RPC request failed") from exc
    if not isinstance(payload, dict) or payload.get("error") is not None:
        raise PaymentProofRpcError("Base RPC returned an error")
    if "result" not in payload:
        raise PaymentProofRpcError("Base RPC response is missing its result")
    return payload["result"]


def _hex_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 16)
    except (TypeError, ValueError) as exc:
        raise PaymentProofRpcError("Base RPC returned malformed hexadecimal data") from exc


def _topic_address(topic: str) -> str:
    if not isinstance(topic, str) or not topic.startswith("0x") or len(topic) != 66:
        raise PaymentProofRpcError("Base RPC returned a malformed address topic")
    return "0x" + topic[-40:].lower()


def _format_usdc(raw_amount: int) -> str:
    value = Decimal(raw_amount) / Decimal(10**USDC_DECIMALS)
    formatted = format(value, "f")
    return formatted.rstrip("0").rstrip(".") if "." in formatted else formatted


def verify_base_usdc_payment(
    *,
    tx_hash: str,
    expected_recipient: str,
    expected_amount_raw: int,
    min_confirmations: int,
    nonce: str | None,
    issued_at: str,
    rpc_url: str = BASE_RPC_URL,
) -> dict[str, Any]:
    """Verify one exact native-USDC Transfer event on Base mainnet."""

    chain_id = _hex_int(_rpc("eth_chainId", [], rpc_url=rpc_url))
    latest_block = _hex_int(_rpc("eth_blockNumber", [], rpc_url=rpc_url))
    receipt = _rpc("eth_getTransactionReceipt", [tx_hash], rpc_url=rpc_url)

    request = {
        "expectedAmountRaw": str(expected_amount_raw),
        "expectedAmountUsdc": _format_usdc(expected_amount_raw),
        "expectedRecipient": expected_recipient.lower(),
        "minConfirmations": min_confirmations,
        "nonce": nonce,
        "transactionHash": tx_hash.lower(),
    }
    request_hash = hashlib.sha256(_canonical_json(request).encode("utf-8")).hexdigest()

    receipt_status: int | None = None
    receipt_block: int | None = None
    confirmations = 0
    matches: list[dict[str, str]] = []
    if isinstance(receipt, dict):
        receipt_status = _hex_int(receipt.get("status"))
        receipt_block = _hex_int(receipt.get("blockNumber"))
        if receipt_block is not None and latest_block is not None and latest_block >= receipt_block:
            confirmations = latest_block - receipt_block + 1

        for log in receipt.get("logs", []):
            if not isinstance(log, dict):
                continue
            topics = log.get("topics")
            if (
                str(log.get("address", "")).lower() != NATIVE_USDC_CONTRACT.lower()
                or not isinstance(topics, list)
                or len(topics) < 3
                or str(topics[0]).lower() != TRANSFER_TOPIC
            ):
                continue
            recipient = _topic_address(topics[2])
            raw_amount = _hex_int(log.get("data"))
            if raw_amount is None:
                continue
            if recipient == expected_recipient.lower() and raw_amount == expected_amount_raw:
                matches.append(
                    {
                        "amountRaw": str(raw_amount),
                        "amountUsdc": _format_usdc(raw_amount),
                        "from": _topic_address(topics[1]),
                        "logIndex": str(_hex_int(log.get("logIndex")) or 0),
                        "to": recipient,
                    }
                )

    checks = {
        "baseMainnetChainId": chain_id == BASE_CHAIN_ID,
        "confirmationsSatisfied": confirmations >= min_confirmations,
        "exactNativeUsdcTransferFound": bool(matches),
        "transactionSucceeded": receipt_status == 1,
    }
    verified = all(checks.values())
    reasons: list[str] = []
    if receipt is None:
        reasons.append("Transaction receipt was not found or is still pending.")
    if chain_id != BASE_CHAIN_ID:
        reasons.append("RPC chain ID is not Base mainnet (8453).")
    if receipt_status is not None and receipt_status != 1:
        reasons.append("Transaction receipt status is not successful.")
    if not matches:
        reasons.append("No exact native-USDC Transfer matched recipient and amount.")
    if confirmations < min_confirmations:
        reasons.append("Transaction does not yet meet the requested confirmation count.")

    proof_body: dict[str, Any] = {
        "chainId": chain_id,
        "checks": checks,
        "confirmations": confirmations,
        "decision": "verified" if verified else "not_verified",
        "issuedAt": issued_at,
        "latestBlockNumber": latest_block,
        "nativeUsdcContract": NATIVE_USDC_CONTRACT,
        "nonce": nonce,
        "reasons": reasons,
        "receiptBlockNumber": receipt_block,
        "receiptStatus": receipt_status,
        "request": request,
        "requestSha256": request_hash,
        "schema": PAYMENT_PROOF_SCHEMA,
        "transferMatches": matches,
    }
    return {
        **proof_body,
        "receiptSha256": hashlib.sha256(_canonical_json(proof_body).encode("utf-8")).hexdigest(),
    }
