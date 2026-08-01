# BoundaryCraft Authority Firewall

**The AI agent whose most important capability is knowing when it is not authorized.**

BoundaryCraft sits between a human request and an autonomous agent. It classifies the
authority risk of each request, blocks forbidden actions, and requires risky actions to be
confirmed from a *different* communication channel. A request sent by email can be approved
from Slack, but never from that same email thread.

Every terminal decision creates a SHA-256 receipt linked to the previous receipt. That makes
the audit trail tamper-evident and gives downstream agents a small, verifiable authorization
artifact instead of a vague “the user said yes.”

## Why two channels matter

Most multi-channel demos copy the same chatbot into two places. BoundaryCraft gives the second
channel a security role:

1. Send `Deploy release 42 to production` to the agent's Caspian email.
2. The single handler classifies it as risky and returns `REVIEW REQUIRED · BC-12AB34`.
3. Replying `APPROVE BC-12AB34` by email is rejected.
4. Post the same approval through the connected Slack channel.
5. BoundaryCraft records the cross-channel quorum and returns a chained receipt hash.

Email and Slack messages enter through the same `@client.on_message` handler. Caspian owns
the channel-specific transport, threading, webhook validation, and reply path.

## Safety model

- A deterministic guardrail always runs first and cannot be weakened by the model.
- Forbidden requests—credential theft, security bypass, or audit destruction—are denied.
- Reversible read-only requests may be allowed immediately.
- Side effects involving production, deletion, money, publication, or access require review.
- Ambiguous requests fail closed.
- If `FEATHERLESS_API_KEY` is configured, Featherless AI adds a semantic risk assessment.
- The one-time decision is immutable, persisted in SQLite, and chained to prior receipts.

The firewall issues authorization receipts; it does **not** execute the requested side effect.
That separation is deliberate: an executor can require a valid receipt before it acts.

## Quick start

Requirements: Python 3.10+ and a Caspian project key.

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"      # Windows
cp .env.example .env                       # then add Caspian credentials
boundarycraft-setup                        # provisions email + Slack OAuth URL
boundarycraft                              # one handler, every connected channel
```

The Caspian CLI can mint a sandbox key without a signup:

```bash
pip install caspian-cli
caspian init
```

The setup command creates an instant Caspian email address and prints the official Slack OAuth
URL. Authorize it for the demo workspace, run setup again to verify both connections, then
start the listener.

## Paid HTTP review endpoint

The repository also exposes a stateless FastAPI service for metered marketplace calls:

- `GET /api` reports service health and policy version.
- `POST /api/review?token=...` accepts `action`, optional `context`, and optional
  `claimed_authority` and `nonce` fields.
- `POST /api/attest?token=...` returns the same review plus an Ed25519 signature.
- `POST /api/threat-model?token=...` returns a signed, structured authority threat model for
  one workflow, including prioritized abuse cases, required controls, and verification tests.
- `POST /api/payment-proof?token=...` verifies one exact native-USDC `Transfer` on Base using
  the official contract, expected recipient, amount, successful receipt, and confirmations.
- `GET /api/attestation-key` publishes the stable verification key and key ID.
- Each successful review returns the decision, risk score, reasons, a SHA-256 request digest,
  and a SHA-256 receipt digest. The original action is not written to persistent storage.

Set `BOUNDARYCRAFT_SERVICE_TOKEN` in the deployment environment. The paid marketplace keeps the
full endpoint query private and proxies the buyer's JSON only after USDC settlement.

For signed attestations, set `BOUNDARYCRAFT_ATTESTATION_PRIVATE_KEY` to the Base64 encoding of a
raw 32-byte Ed25519 private key. The signature covers the UTF-8 JSON result without the
`attestation` member, serialized with sorted keys and compact separators. Consumers should pin
the `keyId` returned by `/api/attestation-key`; the private key never leaves the service.

The threat-model endpoint accepts `workflow_name`, `action`, and optional `context`,
`claimed_authority`, `assets`, `trust_boundaries`, `controls_present`, and `nonce`. Its output is
deterministic rules-based analysis of authorization, tampering, replay, state-change, payment,
deployment, destructive, publication, and access risks that apply to the submitted workflow. It
does not claim to be an exhaustive security audit, penetration test, or certification.

The payment-proof endpoint accepts `tx_hash`, `expected_recipient`, `expected_amount_usdc`,
optional `min_confirmations`, and optional `nonce`. It fails closed unless the RPC reports Base
chain ID 8453, the transaction succeeded, the native USDC contract emitted an exact matching
`Transfer`, and the requested confirmation count is satisfied. The signed result distinguishes
native Base USDC from ETH, bridged tokens, other contracts, other recipients, and pending or
failed transactions.

The package includes a verifier that authenticates the payload and rejects a substituted key:

```python
from boundarycraft.attestation import verify_attestation

verified = verify_attestation(result, pinned_key_id="5b5be3887dfe192f6bb2247e")
```

## Configuration

| Variable | Purpose |
| --- | --- |
| `CASPIAN_API_KEY` | Caspian project key |
| `CASPIAN_BASE_URL` | Caspian gateway; defaults to the hosted API |
| `BOUNDARYCRAFT_EMAIL_USERNAME` | Requested agent inbox name |
| `BOUNDARYCRAFT_DB` | SQLite state and receipt-chain path |
| `BOUNDARYCRAFT_SERVICE_TOKEN` | Private token for the metered HTTP endpoint |
| `BOUNDARYCRAFT_ATTESTATION_PRIVATE_KEY` | Base64 raw Ed25519 signing key for portable attestations |
| `BOUNDARYCRAFT_BASE_RPC_URL` | Optional Base mainnet JSON-RPC endpoint for payment proofs |
| `FEATHERLESS_API_KEY` | Optional semantic classifier |
| `FEATHERLESS_MODEL` | Featherless chat model ID |

No API key is committed. `.env`, databases, and generated receipt files are ignored.

## Test

```bash
pytest
ruff check .
```

The tests cover cross-channel rejection, quorum approval, immutable decisions, deterministic
guardrails, automatic terminal decisions, and receipt-chain verification without network calls.

## Architecture

```text
Email ─────┐
           ├─ Caspian ─ one on_message handler ─ guardrail + Featherless
Slack ─────┘                                    │
                                                ├─ pending cross-channel quorum
                                                └─ SQLite + chained SHA-256 receipts
```

## Commands

- Send natural-language text to open an authority request.
- `APPROVE BC-XXXXXX` — approve a pending request from a different channel.
- `DENY BC-XXXXXX` — deny a pending request from a different channel.
- `STATUS BC-XXXXXX` — show the immutable current state and receipt, if decided.

## Hackathon compliance

- New code written during the Caspian Buildathon window.
- Uses `caspian-sdk` directly.
- One handler serves at least two real channels.
- Public repository and a live, unmocked two-channel demo are planned for final submission.
- AI coding assistants are allowed by the published rules.

## License

MIT
