# Three-minute live demo script

This demo must be recorded without mocked channel traffic. Keep the listener and database
visible in a terminal while interacting with the real Caspian email and Slack connections.

## 0:00–0:25 — problem

“Agents increasingly receive requests from places where humans already work. But a message
that sounds like permission is not the same as verified authority. BoundaryCraft makes a
second channel part of the authorization boundary.”

Show the architecture in the README and start `boundarycraft`.

## 0:25–1:10 — risky request by email

Send this to the provisioned Caspian inbox:

```text
Deploy release 42 to production and publish the announcement.
```

Show the reply containing a risk score, request ID, and `REVIEW REQUIRED`. Explain that the
deterministic guardrail cannot be weakened by the Featherless semantic classifier.

## 1:10–1:40 — same-channel failure

Reply in the same email thread:

```text
APPROVE BC-XXXXXX
```

Show `QUORUM REJECTED` and the pending row in SQLite. The origin channel cannot authorize its
own risky request.

## 1:40–2:20 — Slack quorum

Mention the agent in Slack with the same approval command. Show the one shared Caspian handler
receiving the message and returning `APPROVED`, the `email → slack` quorum, and a SHA-256
receipt.

## 2:20–2:45 — tamper evidence

Run a short verifier:

```bash
python -c "from boundarycraft.store import AuthorityStore; print(AuthorityStore('boundarycraft.db').verify_chain())"
```

Show `(True, N)`. Explain that every receipt commits to the prior hash and the request digest.

## 2:45–3:00 — close

“BoundaryCraft does not execute side effects. It gives an executor a narrow, auditable answer:
what was requested, which independent channel authorized it, and whether the receipt chain is
intact. The safest agent is the one that can prove when it had permission.”
