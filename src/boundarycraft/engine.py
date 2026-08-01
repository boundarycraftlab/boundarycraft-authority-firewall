from __future__ import annotations

import re
import secrets

from .classifier import RiskClassifier
from .models import Decision, FirewallReply
from .store import AuthorityStore

COMMAND = re.compile(r"^\s*(APPROVE|DENY|STATUS)\s+([A-Z0-9-]{4,32})\s*$", re.IGNORECASE)


def _sender_label(sender: dict | None) -> str:
    if not sender:
        return "unknown"
    for key in ("address", "login", "username", "id", "name"):
        if sender.get(key):
            return str(sender[key])[:200]
    return "unknown"


class AuthorityFirewall:
    def __init__(
        self,
        store: AuthorityStore,
        classifier: RiskClassifier | None = None,
    ) -> None:
        self.store = store
        self.classifier = classifier or RiskClassifier.from_env()

    def handle(
        self,
        text: str,
        *,
        channel: str,
        sender: dict | None = None,
    ) -> FirewallReply:
        clean_text = (text or "").strip()
        sender_label = _sender_label(sender)
        command = COMMAND.fullmatch(clean_text)
        if command:
            return self._handle_command(
                command.group(1).upper(),
                command.group(2).upper(),
                channel=channel,
                sender=sender_label,
            )
        if not clean_text:
            return FirewallReply(
                "Send an action request, or use STATUS <request-id>. Empty requests fail closed."
            )

        assessment = self.classifier.assess(clean_text)
        request_id = f"BC-{secrets.token_hex(3).upper()}"
        terminal_status = {
            Decision.ALLOW: "allowed",
            Decision.REVIEW: "pending",
            Decision.DENY: "denied",
        }[assessment.decision]
        request = self.store.create_request(
            request_id=request_id,
            origin_channel=channel,
            origin_sender=sender_label,
            request_text=clean_text,
            score=assessment.score,
            summary=assessment.summary,
            reasons=assessment.reasons,
            classifier_source=assessment.source,
            status="pending",
        )

        if assessment.decision is Decision.REVIEW:
            return FirewallReply(
                text=(
                    f"REVIEW REQUIRED · {request_id}\n"
                    f"Risk: {assessment.score}/100 · {assessment.summary}\n"
                    f"Reasons: {', '.join(assessment.reasons)}\n\n"
                    "Cross-channel quorum: send "
                    f"APPROVE {request_id} or DENY {request_id} from a channel other than "
                    f"{channel}. Approval on this same channel will be rejected."
                ),
                request_id=request_id,
                decision=assessment.decision,
            )

        # Automatic allow/deny decisions also receive a tamper-evident receipt.
        decided = self.store.decide(
            request.request_id,
            status=terminal_status,
            approval_channel="policy",
            approval_sender=assessment.source,
        )
        verb = "ALLOWED" if assessment.decision is Decision.ALLOW else "DENIED"
        return FirewallReply(
            text=(
                f"{verb} · {request_id}\n"
                f"Risk: {assessment.score}/100 · {assessment.summary}\n"
                f"Receipt: sha256:{decided.receipt_hash}"
            ),
            request_id=request_id,
            decision=assessment.decision,
            receipt_hash=decided.receipt_hash,
        )

    def _handle_command(
        self,
        command: str,
        request_id: str,
        *,
        channel: str,
        sender: str,
    ) -> FirewallReply:
        try:
            request = self.store.get_request(request_id)
        except KeyError:
            return FirewallReply(f"Unknown request: {request_id}")

        if command == "STATUS":
            suffix = f" · sha256:{request.receipt_hash}" if request.receipt_hash else ""
            return FirewallReply(
                f"{request.request_id} · {request.status.upper()} · "
                f"risk {request.score}/100{suffix}",
                request_id=request.request_id,
                receipt_hash=request.receipt_hash,
            )

        if request.status != "pending":
            return FirewallReply(
                f"{request.request_id} is already {request.status.upper()}; "
                "decisions are immutable.",
                request_id=request.request_id,
                receipt_hash=request.receipt_hash,
            )

        if channel.lower() == request.origin_channel.lower():
            return FirewallReply(
                f"QUORUM REJECTED · {request_id}\n"
                f"The request originated on {request.origin_channel}. Confirm it from a different "
                "Caspian channel."
            )

        status = "approved" if command == "APPROVE" else "denied"
        decided = self.store.decide(
            request_id,
            status=status,
            approval_channel=channel,
            approval_sender=sender,
        )
        return FirewallReply(
            text=(
                f"{status.upper()} · {request_id}\n"
                f"Cross-channel quorum: {request.origin_channel} → {channel}\n"
                f"Receipt: sha256:{decided.receipt_hash}"
            ),
            request_id=request_id,
            decision=Decision.ALLOW if status == "approved" else Decision.DENY,
            receipt_hash=decided.receipt_hash,
        )
