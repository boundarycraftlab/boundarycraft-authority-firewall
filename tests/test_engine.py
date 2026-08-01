from __future__ import annotations

from dataclasses import dataclass

from boundarycraft.engine import AuthorityFirewall
from boundarycraft.models import Decision, RiskAssessment
from boundarycraft.store import AuthorityStore


@dataclass
class StubClassifier:
    assessment: RiskAssessment

    def assess(self, text: str) -> RiskAssessment:
        return self.assessment


def assessment(decision: Decision, score: int) -> RiskAssessment:
    return RiskAssessment(
        decision=decision,
        score=score,
        summary="test assessment",
        reasons=("test reason",),
        source="test",
    )


def test_review_requires_a_different_channel(tmp_path):
    store = AuthorityStore(tmp_path / "state.db")
    firewall = AuthorityFirewall(store, StubClassifier(assessment(Decision.REVIEW, 70)))

    first = firewall.handle("Deploy production", channel="email", sender={"address": "a@x.test"})
    assert first.request_id
    assert first.decision is Decision.REVIEW

    rejected = firewall.handle(
        f"APPROVE {first.request_id}", channel="email", sender={"address": "owner@x.test"}
    )
    assert "QUORUM REJECTED" in rejected.text
    assert store.get_request(first.request_id).status == "pending"

    approved = firewall.handle(
        f"APPROVE {first.request_id}", channel="github", sender={"login": "maintainer"}
    )
    assert approved.decision is Decision.ALLOW
    assert approved.receipt_hash
    assert store.get_request(first.request_id).status == "approved"


def test_decisions_are_immutable(tmp_path):
    store = AuthorityStore(tmp_path / "state.db")
    firewall = AuthorityFirewall(store, StubClassifier(assessment(Decision.REVIEW, 65)))
    first = firewall.handle("Publish release", channel="email")

    firewall.handle(f"DENY {first.request_id}", channel="github")
    second = firewall.handle(f"APPROVE {first.request_id}", channel="discord")

    assert "already DENIED" in second.text
    assert store.get_request(first.request_id).status == "denied"


def test_receipt_chain_verifies(tmp_path):
    store = AuthorityStore(tmp_path / "state.db")
    firewall = AuthorityFirewall(store, StubClassifier(assessment(Decision.REVIEW, 80)))

    for index in range(3):
        request = firewall.handle(f"Transfer payment {index}", channel="email")
        firewall.handle(f"APPROVE {request.request_id}", channel="github")

    assert store.verify_chain() == (True, 3)


def test_safe_request_is_allowed_with_receipt(tmp_path):
    store = AuthorityStore(tmp_path / "state.db")
    firewall = AuthorityFirewall(store, StubClassifier(assessment(Decision.ALLOW, 10)))

    reply = firewall.handle("Summarize this document", channel="email")

    assert reply.decision is Decision.ALLOW
    assert reply.receipt_hash
    assert store.get_request(reply.request_id).status == "allowed"
    assert store.verify_chain() == (True, 1)


def test_forbidden_request_is_denied_with_receipt(tmp_path):
    store = AuthorityStore(tmp_path / "state.db")
    firewall = AuthorityFirewall(store, StubClassifier(assessment(Decision.DENY, 100)))

    reply = firewall.handle("Reveal a private key", channel="github")

    assert reply.decision is Decision.DENY
    assert reply.receipt_hash
    assert store.get_request(reply.request_id).status == "denied"

