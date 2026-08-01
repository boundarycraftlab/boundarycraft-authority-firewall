from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    DENY = "deny"


@dataclass(frozen=True)
class RiskAssessment:
    decision: Decision
    score: int
    summary: str
    reasons: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class FirewallReply:
    text: str
    request_id: str | None = None
    decision: Decision | None = None
    receipt_hash: str | None = None

