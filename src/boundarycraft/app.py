from __future__ import annotations

import os
from pathlib import Path

from caspian_sdk import CommClient

from .classifier import RiskClassifier
from .engine import AuthorityFirewall
from .store import AuthorityStore


def build_firewall() -> AuthorityFirewall:
    db_path = Path(os.getenv("BOUNDARYCRAFT_DB", "boundarycraft.db"))
    return AuthorityFirewall(AuthorityStore(db_path), RiskClassifier.from_env())


def main() -> None:
    client = CommClient()
    email_username = os.getenv("BOUNDARYCRAFT_EMAIL_USERNAME", "boundarycraft-firewall")
    email = client.connect_email(username=email_username, display_name="BoundaryCraft Firewall")
    firewall = build_firewall()

    print(f"BoundaryCraft email: {email.get('address', email_username)}")
    print("Listening on every connected Caspian channel with one handler.")

    @client.on_message
    def handle(message) -> None:
        reply = firewall.handle(
            message.text or message.subject or "",
            channel=message.channel,
            sender=message.sender,
        )
        message.reply(reply.text)

    client.listen(ack="Checking authority boundary…")


if __name__ == "__main__":
    main()

