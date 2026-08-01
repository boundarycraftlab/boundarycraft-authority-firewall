from __future__ import annotations

import os

from caspian_sdk import CommClient


def _by_channel(connections: list[dict], channel: str) -> list[dict]:
    return [connection for connection in connections if connection.get("channel") == channel]


def main() -> None:
    client = CommClient()
    username = os.getenv("BOUNDARYCRAFT_EMAIL_USERNAME", "boundarycraft-firewall")
    email = client.connect_email(username=username, display_name="BoundaryCraft Firewall")
    print(f"Email active: {email.get('address', username)}")

    # caspian-sdk 0.6.1 exposes individual connection operations but not the list endpoint.
    # The gateway endpoint is public API; use the client's authenticated transport until the
    # convenience method lands in the SDK.
    connections = client._request("GET", "/v1/connections")  # noqa: SLF001
    slack = _by_channel(connections, "slack")
    if slack:
        for connection in slack:
            print(
                "Slack connection: "
                f"{connection.get('status')} · {connection.get('address') or connection.get('id')}"
            )
            if connection.get("authorize_url"):
                print(f"Authorize Slack: {connection['authorize_url']}")
        return

    # The hosted contest gateway provisions its shared Slack app through the standard
    # connection endpoint and returns an OAuth URL; no Slack developer tokens are needed.
    connection = client.connect_slack(display_name="BoundaryCraft Firewall")
    print("Authorize the second channel at:")
    print(connection.get("authorize_url"))
    print("After authorization, run boundarycraft-setup again to verify it is active.")


if __name__ == "__main__":
    main()
