# hubble/claim.py
from __future__ import annotations

import base64
from dataclasses import dataclass

AVAILABLE = "AVAILABLE"
IN_PROGRESS = "IN_PROGRESS"
COMPLETED = "COMPLETED"
CLAIM_STATUSES = (AVAILABLE, IN_PROGRESS, COMPLETED)


def encode_claim_token(token: str) -> str:
    """The path segment a claim_token is looked up by: unpadded base64url.

    The cloud rejects a padded segment, so the ``=`` must go.
    """
    return base64.urlsafe_b64encode(token.encode("utf-8")).rstrip(b"=").decode("ascii")


@dataclass
class DeviceClaim:
    """
    A hand-off of devices from the org that owns them (source) to another
    org (destination). Redeeming it moves every linked device to the
    redeeming org and activates them.

    Status only moves forward: AVAILABLE -> IN_PROGRESS -> COMPLETED. Only an
    AVAILABLE claim can be edited, deleted, or have devices linked/unlinked.
    """

    claim_id: str
    source_org_id: str
    status: str
    # Caller-chosen alternate ID (UUID or GS1-128), normalized by the cloud.
    claim_token: str | None = None
    name: str | None = None
    # None means directionless: any org holding the claim_id can redeem it.
    destination_org_id: str | None = None
    created_ts: int | None = None  # epoch seconds
    updated_ts: int | None = None
    completed_ts: int | None = None
    # Only the single-claim GET returns these. The cloud names the device
    # only when exactly one is linked.
    device_count: int | None = None
    device_ids: list[str] | None = None

    @property
    def directional(self) -> bool:
        """True when only ``destination_org_id`` can redeem this claim."""
        return bool(self.destination_org_id)

    @classmethod
    def from_json(cls, json: dict) -> DeviceClaim:
        devices = json.get("devices")
        return cls(
            claim_id=json["claim_id"],
            source_org_id=json.get("source_org_id", ""),
            status=json.get("status", ""),
            claim_token=json.get("claim_token") or None,
            name=json.get("name") or None,
            destination_org_id=json.get("destination_org_id") or None,
            created_ts=json.get("created_ts"),
            updated_ts=json.get("updated_ts"),
            completed_ts=json.get("completed_ts"),
            device_count=json.get("device_count"),
            device_ids=[d["device_id"] for d in devices] if devices else None,
        )
