# hubble/device.py
from __future__ import annotations

import base64
from dataclasses import dataclass


@dataclass
class Device:
    """
    Represents a device; may or may not hold a key for local decryption.
    If created via Organization API calls, key is typically None.
    """

    id: str
    key: bytes | None = None
    name: str | None = None
    tags: dict[str, str] | None = None
    created_ts: int | None = None
    active: bool | None = False
    # Registration config. Only the single-device GET returns these; the list
    # endpoint omits them, so devices from list_devices() leave them None.
    encryption: str | None = None  # "AES-256-CTR", "AES-128-CTR", "AES-128-EAX"
    counter_source: str | None = None  # UNIX_TIME / DEVICE_UPTIME
    period_exponent: int | None = None  # AES-128-EAX rotation period, 2^n seconds
    # Newest packet the backend decoded, per network: {"terrestrial": ts, ...}
    last_packet_ts: dict[str, float] | None = None

    def __str__(self) -> str:
        key_str = (
            base64.b64encode(self.key).decode("ascii")
            if isinstance(self.key, bytes)
            else self.key
        )
        return (
            f"Device(id={self.id!r}, key={key_str!r}, name={self.name!r}, "
            f"tags={self.tags!r}, created_ts={self.created_ts!r}, active={self.active!r})"
        )

    @classmethod
    def from_json(cls, json):
        rotation = json.get("eid_rotation") or {}
        exponent = rotation.get("period_exponent")
        seconds = rotation.get("period_in_seconds")
        # The API takes either form; only a power of two maps to an exponent.
        if (
            exponent is None
            and isinstance(seconds, int)
            and seconds > 0
            and seconds & (seconds - 1) == 0
        ):
            exponent = seconds.bit_length() - 1
        last = {}
        for network, pkt in (json.get("most_recent_packet") or {}).items():
            if isinstance(pkt, dict) and pkt.get("timestamp") is not None:
                last[network] = pkt["timestamp"]
        return cls(
            id=str(json.get("id")),
            name=json.get("name"),
            tags=json.get("tags"),
            created_ts=json.get("created_ts"),
            active=json.get("active"),
            encryption=json.get("encryption"),
            counter_source=rotation.get("counter_source"),
            period_exponent=exponent,
            last_packet_ts=last or None,
        )
