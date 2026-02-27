# hubble/device.py
from __future__ import annotations
import base64
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class Device:
    """
    Represents a device; may or may not hold a key for local decryption.
    If created via Organization API calls, key is typically None.
    """

    id: str
    key: Optional[bytes] = None
    name: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    created_ts: Optional[int] = None
    active: Optional[bool] = False

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
        return cls(
            id=str(json.get("id")),
            name=json.get("name"),
            tags=json.get("tags"),
            created_ts=json.get("created_ts"),
            active=json.get("active"),
        )
