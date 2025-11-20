# hubble/device.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Device:
    """
    Represents a device; may or may not hold a key for local decryption.
    If created via Organization API calls, key is typically None.
    """

    id: str
    key: Optional[bytes] = None
    name: Optional[str] = None
    tags: Optional[List[Dict]] = None
    created_ts: Optional[int] = None
    active: Optional[bool] = False

    @classmethod
    def from_json(cls, json):
        return cls(
            id=str(json.get("id")),
            name=json.get("name"),
            tags=json.get("tags"),
            created_ts=json.get("created_ts"),
            active=json.get("active"),
        )
