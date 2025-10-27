# hubble/org.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List

from . import cloud
from .packets import DecryptedPacket, Location
from .device import Device
from .errors import BackendError


class Organization:
    """
    Organization-scoped operations that require org ID and API token.
    Used to manage devices and fetch decrypted packets from the backend.
    """

    org_id: str
    api_token: str

    api_base_url: str
    env: str
    name: str

    def __init__(self, org_id: str, api_token: str) -> str:
        self.org_id = org_id
        self.api_token = api_token

        # Attempt to resolve environment (testing or prod)
        resp = None
        for env, url in cloud.ENVIRONMENTS.items():
            try:
                resp = cloud.retrieve_org_metadata(
                    org_id=self.org_id, api_token=self.api_token, base_url=url
                )
                self.api_base_url = url
                self.env = env
                break
            except:
                pass
        if not resp:
            raise BackendError(f"Unable to determine environment")
        self.name = resp["name"]

    def register_device(self) -> Device:
        """
        Register a new device in this organization and return it.
        Returned Device will have an ID and provisioned key.
        """
        resp = cloud.register_device(
            org_id=self.org_id,
            api_token=self.api_token,
            base_url=self.api_base_url,
        )
        # Currently, only registering a single device and taking the
        # first in the returned list
        device = resp["devices"][0]
        return Device(id=device["device_id"], key=device["key"])

    def set_device_name(self, device_id: str, name: str) -> Device:
        """
        Register a new device in this organization and return it.
        Returned Device will have an ID and provisioned key.
        """
        resp = cloud.update_device(
            org_id=self.org_id,
            api_token=self.api_token,
            name=name,
            device_id=device_id,
            base_url=self.api_base_url,
        )
        return Device(id=resp["id"], name=resp["name"])

    def list_devices(self) -> list[Device]:
        """
        Call the Cloud API “List Devices” endpoint and return Device objects.

        Returns:
            list[Device]
        """

        payload = cloud.list_devices(
            org_id=self.org_id, api_token=self.api_token, base_url=self.api_base_url
        )
        raw_list = payload["devices"]

        # Turn each JSON object into a Device
        devices: List[Device] = []
        for item in raw_list:
            devices.append(Device.from_json(item))
        return devices

    def retrieve_packets(self, device: Device, days: int = 7) -> List[DecryptedPacket]:
        """
        Return the most recent decrypted packet for the given device,
        or None if none exists.
        """
        resp = cloud.retrieve_packets(
            org_id=self.org_id,
            api_token=self.api_token,
            device_id=device.id,
            days=days,
            base_url=self.api_base_url,
        )
        packets = []
        for packet in resp["packets"]:
            packets.append(
                DecryptedPacket(
                    timestamp=int(packet["device"]["timestamp"]),
                    device_id=packet["device"]["id"],
                    device_name=packet["device"]["name"]
                    if "name" in packet["device"]
                    else "",
                    location=Location(
                        lat=packet["location"]["latitude"],
                        lon=packet["location"]["longitude"],
                    ),
                    tags=packet["device"]["tags"],
                    payload=packet["device"]["payload"],
                    rssi=packet["device"]["rssi"],
                    counter=packet["device"]["counter"],
                    sequence=packet["device"]["sequence_number"],
                )
            )
        return packets

    def ingest_packet(self, packet: EncryptedPacket) -> None:
        cloud.ingest_packet(
            org_id=self.org_id,
            api_token=self.api_token,
            packet=packet,
            base_url=self.api_base_url,
        )
