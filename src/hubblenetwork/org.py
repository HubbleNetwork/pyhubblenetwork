# hubble/org.py
from __future__ import annotations
from typing import Optional, List

from . import cloud
from .packets import DecryptedPacket, EncryptedPacket, Location
from .device import Device
from .errors import InvalidCredentialsError


class Organization:
    """
    Organization-scoped operations that require org ID and API token.
    Used to manage devices and fetch decrypted packets from the backend.
    """

    name: str

    credentials: cloud.Credentials
    env: cloud.Environment

    def __init__(
        self,
        org_id: Optional(str) = None,
        api_token: Optional(str) = None,
        credentials: Optional(cloud.Credentials) = None,
    ) -> str:
        if credentials:
            self.credentials = credentials
        else:
            self.credentials = cloud.Credentials(org_id, api_token)
        self.env = cloud.get_env_from_credentials(self.credentials)
        if not self.env:
            raise InvalidCredentialsError("Invalid credentials passed in.")
        self.name = cloud.retrieve_org_metadata(
            credentials=self.credentials, env=self.env
        )["name"]

    def register_device(self, encryption: Optional[str] = None) -> Device:
        """
        Register a new device in this organization and return it.
        Returned Device will have an ID and provisioned key.
        """
        resp = cloud.register_device(
            credentials=self.credentials, env=self.env, encryption=encryption
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
            credentials=self.credentials,
            env=self.env,
            name=name,
            device_id=device_id,
        )
        return Device(id=resp["id"], name=resp["name"])

    def list_devices(self) -> list[Device]:
        """
        Call the Cloud API “List Devices” endpoint and return Device objects.

        Returns:
            list[Device]
        """

        # Turn each JSON object into a Device
        devices: List[Device] = []

        continuation_token = None
        while True:
            resp, continuation_token = cloud.list_devices(
                credentials=self.credentials,
                env=self.env,
                continuation_token=continuation_token,
            )
            raw_list = resp["devices"]
            for item in raw_list:
                devices.append(Device.from_json(item))
            if not continuation_token:
                break

        return devices

    def retrieve_packets(self, device: Device, days: int = 7) -> List[DecryptedPacket]:
        """
        Return the most recent decrypted packet for the given device,
        or None if none exists.
        """
        continuation_token = None

        packets = []
        while True:
            resp, continuation_token = cloud.retrieve_packets(
                credentials=self.credentials,
                env=self.env,
                device_id=device.id,
                days=days,
                continuation_token=continuation_token,
            )
            for packet in resp["packets"]:
                packets.append(
                    DecryptedPacket(
                        timestamp=int(packet["device"]["timestamp"]),
                        device_id=packet["device"]["id"],
                        device_name=(
                            packet["device"]["name"]
                            if "name" in packet["device"]
                            else ""
                        ),
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
            if not continuation_token:
                break
        return packets

    def ingest_packet(self, packet: EncryptedPacket) -> None:
        cloud.ingest_packet(
            credentials=self.credentials,
            env=self.env,
            packet=packet,
        )
