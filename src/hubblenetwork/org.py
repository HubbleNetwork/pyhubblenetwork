# hubble/org.py
from __future__ import annotations

import base64
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import replace

from . import cloud
from .crypto import DEVICE_UPTIME, UNIX_TIME
from .device import Device
from .errors import InvalidCredentialsError, ValidationError
from .packets import AesEaxPacket, DecryptedPacket, EncryptedPacket, Location

_VALID_COUNTER_SOURCES = {UNIX_TIME, DEVICE_UPTIME}


def _decrypted_from_cloud(packet: dict) -> DecryptedPacket:
    """Build a DecryptedPacket from one entry of a cloud ``packets`` list.

    Shared by the retrieve-packets and decode responses, which use the same
    ``{"location": ..., "device": ...}`` shape.
    """
    dev = packet["device"]
    loc = packet.get("location") or None
    return DecryptedPacket(
        timestamp=int(dev["timestamp"]),
        device_id=dev["id"],
        device_name=dev.get("name") or "",
        location=Location(lat=loc["latitude"], lon=loc["longitude"]) if loc else None,
        tags=dev.get("tags") or {},
        payload=base64.b64decode(dev.get("payload") or ""),
        rssi=dev["rssi"],
        counter=dev.get("counter"),
        sequence=dev.get("sequence_number"),
    )


class Organization:
    """
    Organization-scoped operations that require org ID and API token.
    Used to manage devices and fetch decrypted packets from the backend.
    """

    name: str

    credentials: cloud.Credentials
    env: cloud.Environment

    @property
    def org_id(self) -> str:
        """Return the organization ID from credentials."""
        return self.credentials.org_id

    def __init__(
        self,
        org_id: str | None = None,
        api_token: str | None = None,
        credentials: cloud.Credentials | None = None,
    ) -> None:
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

    def register_device(
        self,
        encryption: str | None = None,
        counter_source: str | None = None,
        period_seconds: int | None = None,
        period_exponent: int | None = None,
        tags: dict[str, str] | None = None,
    ) -> Device:
        """
        Register a new device in this organization and return it.
        Returned Device will have an ID and provisioned key.

        Args:
            encryption: Encryption type ("AES-256-CTR", "AES-128-CTR", "AES-128-EAX", or "NONE").
                        Defaults to "AES-256-CTR".
            counter_source: EID rotation counter source ("UNIX_TIME" or "DEVICE_UPTIME").
            period_seconds: EID rotation period in seconds. Only valid when
                            encryption='AES-128-EAX' and counter_source='DEVICE_UPTIME'.
            period_exponent: EID rotation period exponent (period = 2^n seconds). Only valid
                             when encryption='AES-128-EAX' and counter_source='DEVICE_UPTIME'.
                             Mutually exclusive with period_seconds.
            tags: Optional custom key/value tags applied at registration.
        """
        if counter_source is not None and counter_source not in _VALID_COUNTER_SOURCES:
            raise ValidationError(
                f"counter_source must be one of {sorted(_VALID_COUNTER_SOURCES)}, got {counter_source!r}"
            )
        if period_seconds is not None and period_exponent is not None:
            raise ValidationError(
                "provide at most one of period_seconds, period_exponent"
            )
        if period_seconds is not None or period_exponent is not None:
            if encryption != "AES-128-EAX":
                raise ValidationError(
                    "period_seconds/period_exponent requires encryption='AES-128-EAX'"
                )
            if counter_source != DEVICE_UPTIME:
                raise ValidationError(
                    "period_seconds/period_exponent requires counter_source='DEVICE_UPTIME'"
                )
        resp = cloud.register_device(
            credentials=self.credentials,
            env=self.env,
            encryption=encryption,
            counter_source=counter_source,
            period_in_seconds=period_seconds,
            period_exponent=period_exponent,
            tags=tags,
        )
        device = resp["devices"][0]
        key_bytes = base64.b64decode(device["key"]) if device.get("key") else None
        return Device(id=device["device_id"], key=key_bytes)

    def set_device_name(self, device_id: str, name: str) -> Device:
        """
        Update the name of an existing device.
        Returns the updated Device object.
        """
        resp = cloud.update_device(
            credentials=self.credentials,
            env=self.env,
            name=name,
            device_id=device_id,
        )
        return Device(id=resp["id"], name=resp["name"])

    def delete_device(self, device_id: str) -> None:
        """
        Delete a device from this organization.

        Args:
            device_id: The ID of the device to delete.
        """
        cloud.delete_device(
            credentials=self.credentials,
            env=self.env,
            device_id=device_id,
        )

    def get_device(self, device_id: str) -> Device:
        """
        Fetch one registered device by ID.

        Raises:
            NotFoundError: the device is not registered in this organization.
        """
        return Device.from_json(
            cloud.get_device(
                credentials=self.credentials, env=self.env, device_id=device_id
            )
        )

    def iter_devices(
        self, on_page: Callable[[int, int], None] | None = None
    ) -> Iterator[Device]:
        """
        Yield Device objects from the Cloud API "List Devices" endpoint,
        one page at a time.

        Pagination is handled internally, but nothing is accumulated, so a
        caller can render or process the first page without waiting for the
        last one.

        Args:
            on_page: Optional callback invoked as ``on_page(page_number, total_so_far)``
                     after each page is fetched. Intended for progress reporting.
        """
        continuation_token = None
        page = 0
        seen = 0
        while True:
            resp, continuation_token = cloud.list_devices(
                credentials=self.credentials,
                env=self.env,
                continuation_token=continuation_token,
            )
            page += 1
            for item in resp["devices"]:
                seen += 1
                yield Device.from_json(item)
            if on_page:
                on_page(page, seen)
            if not continuation_token:
                break

    def list_devices(self) -> list[Device]:
        """
        Call the Cloud API "List Devices" endpoint and return Device objects.

        Returns:
            list[Device]
        """
        return list(self.iter_devices())

    def iter_packets(
        self,
        device: Device,
        days: int = 7,
        on_page: Callable[[int, int], None] | None = None,
    ) -> Iterator[DecryptedPacket]:
        """
        Yield decrypted packets for the given device, one page at a time.

        Pagination is handled internally without accumulating results, so a
        caller can start rendering immediately. A busy device can return tens
        of thousands of packets.

        Args:
            device: The device to fetch packets for.
            days: Number of days to query back from now.
            on_page: Optional callback invoked as ``on_page(page_number, total_so_far)``
                     after each page is fetched. Intended for progress reporting.
        """
        continuation_token = None
        page = 0
        seen = 0
        while True:
            resp, continuation_token = cloud.retrieve_packets(
                credentials=self.credentials,
                env=self.env,
                device_id=device.id,
                days=days,
                continuation_token=continuation_token,
            )
            page += 1
            for packet in resp["packets"]:
                seen += 1
                yield _decrypted_from_cloud(packet)
            if on_page:
                on_page(page, seen)
            if not continuation_token:
                break

    def retrieve_packets(self, device: Device, days: int = 7) -> list[DecryptedPacket]:
        """
        Return the most recent decrypted packet for the given device,
        or None if none exists.
        """
        return list(self.iter_packets(device, days=days))

    def device_metrics(self, days_back: int = 1) -> dict:
        """Fetch device metrics for this organization."""
        return cloud.device_metrics(
            credentials=self.credentials,
            env=self.env,
            days_back=days_back,
        )

    def ingest_packet(self, packet: EncryptedPacket) -> None:
        cloud.ingest_packet(
            credentials=self.credentials,
            env=self.env,
            packet=packet,
        )

    def decode_packets(
        self,
        packets: Sequence[EncryptedPacket | AesEaxPacket],
        metadata: dict[str, str] | None = None,
    ) -> list[DecryptedPacket | None]:
        """
        Decrypt packets in the Hubble Cloud, without holding any device key.

        Accepts any number of BLE packets (``EncryptedPacket`` for AES-CTR,
        ``AesEaxPacket`` for AES-EAX) and sends them in batches of
        ``cloud.DECODE_BATCH_LIMIT``. Identical advertisements (a device
        repeats each one several times) are sent once per call.

        The cloud also stores every packet it decodes, the same as ingestion,
        so do not also pass the same packet to :meth:`ingest_packet`.

        Returns one entry per input, in input order: a ``DecryptedPacket``
        carrying the device ID and name, or ``None`` when the cloud could not
        decrypt it (another org's device, an unregistered device, or a
        corrupt packet). ``timestamp``, ``rssi`` and ``location`` come from
        the input packet so duplicates keep their own reception details.

        The endpoint only accepts packets received in the last 72 hours (and
        no more than 2 hours in the future), and rejects a whole batch if any
        one advertisement is invalid. Packets outside that window, or with an
        empty advertisement, are therefore not sent and come back ``None``.

        Raises:
            ValueError: a packet is not an ``EncryptedPacket`` or
                ``AesEaxPacket`` (unencrypted, unknown-version and satellite
                packets cannot be cloud-decoded; filter them out first).
            PermissionDeniedError: the API key lacks the ``read-packets`` scope.
            BackendError: any other API failure. A failed batch fails the call.
        """
        payloads: list[str | None] = []
        unique: dict[str, dict] = {}
        now = time.time()
        for pkt in packets:
            # One invalid advertisement makes the endpoint reject the whole
            # batch, so anything it would refuse is answered None locally.
            if not cloud.advertisement_bytes(pkt) or not cloud.decode_window_ok(
                pkt.timestamp, now=now
            ):
                payloads.append(None)
                continue
            adv = cloud.packet_to_advertisement(pkt)
            payloads.append(adv["payload"])
            unique.setdefault(adv["payload"], adv)

        advs = list(unique.values())
        decoded: dict[str, dict] = {}
        limit = cloud.DECODE_BATCH_LIMIT
        for start in range(0, len(advs), limit):
            for item in cloud.decode_packets(
                credentials=self.credentials,
                env=self.env,
                advertisements=advs[start : start + limit],
                metadata=metadata,
            ):
                echoed = (item.get("advertisement") or {}).get("payload")
                if echoed in unique:
                    decoded.setdefault(echoed, item)

        results: list[DecryptedPacket | None] = []
        for pkt, b64 in zip(packets, payloads):
            item = decoded.get(b64) if b64 is not None else None
            if item is None:
                results.append(None)
                continue
            results.append(
                replace(
                    _decrypted_from_cloud(item),
                    timestamp=pkt.timestamp,
                    rssi=pkt.rssi,
                    location=pkt.location,
                    protocol_version=pkt.protocol_version,
                    eid=pkt.eid,
                    auth_tag=pkt.auth_tag,
                )
            )
        return results
