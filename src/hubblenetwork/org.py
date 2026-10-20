# hubble/org.py
from __future__ import annotations

import base64
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import replace

from . import cloud
from .claim import CLAIM_STATUSES, COMPLETED, DeviceClaim
from .crypto import DEVICE_UPTIME, UNIX_TIME
from .device import Device
from .errors import (
    BackendError,
    InvalidCredentialsError,
    PartialRegistrationError,
    ValidationError,
)
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


def _paginate(
    fetch: Callable[[str | None], tuple[dict, str | None]],
    key: str,
    on_page: Callable[[int, int], None] | None,
) -> Iterator[dict]:
    """Yield the ``key`` items of every page ``fetch(continuation_token)`` returns.

    Calls ``on_page(page_number, total_so_far)`` after each page.
    """
    continuation_token = None
    page = 0
    seen = 0
    while True:
        resp, continuation_token = fetch(continuation_token)
        page += 1
        for item in resp.get(key) or []:
            seen += 1
            yield item
        if on_page:
            on_page(page, seen)
        if not continuation_token:
            break


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
        return self.register_devices(
            1,
            encryption=encryption,
            counter_source=counter_source,
            period_seconds=period_seconds,
            period_exponent=period_exponent,
            tags=tags,
        )[0]

    def register_devices(
        self,
        count: int,
        encryption: str | None = None,
        counter_source: str | None = None,
        period_seconds: int | None = None,
        period_exponent: int | None = None,
        tags: dict[str, str] | None = None,
        *,
        activated: bool | None = None,
        claim_id: str | None = None,
        new_claim: bool = False,
        destination_org_id: str | None = None,
        on_batch: Callable[[int, int], None] | None = None,
    ) -> list[Device]:
        """
        Register ``count`` devices, optionally linking them to device claims,
        and return them with their keys, in order.

        The cloud takes at most ``cloud.REGISTER_BATCH_LIMIT`` (1000) devices
        per request, so a larger ``count`` is sent as several requests, and
        ``on_batch(registered_so_far, count)`` is called after each one.

        Takes the same encryption options as :meth:`register_device`, plus:

        Args:
            activated: ``False`` creates the devices deactivated, so they cost
                       nothing on the decode path until claimed. Needs the
                       ``can_deactivate_devices`` entitlement.
            claim_id: Link every device to this existing AVAILABLE claim.
            new_claim: Give each device a claim of its own, whose claim ID is
                       the device's ID.
            destination_org_id: The org allowed to redeem the new claims
                                (``new_claim`` only; omit for directionless).

        Linking needs the ``can_create_device_claims`` entitlement. The cloud
        links after creating the devices and does not roll back, so if the
        link fails the devices may exist anyway, unlinked.

        Raises:
            PartialRegistrationError: a request failed (or the run was
                interrupted) after earlier requests registered devices. Its
                ``devices`` holds them with their keys, which exist nowhere
                else; its ``cause`` is the original failure. A failure in the
                first request is raised as-is, since nothing was returned yet.
        """
        if count < 1:
            raise ValidationError(f"count must be at least 1, got {count}")
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
        if claim_id is not None and new_claim:
            raise ValidationError("provide at most one of claim_id, new_claim")
        if destination_org_id is not None and not new_claim:
            raise ValidationError("destination_org_id requires new_claim=True")

        claim_entry: dict | None = None
        if claim_id is not None:
            claim_entry = {"claim_id": claim_id}
        elif new_claim:
            claim_entry = {"new_claim_using_device_id": True}
            if destination_org_id is not None:
                claim_entry["destination_org_id"] = destination_org_id

        devices: list[Device] = []
        try:
            while len(devices) < count:
                n = min(count - len(devices), cloud.REGISTER_BATCH_LIMIT)
                resp = cloud.register_device(
                    credentials=self.credentials,
                    env=self.env,
                    encryption=encryption,
                    counter_source=counter_source,
                    period_in_seconds=period_seconds,
                    period_exponent=period_exponent,
                    tags=tags,
                    n_devices=n,
                    activated=activated,
                    # One entry per device in this request.
                    device_claims=[claim_entry] * n if claim_entry else None,
                )
                batch = [
                    self._registered_device(item, claim_id, new_claim)
                    for item in resp["devices"]
                ]
                if not batch:
                    # Never loop forever on a response that registered nothing.
                    raise BackendError(
                        f"the cloud returned no devices for a request of {n}"
                    )
                devices.extend(batch)
                if on_batch:
                    on_batch(len(devices), count)
        except (Exception, KeyboardInterrupt) as exc:
            # Devices from earlier requests exist, and their keys are only
            # here: hand them back with the failure rather than drop them.
            if devices:
                raise PartialRegistrationError(devices, count, exc) from exc
            raise
        return devices

    @staticmethod
    def _registered_device(item: dict, claim_id: str | None, new_claim: bool) -> Device:
        device_id = item["device_id"]
        return Device(
            id=device_id,
            key=base64.b64decode(item["key"]) if item.get("key") else None,
            name=item.get("name") or None,
            created_ts=item.get("created_ts"),
            active=item.get("activated"),
            # A new claim takes the device's own ID.
            claim_id=device_id if new_claim else claim_id,
        )

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
        Fetch one device, including how it was registered (encryption,
        counter source, rotation period) and when the backend last decoded
        a packet from it. Raises NotFoundError if the ID is not in this org.
        """
        return Device.from_json(
            cloud.get_device(
                credentials=self.credentials, env=self.env, device_id=device_id
            )
        )

    def set_device_activated(self, device_id: str, activated: bool) -> None:
        """
        Activate or deactivate a device. The cloud applies it asynchronously.
        Deactivating needs the ``can_deactivate_devices`` entitlement.
        """
        cloud.set_device_activated(
            credentials=self.credentials,
            env=self.env,
            device_id=device_id,
            activated=activated,
        )

    # -- device claims ------------------------------------------------------

    def create_claim(
        self,
        destination_org_id: str | None = None,
        claim_token: str | None = None,
        name: str | None = None,
    ) -> DeviceClaim:
        """
        Create an empty claim, to link devices to afterwards.

        Args:
            destination_org_id: The only org allowed to redeem it. Omit for a
                                directionless claim, which whoever presents its
                                claim ID first can redeem.
            claim_token: An alternate ID to look the claim up by: a UUID or a
                         GS1-128 payload starting with AI 01 or 21.
            name: A label, up to 250 characters.

        Needs the ``can_create_device_claims`` entitlement.
        """
        return DeviceClaim.from_json(
            cloud.create_claim(
                credentials=self.credentials,
                env=self.env,
                destination_org_id=destination_org_id,
                claim_token=claim_token,
                name=name,
            )
        )

    def iter_claims(
        self,
        incoming: bool = False,
        status: str | None = None,
        on_page: Callable[[int, int], None] | None = None,
    ) -> Iterator[DeviceClaim]:
        """
        Yield claims page by page: the ones this org created, or with
        ``incoming=True`` the ones pinned to this org as destination.
        Directionless claims are never incoming; they are redeemed by ID.

        Args:
            status: Only claims in this status (AVAILABLE, IN_PROGRESS, COMPLETED).
            on_page: Called as ``on_page(page_number, total_so_far)`` after each page.
        """
        if status is not None and status not in CLAIM_STATUSES:
            raise ValidationError(
                f"status must be one of {list(CLAIM_STATUSES)}, got {status!r}"
            )
        def fetch(token):
            return cloud.list_claims(
                credentials=self.credentials,
                env=self.env,
                role="destination" if incoming else "source",
                status=status,
                continuation_token=token,
            )

        for item in _paginate(fetch, "claims", on_page):
            yield DeviceClaim.from_json(item)

    def list_claims(
        self, incoming: bool = False, status: str | None = None
    ) -> list[DeviceClaim]:
        """:meth:`iter_claims`, collected into a list."""
        return list(self.iter_claims(incoming=incoming, status=status))

    def get_claim(
        self, claim_id: str | None = None, *, claim_token: str | None = None
    ) -> DeviceClaim:
        """
        Fetch one claim, with its live ``device_count``, by claim ID or by
        claim token. Raises NotFoundError if it doesn't exist or this org
        can't see it.
        """
        if (claim_id is None) == (claim_token is None):
            raise ValidationError("provide exactly one of claim_id, claim_token")
        return DeviceClaim.from_json(
            cloud.get_claim(
                credentials=self.credentials,
                env=self.env,
                claim_id=claim_id,
                claim_token=claim_token,
            )
        )

    def update_claim(
        self,
        claim_id: str,
        destination_org_id: str | None = None,
        claim_token: str | None = None,
        name: str | None = None,
    ) -> DeviceClaim:
        """
        Change an AVAILABLE claim. ``None`` leaves a field as it is and ``""``
        clears it (a cleared destination makes the claim directionless).
        Raises ConflictError once the claim is no longer AVAILABLE.
        """
        if destination_org_id is None and claim_token is None and name is None:
            raise ValidationError(
                "provide at least one of destination_org_id, claim_token, name"
            )
        return DeviceClaim.from_json(
            cloud.update_claim(
                credentials=self.credentials,
                env=self.env,
                claim_id=claim_id,
                destination_org_id=destination_org_id,
                claim_token=claim_token,
                name=name,
            )
        )

    def delete_claim(self, claim_id: str) -> DeviceClaim:
        """
        Delete an AVAILABLE claim and unlink its devices, which stay in this
        org. Returns the claim as it was. Raises ConflictError once redeemed.
        """
        return DeviceClaim.from_json(
            cloud.delete_claim(
                credentials=self.credentials, env=self.env, claim_id=claim_id
            )
        )

    def link_device(self, device_id: str, claim_id: str) -> None:
        """
        Link one of this org's devices to an AVAILABLE claim it created.
        Needs the ``can_create_device_claims`` entitlement.
        """
        if not claim_id:
            raise ValidationError("claim_id is required; use unlink_device to unlink")
        cloud.set_device_claim(
            credentials=self.credentials,
            env=self.env,
            device_id=device_id,
            claim_id=claim_id,
        )

    def unlink_device(self, device_id: str) -> None:
        """Remove a device from whatever AVAILABLE claim it is linked to."""
        cloud.set_device_claim(
            credentials=self.credentials, env=self.env, device_id=device_id, claim_id=""
        )

    def link_devices(self, device_ids: Iterable[str], claim_id: str) -> list[str]:
        """
        Link many of this org's devices to an AVAILABLE claim, one request per
        ``cloud.BATCH_UPDATE_LIMIT`` (1000) devices. Repeated IDs are sent once.
        Needs the ``can_create_device_claims`` entitlement.

        Each request is all or nothing: one device not in this org fails it
        with a ``RequestError`` naming that device, and none of its devices are
        linked. Requests sent before a failing one stay applied. Returns the
        IDs the cloud reports as updated.
        """
        if not claim_id:
            raise ValidationError("claim_id is required; use unlink_devices to unlink")
        return self._set_device_claims(device_ids, claim_id)

    def unlink_devices(self, device_ids: Iterable[str]) -> list[str]:
        """
        Remove many devices from their claims, batched like ``link_devices``
        and with the same all-or-nothing requests. Returns the updated IDs.
        """
        return self._set_device_claims(device_ids, "")

    def _set_device_claims(self, device_ids: Iterable[str], claim_id: str) -> list[str]:
        unique = list(dict.fromkeys(device_ids))
        limit = cloud.BATCH_UPDATE_LIMIT
        updated: list[str] = []
        for start in range(0, len(unique), limit):
            devices = cloud.batch_update_devices(
                credentials=self.credentials,
                env=self.env,
                updates=[
                    {"device_id": d, "set_device_claim_id": claim_id}
                    for d in unique[start:start + limit]
                ],
            )
            updated.extend(d["id"] for d in devices if d.get("id"))
        return updated

    def redeem_claim(
        self,
        claim_id: str,
        wait: bool = True,
        timeout: float = 120.0,
        poll_interval: float = 2.0,
        on_poll: Callable[[DeviceClaim, float], None] | None = None,
    ) -> DeviceClaim:
        """
        Redeem a claim into this org: its devices move here and are activated.

        The cloud does the move in the background. With ``wait`` this polls
        until the claim is COMPLETED or ``timeout`` seconds pass, and returns
        the latest claim either way, so check ``status``. Safe to call again
        while the claim is IN_PROGRESS for this org.

        Args:
            on_poll: Called as ``on_poll(claim, elapsed_seconds)`` after each poll.

        Raises:
            NotFoundError: no such claim, or it is pinned to another org.
            ConflictError: already COMPLETED, or otherwise not redeemable.
        """
        claim = DeviceClaim.from_json(
            cloud.redeem_claim(
                credentials=self.credentials, env=self.env, claim_id=claim_id
            )
        )
        if not wait:
            return claim
        start = time.monotonic()
        while claim.status != COMPLETED:
            elapsed = time.monotonic() - start
            if elapsed >= timeout:
                break
            time.sleep(min(poll_interval, max(0.0, timeout - elapsed)))
            claim = self.get_claim(claim_id)
            if on_poll:
                on_poll(claim, time.monotonic() - start)
        return claim

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
        def fetch(token):
            return cloud.list_devices(
                credentials=self.credentials,
                env=self.env,
                continuation_token=token,
            )

        for item in _paginate(fetch, "devices", on_page):
            yield Device.from_json(item)

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
        def fetch(token):
            return cloud.retrieve_packets(
                credentials=self.credentials,
                env=self.env,
                device_id=device.id,
                days=days,
                continuation_token=token,
            )

        for packet in _paginate(fetch, "packets", on_page):
            yield _decrypted_from_cloud(packet)

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
        return decode_packets(
            credentials=self.credentials, env=self.env, packets=packets, metadata=metadata
        )


def decode_packets(
    *,
    credentials: cloud.Credentials,
    env: cloud.Environment,
    packets: Sequence[EncryptedPacket | AesEaxPacket],
    metadata: dict[str, str] | None = None,
) -> list[DecryptedPacket | None]:
    """:meth:`Organization.decode_packets` for a caller that already resolved
    the environment, so it costs no requests beyond the decode itself."""
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
            credentials=credentials,
            env=env,
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
