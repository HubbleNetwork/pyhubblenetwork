"""End-to-end integration tests for packet generation.

Each test:
  1. Registers a fresh device with the cloud and gets back its key + UUID
  2. Generates a packet locally with `encrypt` / `encrypt_eax` using that key
  3. Ingests the packet via `Organization.ingest_packet`
  4. Polls `Organization.retrieve_packets` until the backend has decrypted
     the packet, then asserts the decrypted payload matches what was sent
  5. Cleans up the device

Backend ingestion is asynchronous; tests poll for up to 2 minutes per packet.
Run with `pytest -m integration` and credentials in env:
  HUBBLE_TESTING_ORG_ID / HUBBLE_TESTING_API_TOKEN  (preferred), or
  HUBBLE_PROD_ORG_ID    / HUBBLE_PROD_API_TOKEN
"""

from __future__ import annotations

import os
import time
import pytest

from hubblenetwork import Organization, encrypt, encrypt_eax
from hubblenetwork.device import Device

pytestmark = pytest.mark.integration


_POLL_TIMEOUT_SEC = 120
_POLL_INTERVAL_SEC = 3


def _credentials_or_skip() -> tuple[str, str]:
    org_id = os.environ.get("HUBBLE_TESTING_ORG_ID") or os.environ.get("HUBBLE_PROD_ORG_ID")
    api_token = os.environ.get("HUBBLE_TESTING_API_TOKEN") or os.environ.get("HUBBLE_PROD_API_TOKEN")
    if not org_id or not api_token:
        pytest.skip("Requires HUBBLE_TESTING_* or HUBBLE_PROD_* env vars")
    return org_id, api_token


def _wait_for_packet(org: Organization, device: Device, expected_payload: bytes):
    """Poll retrieve_packets until a packet with the expected payload appears."""
    deadline = time.monotonic() + _POLL_TIMEOUT_SEC
    while time.monotonic() < deadline:
        for pkt in org.retrieve_packets(device, days=1):
            if pkt.payload == expected_payload:
                return pkt
        time.sleep(_POLL_INTERVAL_SEC)
    return None


@pytest.fixture
def org() -> Organization:
    org_id, api_token = _credentials_or_skip()
    return Organization(org_id=org_id, api_token=api_token)


def _safe_delete(org: Organization, device_id: str) -> None:
    """Best-effort cleanup — don't mask the real failure if delete also fails."""
    try:
        org.delete_device(device_id)
    except Exception as e:  # pragma: no cover - test-time cleanup
        print(f"[cleanup] failed to delete device {device_id}: {e}")


class TestAesCtrRoundTripViaCloud:
    """Register an AES-CTR device, encrypt a packet locally, ingest it, read
    it back from the cloud, and verify the decrypted payload matches."""

    def test_aes_256_ctr_unix_time(self, org):
        device = org.register_device(
            encryption="AES-256-CTR",
            counter_source="UNIX_TIME",
        )
        assert device.id and device.key and len(device.key) == 32
        try:
            payload = b"int-256-" + os.urandom(4)
            pkt = encrypt(device.key, payload)  # default UNIX_TIME, today's UTC day
            org.ingest_packet(pkt)

            decrypted = _wait_for_packet(org, device, payload)
            assert decrypted is not None, (
                f"backend did not surface ingested packet within {_POLL_TIMEOUT_SEC}s"
            )
            assert decrypted.payload == payload
            assert decrypted.device_id == device.id
        finally:
            _safe_delete(org, device.id)

    def test_aes_256_ctr_device_uptime_with_explicit_counter_and_seq(self, org):
        device = org.register_device(
            encryption="AES-256-CTR",
            counter_source="DEVICE_UPTIME",
        )
        assert device.id and device.key and len(device.key) == 32
        try:
            payload = b"int-up-" + os.urandom(4)
            counter = 5
            seq_no = 42
            pkt = encrypt(
                device.key, payload,
                time_counter=counter, seq_no=seq_no,
                counter_mode="DEVICE_UPTIME",
            )
            org.ingest_packet(pkt)

            decrypted = _wait_for_packet(org, device, payload)
            assert decrypted is not None
            assert decrypted.payload == payload
            assert decrypted.device_id == device.id
            assert decrypted.counter == counter
            assert decrypted.sequence == seq_no
        finally:
            _safe_delete(org, device.id)

    def test_aes_128_ctr_unix_time(self, org):
        device = org.register_device(
            encryption="AES-128-CTR",
            counter_source="UNIX_TIME",
        )
        assert device.id and device.key and len(device.key) == 16
        try:
            payload = b"int-128-" + os.urandom(4)
            pkt = encrypt(device.key, payload)
            org.ingest_packet(pkt)

            decrypted = _wait_for_packet(org, device, payload)
            assert decrypted is not None
            assert decrypted.payload == payload
            assert decrypted.device_id == device.id
        finally:
            _safe_delete(org, device.id)


class TestAesEaxRoundTripViaCloud:
    """Same round-trip with an AES-128-EAX device."""

    def test_aes_128_eax_device_uptime(self, org):
        # Cloud accepts period_exponent 10..15 for AES-128-EAX/DEVICE_UPTIME.
        period_exponent = 15
        device = org.register_device(
            encryption="AES-128-EAX",
            counter_source="DEVICE_UPTIME",
            period_exponent=period_exponent,
        )
        assert device.id and device.key and len(device.key) == 16
        try:
            payload = b"int-eax-" + os.urandom(1)  # 9 bytes max for EAX
            pkt = encrypt_eax(
                device.key, payload,
                counter=0, period_exponent=period_exponent,
            )
            org.ingest_packet(pkt)

            decrypted = _wait_for_packet(org, device, payload)
            assert decrypted is not None, (
                f"backend did not surface ingested EAX packet within {_POLL_TIMEOUT_SEC}s"
            )
            assert decrypted.payload == payload
            assert decrypted.device_id == device.id
        finally:
            _safe_delete(org, device.id)
