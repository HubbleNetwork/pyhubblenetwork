"""Cloud packet decoding: request shape, batching, alignment, errors (all mocked)."""
from __future__ import annotations

import base64
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from hubblenetwork import cloud, crypto
from hubblenetwork.errors import (
    BackendError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    RequestError,
)
from hubblenetwork.org import Organization
from hubblenetwork.packets import (
    AesEaxPacket,
    EncryptedPacket,
    Location,
    UnencryptedPacket,
    UnknownPacket,
)
from tests.fake_packets import (
    as_packet,
    ctr_eid,
    make_ctr,
    make_eax,
    today_counter,
)

KEY_256 = bytes(range(32))
KEY_128 = bytes(range(16))
ENV = cloud.Environment("TESTING", "https://example.invalid")
CREDS = cloud.Credentials("org-1", "tok")
DEVICE_ID = "3f4b2c0c-2d43-4cbe-9c1f-0a4c2d59e2a1"


def _org() -> Organization:
    org = Organization.__new__(Organization)
    org.credentials = CREDS
    org.env = ENV
    org.name = "test"
    return org


def _cloud_item(adv_b64: str, payload: bytes = b"hi", seq: int = 3, ctr: int = 7) -> dict:
    return {
        "location": {"latitude": 1.0, "longitude": 2.0},
        "device": {
            "id": DEVICE_ID,
            "name": "dev-a",
            "tags": {"k": "v"},
            "payload": base64.b64encode(payload).decode(),
            "timestamp": 1758200000.5,
            "rssi": -61,
            "sequence_number": seq,
            "counter": ctr,
        },
        "network_type": "TERRESTRIAL",
        "advertisement": {"payload": adv_b64},
    }


def _echo_all(advertisements, **_):
    """Stand-in for cloud.decode_packets that decrypts everything."""
    return [_cloud_item(a["payload"]) for a in advertisements]


# ---------------------------------------------------------------------------
# Fake packet generator round-trips against the SDK's own decryptors
# ---------------------------------------------------------------------------


class TestFakePackets:
    def test_ctr_unix_time_round_trip_256(self):
        pkt = as_packet(make_ctr(KEY_256, b"hello-ut", seq_no=9))
        assert isinstance(pkt, EncryptedPacket)
        res = crypto.decrypt(KEY_256, pkt)
        assert res.payload == b"hello-ut"
        assert res.counter == today_counter()
        assert res.sequence == 9

    def test_ctr_unix_time_round_trip_128(self):
        res = crypto.decrypt(KEY_128, as_packet(make_ctr(KEY_128, b"a128")))
        assert res.payload == b"a128"

    def test_ctr_device_uptime_round_trip(self):
        pkt = as_packet(make_ctr(KEY_256, b"hello-du", time_counter=5, seq_no=7))
        res = crypto.decrypt(KEY_256, pkt, counter_mode=crypto.DEVICE_UPTIME)
        assert (res.payload, res.counter, res.sequence) == (b"hello-du", 5, 7)
        assert crypto.decrypt(KEY_256, pkt) is None  # not a UNIX_TIME packet

    def test_ctr_header_carries_the_eid(self):
        pkt = as_packet(make_ctr(KEY_256, b"x", time_counter=5))
        assert pkt.eid == ctr_eid(KEY_256, 5)
        assert pkt.protocol_version == 0

    @pytest.mark.parametrize("exponent,index", [(0, 3), (10, 5), (15, 1)])
    def test_eax_round_trip(self, exponent, index):
        pkt = as_packet(make_eax(KEY_128, b"eax-ok", index=index, period_exponent=exponent))
        assert isinstance(pkt, AesEaxPacket)
        res = crypto.decrypt_eax(KEY_128, pkt, period_exponent=exponent)
        assert res.payload == b"eax-ok"
        assert res.counter == index

    def test_eax_wrong_key_fails(self):
        pkt = as_packet(make_eax(KEY_128, b"eax", index=1, period_exponent=0))
        assert crypto.decrypt_eax(bytes(16), pkt) is None

    def test_rejects_oversized_payloads(self):
        with pytest.raises(ValueError):
            make_ctr(KEY_256, b"x" * 14)
        with pytest.raises(ValueError):
            make_eax(KEY_128, b"x" * 10)


# ---------------------------------------------------------------------------
# Raw advertisement bytes
# ---------------------------------------------------------------------------


class TestAdvertisementBytes:
    def test_eax_raw_is_byte_identical_to_service_data(self):
        raw = make_eax(KEY_128, b"payload", index=2, period_exponent=0)
        pkt = as_packet(raw)
        assert pkt.raw == raw
        assert cloud.advertisement_bytes(pkt) == raw

    def test_eax_without_raw_is_reserialized_faithfully(self):
        raw = make_eax(KEY_128, b"p", index=1, period_exponent=0)
        pkt = as_packet(raw)
        from dataclasses import replace

        assert cloud.advertisement_bytes(replace(pkt, raw=None)) == raw

    def test_ctr_payload_is_the_whole_advertisement(self):
        raw = make_ctr(KEY_256, b"abc")
        assert cloud.advertisement_bytes(as_packet(raw)) == raw

    def test_unsupported_types_rejected(self):
        pkt = UnknownPacket(0, None, 9, b"x", -50)
        with pytest.raises(ValueError):
            cloud.advertisement_bytes(pkt)


# ---------------------------------------------------------------------------
# cloud.decode_packets: one request
# ---------------------------------------------------------------------------


class TestCloudDecodeRequest:
    def test_request_body_shape(self):
        raw = make_ctr(KEY_256, b"abc")
        pkt = EncryptedPacket(
            timestamp=1758200000, location=None, payload=raw, rssi=-60
        )
        adv = cloud.packet_to_advertisement(pkt)
        with patch.object(cloud, "cloud_request", return_value=({"packets": []}, None)) as req:
            out = cloud.decode_packets(
                credentials=CREDS, env=ENV, advertisements=[adv],
                metadata={"platform": "test"},
            )
        assert out == []
        kw = req.call_args.kwargs
        assert kw["method"] == "POST"
        assert kw["path"] == "/org/org-1/packets/decode"
        body = kw["json"]
        assert body["metadata"] == {"platform": "test"}
        (sent,) = body["advertisements"]
        assert base64.b64decode(sent["payload"]) == raw
        assert sent["rssi"] == -60 and isinstance(sent["rssi"], int)
        assert sent["timestamp"] == 1758200000.0 and isinstance(sent["timestamp"], float)
        loc = sent["location"]
        # Backend requires a location; None becomes a placeholder.
        assert (loc["latitude"], loc["longitude"], loc["altitude"]) == (0.0, 0.0, 0.0)
        assert loc["timestamp"] == 1758200000.0
        assert {"horizontal_accuracy", "vertical_accuracy"} <= loc.keys()

    def test_real_location_is_sent(self):
        pkt = EncryptedPacket(
            timestamp=1, location=Location(lat=90, lon=0, fake=True),
            payload=b"\x00" * 12, rssi=-60,
        )
        loc = cloud.packet_to_advertisement(pkt)["location"]
        assert (loc["latitude"], loc["longitude"]) == (90.0, 0.0)

    def test_hits_the_api_alias_path(self):
        seen = {}
        with self._respond(200, {"packets": []}, seen=seen):
            cloud.decode_packets(
                credentials=CREDS, env=ENV,
                advertisements=[{"payload": "AA==", "rssi": -1}],
            )
        assert seen["url"] == "https://example.invalid/api/org/org-1/packets/decode"
        assert seen["auth"] == "Bearer tok"

    def test_metadata_omitted_by_default(self):
        with patch.object(cloud, "cloud_request", return_value=({"packets": []}, None)) as req:
            cloud.decode_packets(credentials=CREDS, env=ENV, advertisements=[{}])
        assert "metadata" not in req.call_args.kwargs["json"]

    def test_rejects_empty_and_oversized(self):
        with pytest.raises(ValueError):
            cloud.decode_packets(credentials=CREDS, env=ENV, advertisements=[])
        with pytest.raises(ValueError):
            cloud.decode_packets(credentials=CREDS, env=ENV, advertisements=[{}] * 26)

    def _respond(self, status, body, seen=None):
        """Patch httpx.Client to answer every request with ``status``/``body``.

        If ``seen`` is a dict, the request's URL and auth header are recorded in it.
        """
        class _Client:
            def __init__(self, **_):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def request(self, method, url, **kw):
                if seen is not None:
                    seen["url"] = url
                    seen["auth"] = kw["headers"]["Authorization"]
                return httpx.Response(status, json=body)

        return patch.object(cloud.httpx, "Client", _Client)

    def test_403_names_the_scope(self):
        with self._respond(403, {"error": "forbidden"}):
            with pytest.raises(PermissionDeniedError, match="read-packets"):
                cloud.decode_packets(credentials=CREDS, env=ENV, advertisements=[{}])

    def test_429_is_a_rate_limit_error(self):
        with self._respond(429, {"error": "slow down"}):
            with pytest.raises(RateLimitError):
                cloud.decode_packets(credentials=CREDS, env=ENV, advertisements=[{}])

    def test_huge_400_body_is_truncated(self):
        with self._respond(400, {"error": "x" * 5000}):
            with pytest.raises(RequestError) as exc:
                cloud.decode_packets(credentials=CREDS, env=ENV, advertisements=[{}])
        assert len(str(exc.value)) < 400

    def test_404_maps_to_not_found(self):
        with self._respond(404, {"error": "nope"}):
            with pytest.raises(NotFoundError):
                cloud.get_device(credentials=CREDS, env=ENV, device_id="d")


# ---------------------------------------------------------------------------
# Organization.decode_packets: batching and alignment
# ---------------------------------------------------------------------------


class TestOrganizationDecode:
    def test_chunks_at_25(self):
        pkts = [as_packet(make_ctr(KEY_256, b"p", seq_no=i)) for i in range(60)]
        with patch.object(cloud, "decode_packets", side_effect=_echo_all) as dec:
            out = _org().decode_packets(pkts)
        sizes = [len(c.kwargs["advertisements"]) for c in dec.call_args_list]
        assert sizes == [25, 25, 10]
        assert all(r is not None for r in out)

    def test_alignment_and_none_for_omitted(self):
        pkts = [as_packet(make_ctr(KEY_256, b"p", seq_no=i)) for i in range(5)]

        def only_odd(advertisements, **_):
            return [
                _cloud_item(a["payload"], payload=bytes([i]))
                for i, a in enumerate(advertisements)
                if i % 2
            ][::-1]  # response order must not matter

        with patch.object(cloud, "decode_packets", side_effect=only_odd):
            out = _org().decode_packets(pkts)
        assert [r is not None for r in out] == [False, True, False, True, False]
        assert out[1].payload == b"\x01" and out[3].payload == b"\x03"

    def test_result_fields(self):
        pkt = as_packet(make_ctr(KEY_256, b"p", seq_no=4), rssi=-72)
        with patch.object(cloud, "decode_packets", side_effect=_echo_all):
            (res,) = _org().decode_packets([pkt])
        assert res.device_id == DEVICE_ID
        assert res.device_name == "dev-a"
        assert res.tags == {"k": "v"}
        assert res.payload == b"hi"
        assert (res.sequence, res.counter) == (3, 7)
        # Reception details come from the packet that was heard.
        assert res.rssi == -72 and res.timestamp == pkt.timestamp
        assert res.eid == pkt.eid

    def test_duplicates_sent_once_and_both_answered(self):
        raw = make_ctr(KEY_256, b"dup")
        pkts = [as_packet(raw, rssi=-50), as_packet(raw, rssi=-80)]
        with patch.object(cloud, "decode_packets", side_effect=_echo_all) as dec:
            out = _org().decode_packets(pkts)
        assert len(dec.call_args.kwargs["advertisements"]) == 1
        assert [r.rssi for r in out] == [-50, -80]

    def test_eax_sent_with_raw_bytes(self):
        raw = make_eax(KEY_128, b"e", index=1, period_exponent=0)
        with patch.object(cloud, "decode_packets", side_effect=_echo_all) as dec:
            (res,) = _org().decode_packets([as_packet(raw)])
        sent = dec.call_args.kwargs["advertisements"][0]
        assert base64.b64decode(sent["payload"]) == raw
        assert res is not None

    def test_out_of_window_and_empty_are_not_sent(self):
        old = as_packet(make_ctr(KEY_256, b"o"), timestamp=int(time.time()) - 73 * 3600)
        future = as_packet(make_ctr(KEY_256, b"f"), timestamp=int(time.time()) + 3 * 3600)
        empty = EncryptedPacket(timestamp=int(time.time()), location=None, payload=b"", rssi=-1)
        good = as_packet(make_ctr(KEY_256, b"g"))
        with patch.object(cloud, "decode_packets", side_effect=_echo_all) as dec:
            out = _org().decode_packets([old, future, empty, good])
        assert len(dec.call_args.kwargs["advertisements"]) == 1
        assert [r is not None for r in out] == [False, False, False, True]

    def test_nothing_to_send_makes_no_request(self):
        with patch.object(cloud, "decode_packets") as dec:
            assert _org().decode_packets([]) == []
        dec.assert_not_called()

    @pytest.mark.parametrize(
        "pkt",
        [
            UnencryptedPacket(0, None, 1, 1, b"x", -50),
            UnknownPacket(0, None, 9, b"x", -50),
            MagicMock(),
        ],
    )
    def test_unsupported_packet_types_raise(self, pkt):
        with pytest.raises(ValueError):
            _org().decode_packets([pkt])

    def test_backend_errors_propagate(self):
        pkt = as_packet(make_ctr(KEY_256, b"p"))
        with patch.object(cloud, "decode_packets", side_effect=BackendError("500: boom")):
            with pytest.raises(BackendError):
                _org().decode_packets([pkt])

    def test_get_device(self):
        with patch.object(cloud, "get_device", return_value={"id": DEVICE_ID, "name": "n"}):
            dev = _org().get_device(DEVICE_ID)
        assert dev.id == DEVICE_ID and dev.name == "n"
