"""Key-setup diagnosis: evidence gathering and the cross-check rules.

Packets are built with real crypto, the way hubble-device-sdk builds them, so
each misconfiguration is exercised through the same EID and auth-tag paths a
real board would hit: the wrong counter mode, a 32-byte key in an AES-128
build, a skewed clock, a key that is simply wrong.
"""

import dataclasses
import time

from hubblenetwork import diagnose as dg
from hubblenetwork.crypto import (
    DEVICE_UPTIME,
    UNIX_TIME,
    ctr_eid,
    decrypt_at,
    eax_eid_index,
)
from hubblenetwork.device import Device
from hubblenetwork.packets import EncryptedPacket
from tests.test_aes_eax import _build_eax_packet_at_exponent
from tests.test_counter_eid import _encrypt_payload

KEY = bytes(range(32))
OTHER = bytes(range(1, 33))
NOW = 1_790_000_000.0
TODAY = int(NOW) // 86400


def _ctr(key, counter, seq=7, plaintext=b"hi", eid=None, tamper=False):
    """An AES-CTR advertisement exactly as the SDK's hubble_ble.c lays it out."""
    p = _encrypt_payload(key, counter, seq, plaintext)  # seq | pad(4) | tag | ct
    eid = ctr_eid(key, counter) if eid is None else eid
    raw = p[:2] + eid + p[6:]
    if tamper:
        raw = raw[:10] + bytes([raw[10] ^ 1]) + raw[11:]
    return EncryptedPacket(
        timestamp=int(NOW), location=None, payload=raw, rssi=-60,
        protocol_version=0, eid=int.from_bytes(eid, "big"), auth_tag=raw[6:10], seq_no=seq,
    )


def _eax(key, exponent, tamper=False):
    """An AES-EAX packet in pool slot 3 (see test_aes_eax)."""
    pkt = _build_eax_packet_at_exponent(key, exponent, b"hi")
    if tamper:
        pkt = dataclasses.replace(pkt, auth_tag=bytes([pkt.auth_tag[0] ^ 1]) + pkt.auth_tag[1:])
    return pkt


def _air(pkts, key=KEY):
    scan = dg.AirScan(key, now=NOW)
    for pkt in pkts:
        scan.add(pkt)
    return scan.evidence()


def _device(**kw):
    base = {"id": "dev-1", "name": "board", "encryption": dg.AES_256_CTR,
            "counter_source": UNIX_TIME, "last_packet_ts": None}
    base.update(kw)
    return Device(**base)


def _rows(**kw):
    for name, default in (("key", KEY), ("device", None), ("air", None), ("now", NOW)):
        kw.setdefault(name, default)
    return {f.check: f for f in dg.diagnose(**kw)}


# ---------------------------------------------------------------------------
# crypto primitives
# ---------------------------------------------------------------------------


class TestCryptoPrimitives:
    def test_ctr_eid_matches_the_device_sdk_reference_tool(self):
        # Vectors from hubble-device-sdk tools/ble-adv.py get_device_id().
        assert ctr_eid(KEY, 0).hex() == "69aacffb"
        assert ctr_eid(KEY, 20000).hex() == "b5461b3a"

    def test_decrypt_at_only_succeeds_on_the_right_counter(self):
        pkt = _ctr(KEY, TODAY, plaintext=b"payload")
        assert decrypt_at(KEY, pkt, TODAY).payload == b"payload"
        assert decrypt_at(KEY, pkt, TODAY + 1) is None

    def test_eax_eid_index_matches_without_a_valid_tag(self):
        pkt = _eax(KEY[:16], exponent=4, tamper=True)
        assert eax_eid_index(KEY[:16], pkt, period_exponent=4) == 3
        assert eax_eid_index(KEY[:16], pkt, period_exponent=3) is None


# ---------------------------------------------------------------------------
# air
# ---------------------------------------------------------------------------


class TestAnalyzeAir:
    def test_unix_time_device_is_found_among_other_devices(self):
        noise = [_ctr(OTHER, TODAY, s) for s in range(4)]
        air = _air(noise + [_ctr(KEY, TODAY, s) for s in range(3)])
        m = air.match
        assert air.heard == 7
        assert (m.encryption, m.counter_source, m.key_variant) == (dg.AES_256_CTR, UNIX_TIME, "full")
        assert (m.packets, m.day_delta, m.authenticated) == (3, 0, True)

    def test_device_uptime_counter_is_recognised(self):
        m = _air([_ctr(KEY, 42)]).match
        assert (m.counter_source, m.counter, m.day_delta) == (DEVICE_UPTIME, 42, None)

    def test_aes128_build_using_the_first_half_of_a_32_byte_key(self):
        m = _air([_ctr(KEY[:16], TODAY)]).match
        assert (m.encryption, m.key_variant) == (dg.AES_128_CTR, "first16")

    def test_clock_skew_far_outside_the_decrypt_window(self):
        assert _air([_ctr(KEY, TODAY - 40)]).match.day_delta == -40

    def test_wrong_key_matches_nothing(self):
        air = _air([_ctr(OTHER, TODAY)])
        assert air.heard == 1 and air.match is None

    def test_eid_match_with_a_bad_payload_is_not_authenticated(self):
        m = _air([_ctr(KEY, TODAY, tamper=True)]).match
        assert m is not None and not m.authenticated

    def test_right_key_with_a_non_sdk_eid_is_its_own_finding(self):
        # The tag sweep still finds the key, but a wrong EID is exactly what
        # would stop the backend attributing the packet: report it, don't pass.
        air = _air([_ctr(KEY, TODAY, eid=b"\x00\x00\x00\x00")])
        assert air.match.authenticated and air.match.eid_mismatch
        row = _rows(air=air)["Over the air"]
        assert row.status == dg.FAIL and "wrong EID" in row.summary

    def test_aes_eax_period_exponent_is_identified(self):
        m = _air([_eax(KEY[:16], exponent=6)], key=KEY[:16]).match
        assert (m.encryption, m.period_exponent, m.authenticated) == (dg.AES_128_EAX, 6, True)

    def test_no_packets(self):
        air = _air([])
        assert (air.heard, air.match) == (0, None)


# ---------------------------------------------------------------------------
# firmware
# ---------------------------------------------------------------------------

_DOTCONFIG = """\
CONFIG_HUBBLE_BLE_NETWORK=y
# CONFIG_HUBBLE_NETWORK_KEY_256 is not set
CONFIG_HUBBLE_NETWORK_KEY_128=y
# CONFIG_HUBBLE_COUNTER_SOURCE_UNIX_TIME is not set
CONFIG_HUBBLE_COUNTER_SOURCE_DEVICE_UPTIME=y
CONFIG_HUBBLE_KEY_SIZE=16
"""


def _ihex(data: bytes, base: int = 0x0800_0000) -> str:
    """Minimal Intel HEX, with an extended linear address record."""
    def rec(kind, addr, payload):
        body = bytes([len(payload), addr >> 8, addr & 0xFF, kind]) + payload
        return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()
    lines = [rec(0x04, 0, (base >> 16).to_bytes(2, "big"))]
    for off in range(0, len(data), 16):
        lines.append(rec(0x00, (base & 0xFFFF) + off, data[off:off + 16]))
    lines.append(rec(0x01, 0, b""))
    return "\n".join(lines)


class TestFirmware:
    def test_parse_kconfig_reads_set_and_unset_symbols(self):
        sym = dg.parse_kconfig(_DOTCONFIG)
        assert sym["HUBBLE_NETWORK_KEY_128"] == "y"
        assert sym["HUBBLE_NETWORK_KEY_256"] == "n"
        assert sym["HUBBLE_KEY_SIZE"] == "16"

    def test_parse_kconfig_reads_autoconf_header(self):
        sym = dg.parse_kconfig("#define CONFIG_HUBBLE_NETWORK_KEY_256 1\n")
        assert sym["HUBBLE_NETWORK_KEY_256"] == "y"

    def test_build_dir_config_and_compiled_in_key(self, tmp_path):
        zephyr = tmp_path / "build" / "zephyr"
        zephyr.mkdir(parents=True)
        (zephyr / ".config").write_text(_DOTCONFIG)
        (zephyr / "zephyr.bin").write_bytes(b"\x00" * 100 + KEY + b"\xff" * 50)
        fw = dg.inspect_firmware(tmp_path, KEY)
        assert (fw.encryption, fw.counter_source) == (dg.AES_128_CTR, DEVICE_UPTIME)
        assert fw.key_found == "full"

    def test_only_half_the_key_in_the_image(self, tmp_path):
        (tmp_path / "app.bin").write_bytes(b"\x00" * 10 + KEY[:16] + b"\x11" * 16)
        assert dg.inspect_firmware(tmp_path, KEY).key_found == "first16"

    def test_key_absent(self, tmp_path):
        (tmp_path / "app.elf").write_bytes(b"\x7fELF" + b"\x00" * 200)
        assert dg.inspect_firmware(tmp_path, KEY).key_found == "none"

    def test_key_found_inside_an_intel_hex_file(self, tmp_path):
        image = tmp_path / "zephyr.hex"
        image.write_text(_ihex(b"\xaa" * 7 + KEY + b"\xbb" * 9))
        assert dg.inspect_firmware(image, KEY).key_found == "full"

    def test_intel_hex_splits_non_contiguous_runs(self):
        first = _ihex(b"\x01" * 16, base=0x1000).splitlines()[:-1]  # drop its EOF
        text = "\n".join(first) + "\n" + _ihex(b"\x02" * 16, base=0x9000)
        assert dg.read_intel_hex(text) == [b"\x01" * 16, b"\x02" * 16]

    def test_intel_hex_stops_at_the_eof_record(self):
        text = _ihex(b"\x01" * 16) + "\n" + _ihex(b"\x02" * 16, base=0x9000)
        assert dg.read_intel_hex(text) == [b"\x01" * 16]

    def test_psa_key_id_build_is_a_skip_not_a_failure(self, tmp_path):
        (tmp_path / ".config").write_text(
            _DOTCONFIG + "CONFIG_HUBBLE_NETWORK_CRYPTO_PSA_USE_KEY_ID=y\n"
        )
        (tmp_path / "zephyr.bin").write_bytes(b"\x00" * 64)
        rows = _rows(firmware=dg.inspect_firmware(tmp_path, KEY))
        assert rows["Firmware key"].status == dg.SKIP
        assert "PSA" in rows["Firmware key"].summary


# Exactly what hubble-device-sdk's hdcv.h produces for these two builds.
HDCV_128_UT = b"HDCV:1.0/E:128/CS:UT/RP:S86400/N:T/TV:0"
HDCV_256_DU = b"HDCV:1.0/E:256/CS:DU/EC:128/RP:S86400/N:T/TV:0"


def _image(*parts):
    """Bytes of a fake image: padding around each part, as in a real binary."""
    return b"\x00\x13".join([b"\xff" * 40, *parts, b"\xee" * 40])


class TestFirmwareConfigVector:
    def test_parse_hdcv(self):
        assert dg.parse_hdcv(HDCV_256_DU.decode()) == {
            "HDCV": "1.0", "E": "256", "CS": "DU", "EC": "128", "RP": "S86400",
            "N": "T", "TV": "0",
        }

    def test_config_is_read_from_the_image_alone(self, tmp_path):
        image = tmp_path / "app.elf"
        image.write_bytes(_image(HDCV_128_UT, KEY[:16]))
        fw = dg.inspect_firmware(image, KEY[:16])
        assert (fw.config_source, fw.encryption, fw.counter_source) == (
            "image", dg.AES_128_CTR, UNIX_TIME,
        )
        assert fw.key_found == "full"

    def test_ihex_is_an_image(self, tmp_path):
        # The EM9305 SDK names its Intel HEX output .ihex.
        image = tmp_path / "app.ihex"
        image.write_text(_ihex(_image(HDCV_256_DU)))
        fw = dg.inspect_firmware(image, KEY)
        assert (fw.encryption, fw.counter_source) == (dg.AES_256_CTR, DEVICE_UPTIME)

    def test_image_beats_a_stale_kconfig(self, tmp_path):
        zephyr = tmp_path / "build" / "zephyr"
        zephyr.mkdir(parents=True)
        (zephyr / ".config").write_text(_DOTCONFIG)  # says AES-128, DEVICE_UPTIME
        (zephyr / "zephyr.bin").write_bytes(_image(b"HDCV:1.0/E:256/CS:UT/N:T"))
        fw = dg.inspect_firmware(tmp_path, KEY)
        assert (fw.encryption, fw.counter_source) == (dg.AES_256_CTR, UNIX_TIME)
        assert fw.config_conflict == "AES-128-CTR, DEVICE_UPTIME"
        row = _rows(firmware=fw)["Firmware"]
        assert row.status == dg.OK
        assert any("stale build tree" in line for line in row.advice)

    def test_project_image_beats_a_vendor_sdk_image(self, tmp_path):
        # The EM9305 layout: the app under build/, the vendor SDK's prebuilt
        # bootloader images under external/.
        (tmp_path / "external" / "sdk").mkdir(parents=True)
        (tmp_path / "external" / "sdk" / "app_bootloader.elf").write_bytes(_image(b"boot"))
        (tmp_path / "build" / "app").mkdir(parents=True)
        (tmp_path / "build" / "app" / "app.elf").write_bytes(_image(HDCV_128_UT, KEY[:16]))
        fw = dg.inspect_firmware(tmp_path, KEY[:16])
        assert fw.hdcv_image.endswith("app.elf") and "build" in fw.hdcv_image
        assert fw.key_image == fw.hdcv_image

    def test_differing_images_are_called_out(self, tmp_path):
        (tmp_path / "a.bin").write_bytes(_image(HDCV_128_UT))
        (tmp_path / "b.bin").write_bytes(_image(HDCV_256_DU))
        row = _rows(firmware=dg.inspect_firmware(tmp_path, KEY))["Firmware"]
        assert any("2 images carry different configs" in line for line in row.advice)

    def test_kconfig_fallback_for_sdks_older_than_hdcv(self, tmp_path):
        (tmp_path / ".config").write_text(_DOTCONFIG)
        (tmp_path / "zephyr.bin").write_bytes(_image(b"no vector here"))
        fw = dg.inspect_firmware(tmp_path, KEY)
        assert (fw.config_source, fw.encryption) == ("kconfig", dg.AES_128_CTR)
        assert "older than HDCV" in _rows(firmware=fw)["Firmware"].advice[0]

    def test_image_config_drives_the_encryption_check(self, tmp_path):
        image = tmp_path / "app.hex"
        image.write_text(_ihex(_image(HDCV_128_UT)))
        rows = _rows(device=_device(), firmware=dg.inspect_firmware(image, KEY))
        assert rows["Encryption"].summary == (
            "registered AES-256-CTR, but the firmware is built for AES-128-CTR"
        )


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


class TestBackendRows:

    def test_recent_packet_means_decoded_on_the_backend(self):
        dev = _device(last_packet_ts={"terrestrial": NOW - 180})
        row = _rows(device=dev)["Backend"]
        assert row.status == dg.OK
        assert "being decoded" in row.summary and "3m ago" in row.summary

    def test_six_minutes_old_is_not_a_pass(self):
        # Five minutes by default: an older packet may predate a reflash or a
        # key change, which is exactly what this command is run to catch.
        dev = _device(last_packet_ts={"terrestrial": NOW - 6 * 60})
        row = _rows(device=dev)["Backend"]
        assert row.status == dg.FAIL
        assert row.summary == "last decoded 6m ago (BLE), nothing in the last 5m"
        assert any("predate a reflash" in line for line in row.advice)


    def test_stale_packet_is_a_failure(self):
        dev = _device(last_packet_ts={"satellite": NOW - 30 * 86400})
        row = _rows(device=dev)["Backend"]
        assert row.status == dg.FAIL and "30d ago (satellite)" in row.summary
        assert any("something changed" in line for line in row.advice)

    def test_never_decoded(self):
        row = _rows(device=_device())["Backend"]
        assert row.status == dg.FAIL and "never" in row.summary


class TestCounterModeRows:
    def test_registered_unix_but_flashed_with_device_uptime(self):
        rows = _rows(device=_device(), key=KEY, air=_air([_ctr(KEY, 42)]))
        row = rows["Counter mode"]
        assert row.status == dg.FAIL
        assert row.summary == (
            "registered UNIX_TIME, but the device is broadcasting DEVICE_UPTIME"
        )
        assert any("1970" in line for line in row.advice)

    def test_registered_uptime_but_firmware_built_unix(self, tmp_path):
        (tmp_path / ".config").write_text("CONFIG_HUBBLE_COUNTER_SOURCE_UNIX_TIME=y\n")
        rows = _rows(
            device=_device(counter_source=DEVICE_UPTIME),
            firmware=dg.inspect_firmware(tmp_path, KEY),
        )
        assert rows["Counter mode"].summary == (
            "registered DEVICE_UPTIME, but the firmware is built for UNIX_TIME"
        )

    def _fw(self, tmp_path, hdcv):
        image = tmp_path / "app.elf"
        image.write_bytes(_image(hdcv))
        return dg.inspect_firmware(image, KEY)

    def test_unix_build_with_an_uptime_counter_is_an_unset_clock(self, tmp_path):
        # Registration and build both say UNIX_TIME, so counter 42 is not
        # uptime: the device's Unix clock reads 42 days after the epoch.
        rows = _rows(
            device=_device(), key=KEY, air=_air([_ctr(KEY, 42)]),
            firmware=self._fw(tmp_path, b"HDCV:1.0/E:256/CS:UT/N:T"),
        )
        assert rows["Counter mode"].status == dg.OK
        assert "registration, firmware and air agree" in rows["Counter mode"].summary
        assert rows["Over the air"].summary.endswith("UNIX_TIME (clock unset)")
        clock = rows["Clock"]
        assert clock.status == dg.FAIL
        assert clock.summary == "device clock reads 1970-02-12: Unix time was never set"
        assert any("isn't running this image" in line for line in clock.advice)

    def test_firmware_disagreeing_with_registration_is_the_reported_cause(self, tmp_path):
        rows = _rows(
            device=_device(), key=KEY, air=_air([_ctr(KEY, 42)]),
            firmware=self._fw(tmp_path, HDCV_256_DU),
        )
        assert rows["Counter mode"].summary == (
            "registered UNIX_TIME, but the firmware is built for DEVICE_UPTIME"
        )
        assert "Clock" not in rows

    def test_unix_build_is_not_reread_against_an_uptime_registration(self, tmp_path):
        rows = _rows(
            device=_device(counter_source=DEVICE_UPTIME), key=KEY,
            air=_air([_ctr(KEY, 42)]), firmware=self._fw(tmp_path, b"HDCV:1.0/E:256/CS:UT"),
        )
        assert rows["Counter mode"].summary == (
            "registered DEVICE_UPTIME, but the firmware is built for UNIX_TIME"
        )
        assert "Clock" not in rows

    def test_agreement_row_needs_two_sources(self):
        alone = _rows(device=_device())
        assert "Counter mode" not in alone
        both = _rows(device=_device(), key=KEY, air=_air([_ctr(KEY, TODAY)]))
        assert both["Counter mode"].status == dg.OK
        assert "registration and air agree" in both["Counter mode"].summary


class TestEncryptionRows:
    def test_aes128_build_with_a_registered_aes256_key(self):
        rows = _rows(
            device=_device(), key=KEY, air=_air([_ctr(KEY[:16], TODAY)]),
        )
        row = rows["Encryption"]
        assert row.status == dg.FAIL
        assert "first 16 bytes" in row.summary
        assert any("defaults to AES-256-CTR" in line for line in row.advice)

    def test_key_length_disagrees_with_registration(self):
        row = _rows(device=_device(), key=KEY[:16])["Encryption"]
        assert row.status == dg.FAIL
        assert "16 bytes" in row.summary and "AES-256-CTR" in row.summary

    def test_eax_device_registered_as_ctr(self):
        k = KEY[:16]
        rows = _rows(
            device=_device(encryption=dg.AES_128_CTR), key=k,
            air=_air([_eax(k, exponent=5)], key=k),
        )
        assert rows["Encryption"].summary == (
            "registered AES-128-CTR, but the device is broadcasting AES-128-EAX"
        )

    def test_firmware_key_size_disagrees_with_registration(self, tmp_path):
        (tmp_path / ".config").write_text("CONFIG_HUBBLE_NETWORK_KEY_128=y\n")
        rows = _rows(device=_device(), firmware=dg.inspect_firmware(tmp_path, KEY))
        assert rows["Encryption"].summary == (
            "registered AES-256-CTR, but the firmware is built for AES-128-CTR"
        )


class TestClockAndPeriodRows:
    def test_clock_days_off_is_a_failure(self):
        row = _rows(key=KEY, air=_air([_ctr(KEY, TODAY + 9)]))["Clock"]
        assert row.status == dg.FAIL and row.summary == "device clock is 9 days ahead"

    def test_clock_within_tolerance(self):
        assert _rows(key=KEY, air=_air([_ctr(KEY, TODAY - 1)]))["Clock"].status == dg.OK

    def test_period_mismatch(self):
        k = KEY[:16]
        rows = _rows(
            device=_device(encryption=dg.AES_128_EAX, counter_source=DEVICE_UPTIME,
                           period_exponent=15),
            key=k, air=_air([_eax(k, exponent=10)], key=k),
        )
        assert rows["Period"].summary == "device rotates every 2^10s, registered 2^15s"


class TestAirRows:
    def test_nothing_heard(self):
        row = _rows(key=KEY, air=_air([]), timeout=15)["Over the air"]
        assert row.status == dg.FAIL and "in 15s" in row.summary

    def test_heard_but_not_this_key(self):
        row = _rows(key=KEY, air=_air([_ctr(OTHER, TODAY)]))["Over the air"]
        assert row.status == dg.FAIL
        assert row.summary == "no packets from this key (other Hubble devices were heard)"

    def test_summary_counts_only_this_keys_packets(self):
        air = _air([_ctr(OTHER, TODAY, s) for s in range(5)] + [_ctr(KEY, TODAY, s) for s in range(2)])
        row = _rows(key=KEY, air=air)["Over the air"]
        assert row.summary == "2 packets from this key: AES-256-CTR, UNIX_TIME"

    def test_eid_only_match_points_at_firmware_crypto(self):
        row = _rows(key=KEY, air=_air([_ctr(KEY, TODAY, tamper=True)]))["Over the air"]
        assert row.status == dg.FAIL and "no payload authenticates" in row.summary


class TestDeliveryRow:
    def _good(self, **kw):
        return _rows(device=_device(), key=KEY,
                     air=_air([_ctr(KEY, TODAY)]), **kw)

    def test_right_setup_but_nothing_reaches_the_cloud(self):
        row = self._good()["Delivery"]
        assert row.status == dg.FAIL
        assert any("gateway" in line for line in row.advice)

    def test_not_claimed_when_the_setup_itself_is_wrong(self):
        rows = _rows(device=_device(), key=KEY, air=_air([_ctr(KEY, 42)]))
        assert "Delivery" not in rows

    def test_not_claimed_when_the_backend_is_decoding(self):
        dev = _device(last_packet_ts={"terrestrial": NOW - 60})
        rows = _rows(device=dev, key=KEY, air=_air([_ctr(KEY, TODAY)]))
        assert "Delivery" not in rows
        assert all(r.status == dg.OK for r in rows.values())


class TestAirScanStopsEarly:
    """AirScan.add() is ble.scan's `until`: True ends the scan."""

    def test_true_only_once_this_keys_packet_authenticates(self):
        scan = dg.AirScan(KEY, now=NOW)
        assert scan.add(_ctr(OTHER, TODAY)) is False
        assert scan.add(_ctr(KEY, TODAY)) is True

    def test_an_eid_match_that_fails_auth_does_not_stop_the_scan(self):
        scan = dg.AirScan(KEY, now=NOW)
        assert scan.add(_ctr(KEY, TODAY, seq=1, tamper=True)) is False
        # A later good packet from the same device does.
        assert scan.add(_ctr(KEY, TODAY, seq=2)) is True
        assert scan.evidence().match.packets == 2

    def test_eax(self):
        k = KEY[:16]
        assert dg.AirScan(k, now=NOW).add(_eax(k, exponent=3)) is True



class TestDeviceFromJson:
    def test_registration_config_and_last_packet(self):
        dev = Device.from_json({
            "id": "x", "encryption": "AES-128-EAX",
            "eid_rotation": {"counter_source": "DEVICE_UPTIME", "period_in_seconds": 1024},
            "most_recent_packet": {"terrestrial": {"timestamp": 5.0}, "satellite": None},
        })
        assert (dev.encryption, dev.counter_source, dev.period_exponent) == (
            "AES-128-EAX", "DEVICE_UPTIME", 10,
        )
        assert dev.last_packet_ts == {"terrestrial": 5.0}

    def test_list_endpoint_shape_leaves_config_unset(self):
        dev = Device.from_json({"id": "x", "name": "n", "active": True})
        assert (dev.encryption, dev.counter_source, dev.last_packet_ts) == (None, None, None)


def test_analysis_is_fast_enough_for_a_crowded_room():
    crowd = [_ctr(bytes([i]) * 32, TODAY, s) for i in range(40) for s in range(2)]
    start = time.perf_counter()
    _air(crowd + [_ctr(KEY, TODAY)])
    assert time.perf_counter() - start < 10
