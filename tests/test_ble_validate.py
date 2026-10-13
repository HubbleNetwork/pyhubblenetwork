"""`hubblenetwork ble validate` and the diagnosis behind it (hubblenetwork.validate).

Packets are built with real crypto, the way hubble-device-sdk builds them, so
each misconfiguration is exercised through the same EID and auth-tag paths a
real board would hit: the wrong counter mode, a 32-byte key in an AES-128
build, a skewed clock, a key that is simply wrong.

The CLI tests at the end lock the command's contract: what it needs, what it
prints, and that a failure exits 1 so it can gate a script, the same as
`doctor`.
"""

import dataclasses
import pathlib
import re
import time
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from hubblenetwork import validate as vd
from hubblenetwork.cli import _CHECK_OK, cli
from hubblenetwork.crypto import (
    DEVICE_UPTIME,
    UNIX_TIME,
    ctr_eid,
    decrypt_at,
    eax_eid_index,
)
from hubblenetwork.device import Device
from hubblenetwork.errors import NotFoundError, PermissionDeniedError, RateLimitError
from hubblenetwork.org import Organization
from hubblenetwork.packets import DecryptedPacket, EncryptedPacket
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
    scan = vd.AirScan(key, now=NOW)
    for pkt in pkts:
        scan.add(pkt)
    return scan.evidence()


def _device(**kw):
    base = {"id": "dev-1", "name": "board", "encryption": vd.AES_256_CTR,
            "counter_source": UNIX_TIME, "last_packet_ts": None}
    base.update(kw)
    return Device(**base)


def _rows(**kw):
    for name, default in (("key", KEY), ("device", None), ("air", None), ("now", NOW)):
        kw.setdefault(name, default)
    return {f.check: f for f in vd.diagnose(**kw)}


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
        sym = vd.parse_kconfig(_DOTCONFIG)
        assert sym["HUBBLE_NETWORK_KEY_128"] == "y"
        assert sym["HUBBLE_NETWORK_KEY_256"] == "n"
        assert sym["HUBBLE_KEY_SIZE"] == "16"

    def test_parse_kconfig_reads_autoconf_header(self):
        sym = vd.parse_kconfig("#define CONFIG_HUBBLE_NETWORK_KEY_256 1\n")
        assert sym["HUBBLE_NETWORK_KEY_256"] == "y"

    def test_build_dir_config_and_compiled_in_key(self, tmp_path):
        zephyr = tmp_path / "build" / "zephyr"
        zephyr.mkdir(parents=True)
        (zephyr / ".config").write_text(_DOTCONFIG)
        (zephyr / "zephyr.bin").write_bytes(b"\x00" * 100 + KEY + b"\xff" * 50)
        fw = vd.inspect_firmware(tmp_path, KEY)
        assert (fw.encryption, fw.counter_source) == (vd.AES_128_CTR, DEVICE_UPTIME)
        assert fw.key_found == "full"

    def test_only_half_the_key_in_the_image(self, tmp_path):
        (tmp_path / "app.bin").write_bytes(b"\x00" * 10 + KEY[:16] + b"\x11" * 16)
        assert vd.inspect_firmware(tmp_path, KEY).key_found == "first16"

    def test_key_absent(self, tmp_path):
        (tmp_path / "app.elf").write_bytes(b"\x7fELF" + b"\x00" * 200)
        assert vd.inspect_firmware(tmp_path, KEY).key_found == "none"

    def test_key_found_inside_an_intel_hex_file(self, tmp_path):
        image = tmp_path / "zephyr.hex"
        image.write_text(_ihex(b"\xaa" * 7 + KEY + b"\xbb" * 9))
        assert vd.inspect_firmware(image, KEY).key_found == "full"

    def test_intel_hex_splits_non_contiguous_runs(self):
        first = _ihex(b"\x01" * 16, base=0x1000).splitlines()[:-1]  # drop its EOF
        text = "\n".join(first) + "\n" + _ihex(b"\x02" * 16, base=0x9000)
        assert vd.read_intel_hex(text) == [b"\x01" * 16, b"\x02" * 16]

    def test_intel_hex_stops_at_the_eof_record(self):
        text = _ihex(b"\x01" * 16) + "\n" + _ihex(b"\x02" * 16, base=0x9000)
        assert vd.read_intel_hex(text) == [b"\x01" * 16]

    def test_psa_key_id_build_is_a_skip_not_a_failure(self, tmp_path):
        (tmp_path / ".config").write_text(
            _DOTCONFIG + "CONFIG_HUBBLE_NETWORK_CRYPTO_PSA_USE_KEY_ID=y\n"
        )
        (tmp_path / "zephyr.bin").write_bytes(b"\x00" * 64)
        rows = _rows(firmware=vd.inspect_firmware(tmp_path, KEY))
        assert rows["Firmware key"].status == vd.SKIP
        assert "PSA" in rows["Firmware key"].summary


# Exactly what hubble-device-sdk's hdcv.h produces for these two builds.
HDCV_128_UT = b"HDCV:1.0/E:128/CS:UT/RP:S86400/N:T/TV:0"
HDCV_256_DU = b"HDCV:1.0/E:256/CS:DU/EC:128/RP:S86400/N:T/TV:0"


def _image(*parts):
    """Bytes of a fake image: padding around each part, as in a real binary."""
    return b"\x00\x13".join([b"\xff" * 40, *parts, b"\xee" * 40])


class TestFirmwareConfigVector:
    def test_config_is_read_from_the_image_alone(self, tmp_path):
        image = tmp_path / "app.elf"
        image.write_bytes(_image(HDCV_128_UT, KEY[:16]))
        fw = vd.inspect_firmware(image, KEY[:16])
        assert (fw.config_source, fw.encryption, fw.counter_source) == (
            "image", vd.AES_128_CTR, UNIX_TIME,
        )
        assert fw.key_found == "full"

    def test_ihex_is_an_image(self, tmp_path):
        # The EM9305 SDK names its Intel HEX output .ihex.
        image = tmp_path / "app.ihex"
        image.write_text(_ihex(_image(HDCV_256_DU)))
        fw = vd.inspect_firmware(image, KEY)
        assert (fw.encryption, fw.counter_source) == (vd.AES_256_CTR, DEVICE_UPTIME)

    def test_image_beats_a_stale_kconfig(self, tmp_path):
        zephyr = tmp_path / "build" / "zephyr"
        zephyr.mkdir(parents=True)
        (zephyr / ".config").write_text(_DOTCONFIG)  # says AES-128, DEVICE_UPTIME
        (zephyr / "zephyr.bin").write_bytes(_image(b"HDCV:1.0/E:256/CS:UT/N:T"))
        fw = vd.inspect_firmware(tmp_path, KEY)
        assert (fw.encryption, fw.counter_source) == (vd.AES_256_CTR, UNIX_TIME)
        assert fw.config_conflict == "AES-128-CTR, DEVICE_UPTIME"
        row = _rows(firmware=fw)["Firmware"]
        assert row.status == vd.OK
        assert any("stale build tree" in line for line in row.advice)

    def test_config_comes_from_the_images_own_build_dir(self, tmp_path):
        # Two boards built side by side: the shallowest .config belongs to the
        # other board, and must not be read as this image's config.
        other = tmp_path / "build_a"
        other.mkdir()
        (other / ".config").write_text(_DOTCONFIG)  # AES-128, DEVICE_UPTIME
        mine = tmp_path / "build_b" / "zephyr"
        mine.mkdir(parents=True)
        (mine / ".config").write_text(
            "CONFIG_HUBBLE_NETWORK_KEY_256=y\nCONFIG_HUBBLE_COUNTER_SOURCE_UNIX_TIME=y\n"
        )
        (mine / "zephyr.elf").write_bytes(_image(b"HDCV:1.0/E:256/CS:UT/N:T"))
        fw = vd.inspect_firmware(tmp_path, KEY)
        assert pathlib.Path(fw.config_path).parent == mine
        assert fw.config_conflict is None

    def test_project_image_beats_a_vendor_sdk_image(self, tmp_path):
        # The EM9305 layout: the app under build/, the vendor SDK's prebuilt
        # bootloader images under external/.
        (tmp_path / "external" / "sdk").mkdir(parents=True)
        (tmp_path / "external" / "sdk" / "app_bootloader.elf").write_bytes(_image(b"boot"))
        (tmp_path / "build" / "app").mkdir(parents=True)
        (tmp_path / "build" / "app" / "app.elf").write_bytes(_image(HDCV_128_UT, KEY[:16]))
        fw = vd.inspect_firmware(tmp_path, KEY[:16])
        assert fw.hdcv_image.endswith("app.elf") and "build" in fw.hdcv_image
        assert fw.key_image == fw.hdcv_image

    def test_a_build_named_ancestor_does_not_rank_vendor_images(self, tmp_path):
        # --firmware /builds/proj: "builds" is above the root, not in the tree.
        root = tmp_path / "builds" / "proj"
        (root / "external").mkdir(parents=True)
        (root / "external" / "app_boot.elf").write_bytes(_image(b"boot"))
        (root / "build" / "app").mkdir(parents=True)
        (root / "build" / "app" / "app.elf").write_bytes(_image(HDCV_128_UT))
        _configs, images = vd._discover(root)
        assert images[0] == root / "build" / "app" / "app.elf"

    def test_another_protocol_version_is_not_read_as_ctr(self, tmp_path):
        # E: is only a key size; it means AES-CTR on TV:0.
        image = tmp_path / "app.elf"
        image.write_bytes(_image(b"HDCV:1.0/E:128/CS:DU/N:T/TV:2"))
        fw = vd.inspect_firmware(image, KEY)
        assert (fw.encryption, fw.counter_source) == (None, DEVICE_UPTIME)

    def test_differing_images_are_called_out(self, tmp_path):
        (tmp_path / "a.bin").write_bytes(_image(HDCV_128_UT))
        (tmp_path / "b.bin").write_bytes(_image(HDCV_256_DU))
        row = _rows(firmware=vd.inspect_firmware(tmp_path, KEY))["Firmware"]
        assert any("2 images carry different configs" in line for line in row.advice)

    def test_kconfig_fallback_for_sdks_older_than_hdcv(self, tmp_path):
        (tmp_path / ".config").write_text(_DOTCONFIG)
        (tmp_path / "zephyr.bin").write_bytes(_image(b"no vector here"))
        fw = vd.inspect_firmware(tmp_path, KEY)
        assert (fw.config_source, fw.encryption) == ("kconfig", vd.AES_128_CTR)
        assert "older than HDCV" in _rows(firmware=fw)["Firmware"].advice[0]


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


class TestBackendRows:
    def test_recent_packet_means_decoded_on_the_backend(self):
        dev = _device(last_packet_ts={"terrestrial": NOW - 180})
        row = _rows(device=dev)["Backend"]
        assert row.status == vd.OK
        assert "being decoded" in row.summary and "3m ago" in row.summary

    def test_nine_minutes_old_is_a_pass(self):
        dev = _device(last_packet_ts={"terrestrial": NOW - 9 * 60})
        assert _rows(device=dev)["Backend"].status == vd.OK

    def test_eleven_minutes_old_is_not_a_pass(self):
        # Ten minutes: an older packet may predate a reflash or a key change,
        # which is exactly what this command is run to catch.
        dev = _device(last_packet_ts={"terrestrial": NOW - 11 * 60})
        row = _rows(device=dev)["Backend"]
        assert row.status == vd.FAIL
        assert row.summary == "last decoded 11m ago (BLE), nothing in the last 10m"
        assert any("predate a reflash" in line for line in row.advice)

    def test_packet_decoded_just_now_beats_a_stale_last_packet(self):
        cloud = vd.CloudEvidence("checked", sent=2, mine=1, key_packets=True)
        row = _rows(device=_device(), cloud=cloud)["Backend"]
        assert row.status == vd.OK
        assert row.summary == "decoded 1 of 2 packets heard just now as this device"

    def test_undecoded_key_packets_fail_even_with_a_fresh_packet(self):
        dev = _device(last_packet_ts={"terrestrial": NOW - 60})
        cloud = vd.CloudEvidence("checked", sent=1, key_packets=True)
        row = _rows(device=dev, cloud=cloud)["Backend"]
        assert row.status == vd.FAIL
        assert row.summary == "could not decode this key's packets (1 sent)"
        assert any("registered key is not this --key" in line for line in row.advice)

    def test_key_registered_to_another_device(self):
        cloud = vd.CloudEvidence("checked", sent=1, others=("bench-2",), key_packets=True)
        row = _rows(device=_device(), cloud=cloud)["Backend"]
        assert row.status == vd.FAIL
        assert row.summary == "decodes this key's packets as bench-2, not this device"

    def test_without_a_key_the_cloud_says_whose_packets_were_heard(self):
        cloud = vd.CloudEvidence("checked", sent=3, others=("a", "b", "c", "d"))
        rows = _rows(key=None, device=_device(), cloud=cloud,
                     air=vd.AirEvidence(heard=3, match=None))
        assert rows["Over the air"].status == vd.OK
        assert rows["Over the air"].summary == "3 Hubble packets heard (no --key: the cloud says whose)"
        assert rows["Backend"].summary == "decoded none of the 3 packets heard as this device"
        assert "Decoded as other devices in your org: a, b, c and 1 more." in rows["Backend"].advice
        assert any("add --key" in line for line in rows["Backend"].advice)
        # No key: nothing to compare its length with, and no clock to read.
        assert {"Encryption", "Clock", "Key"}.isdisjoint(rows)

    def test_device_in_range_under_another_key(self):
        # Nothing opened with --key, but the cloud found the device among
        # everything heard: --key is what is wrong.
        cloud = vd.CloudEvidence("checked", sent=1, mine=1)
        rows = _rows(device=_device(), air=_air([_ctr(OTHER, TODAY)]), cloud=cloud)
        assert rows["Backend"].status == vd.OK
        assert rows["Key"].status == vd.FAIL
        assert "don't decrypt with this --key" in rows["Key"].summary

    @pytest.mark.parametrize("cloud, why", [
        (vd.CloudEvidence("no_scope"), "lacks the read-packets scope"),
        (vd.CloudEvidence("error", error="503: unavailable"), "503: unavailable"),
    ])
    def test_falls_back_to_the_last_packet_when_the_cloud_cannot_decode(self, cloud, why):
        dev = _device(last_packet_ts={"terrestrial": NOW - 60})
        row = _rows(device=dev, cloud=cloud)["Backend"]
        assert row.status == vd.OK
        assert "being decoded" in row.summary
        assert any(why in line for line in row.advice)

    def test_no_gateway_suggests_relaying_from_here(self):
        rows = _rows(device=_device(), air=_air([_ctr(KEY, TODAY)]))
        assert any("ble scan --key <key> --ingest" in line for line in rows["Delivery"].advice)

    def test_stale_packet_is_a_failure(self):
        dev = _device(last_packet_ts={"satellite": NOW - 30 * 86400})
        row = _rows(device=dev)["Backend"]
        assert row.status == vd.FAIL and "30d ago (satellite)" in row.summary
        assert any("something changed" in line for line in row.advice)

    def test_never_decoded(self):
        row = _rows(device=_device())["Backend"]
        assert row.status == vd.FAIL and "never" in row.summary


class TestCounterModeRows:
    def test_registered_unix_but_flashed_with_device_uptime(self):
        rows = _rows(device=_device(), key=KEY, air=_air([_ctr(KEY, 42)]))
        row = rows["Counter mode"]
        assert row.status == vd.FAIL
        assert row.summary == (
            "registered UNIX_TIME, but the device is broadcasting DEVICE_UPTIME"
        )
        assert any("1970" in line for line in row.advice)

    def test_registered_uptime_but_firmware_built_unix(self, tmp_path):
        (tmp_path / ".config").write_text("CONFIG_HUBBLE_COUNTER_SOURCE_UNIX_TIME=y\n")
        rows = _rows(
            device=_device(counter_source=DEVICE_UPTIME),
            firmware=vd.inspect_firmware(tmp_path, KEY),
        )
        assert rows["Counter mode"].summary == (
            "registered DEVICE_UPTIME, but the firmware is built for UNIX_TIME"
        )

    def _fw(self, tmp_path, hdcv):
        image = tmp_path / "app.elf"
        image.write_bytes(_image(hdcv))
        return vd.inspect_firmware(image, KEY)

    def test_unix_build_with_an_uptime_counter_is_an_unset_clock(self, tmp_path):
        # Registration and build both say UNIX_TIME, so counter 42 is not
        # uptime: the device's Unix clock reads 42 days after the epoch.
        rows = _rows(
            device=_device(), key=KEY, air=_air([_ctr(KEY, 42)]),
            firmware=self._fw(tmp_path, b"HDCV:1.0/E:256/CS:UT/N:T"),
        )
        assert rows["Counter mode"].status == vd.OK
        assert "registration, firmware and air agree" in rows["Counter mode"].summary
        assert rows["Over the air"].summary.endswith("UNIX_TIME (clock unset)")
        clock = rows["Clock"]
        assert clock.status == vd.FAIL
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

    def test_build_the_board_is_not_running_is_not_the_cause(self, tmp_path):
        # The air agrees with the registration, so the device is right and the
        # build given is not what it runs: re-registering would break it.
        rows = _rows(
            device=_device(), key=KEY, air=_air([_ctr(KEY, TODAY)]),
            firmware=self._fw(tmp_path, HDCV_256_DU),
        )
        row = rows["Counter mode"]
        assert row.status == vd.FAIL
        assert row.summary == (
            "the device broadcasts UNIX_TIME as registered, but the firmware "
            "given is built for DEVICE_UPTIME"
        )
        assert not any("register-device" in line for line in row.advice)

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
        assert both["Counter mode"].status == vd.OK
        assert "registration and air agree" in both["Counter mode"].summary


class TestEncryptionRows:
    def test_aes128_build_with_a_registered_aes256_key(self):
        rows = _rows(
            device=_device(), key=KEY, air=_air([_ctr(KEY[:16], TODAY)]),
        )
        row = rows["Encryption"]
        assert row.status == vd.FAIL
        assert "first 16 bytes" in row.summary
        assert any("defaults to AES-256-CTR" in line for line in row.advice)

    def test_32_byte_key_for_a_device_registered_aes128(self):
        # Registration and air agree on AES-128: nothing to re-register, the
        # --key just carries 16 bytes too many.
        rows = _rows(device=_device(encryption=vd.AES_128_CTR), key=KEY,
                     air=_air([_ctr(KEY[:16], TODAY)]))
        row = rows["Encryption"]
        assert row.status == vd.OK
        assert not any("register-device" in line for line in row.advice)
        assert any("Pass just those 16 bytes" in line for line in row.advice)

    def test_aes128_eax_build_with_a_32_byte_key_gets_eax_advice(self):
        row = _rows(key=KEY, air=_air([_eax(KEY[:16], exponent=5)]))["Encryption"]
        assert "first 16 bytes" in row.summary
        assert any("--encryption AES-128-EAX" in line for line in row.advice)
        assert not any("KEY_256" in line for line in row.advice)

    def test_key_length_disagrees_with_registration(self):
        row = _rows(device=_device(), key=KEY[:16])["Encryption"]
        assert row.status == vd.FAIL
        assert "16 bytes" in row.summary and "AES-256-CTR" in row.summary

    def test_eax_device_registered_as_ctr(self):
        k = KEY[:16]
        rows = _rows(
            device=_device(encryption=vd.AES_128_CTR), key=k,
            air=_air([_eax(k, exponent=5)], key=k),
        )
        assert rows["Encryption"].summary == (
            "registered AES-128-CTR, but the device is broadcasting AES-128-EAX"
        )

    def test_firmware_key_size_disagrees_with_registration(self, tmp_path):
        (tmp_path / ".config").write_text("CONFIG_HUBBLE_NETWORK_KEY_128=y\n")
        rows = _rows(device=_device(), firmware=vd.inspect_firmware(tmp_path, KEY))
        assert rows["Encryption"].summary == (
            "registered AES-256-CTR, but the firmware is built for AES-128-CTR"
        )


class TestClockAndPeriodRows:
    def test_clock_days_off_is_a_failure(self):
        row = _rows(key=KEY, air=_air([_ctr(KEY, TODAY + 9)]))["Clock"]
        assert row.status == vd.FAIL and row.summary == "device clock is 9 days ahead"

    def test_clock_within_tolerance(self):
        assert _rows(key=KEY, air=_air([_ctr(KEY, TODAY - 1)]))["Clock"].status == vd.OK

    def test_unset_clock_past_the_uptime_pool(self):
        # Day 200 can't be an uptime counter (0-127), so no firmware is needed.
        row = _rows(key=KEY, air=_air([_ctr(KEY, 200)]))["Clock"]
        assert row.status == vd.FAIL
        assert row.summary == "device clock reads 1970-07-20: Unix time was never set"
        assert not any("--firmware" in line for line in row.advice)

    def test_period_mismatch(self):
        k = KEY[:16]
        rows = _rows(
            device=_device(encryption=vd.AES_128_EAX, counter_source=DEVICE_UPTIME,
                           period_exponent=15),
            key=k, air=_air([_eax(k, exponent=10)], key=k),
        )
        assert rows["Period"].summary == "device rotates every 2^10s, registered 2^15s"


class TestAirRows:
    def test_nothing_heard(self):
        row = _rows(key=KEY, air=_air([]), timeout=15)["Over the air"]
        assert row.status == vd.FAIL and "in 15s" in row.summary

    def test_heard_but_not_this_key(self):
        row = _rows(key=KEY, air=_air([_ctr(OTHER, TODAY)]))["Over the air"]
        assert row.status == vd.FAIL
        assert row.summary == "no packets from this key (other Hubble devices were heard)"

    def test_summary_counts_only_this_keys_packets(self):
        air = _air([_ctr(OTHER, TODAY, s) for s in range(5)] + [_ctr(KEY, TODAY, s) for s in range(2)])
        row = _rows(key=KEY, air=air)["Over the air"]
        assert row.summary == "2 packets from this key: AES-256-CTR, UNIX_TIME"

    def test_eid_only_match_points_at_firmware_crypto(self):
        row = _rows(key=KEY, air=_air([_ctr(KEY, TODAY, tamper=True)]))["Over the air"]
        assert row.status == vd.FAIL and "no payload authenticates" in row.summary

    def test_right_key_with_a_non_sdk_eid_is_its_own_finding(self):
        # The tag sweep still finds the key, but a wrong EID is exactly what
        # would stop the backend attributing the packet: report it, don't pass.
        air = _air([_ctr(KEY, TODAY, eid=b"\x00\x00\x00\x00")])
        assert air.match.authenticated and air.match.eid_mismatch
        row = _rows(air=air)["Over the air"]
        assert row.status == vd.FAIL and "wrong EID" in row.summary

    def test_tag_sweep_is_capped_in_crowded_rf(self, monkeypatch):
        # The sweep is slow, so only the first few unknown EIDs get one.
        monkeypatch.setattr(vd, "_MAX_FALLBACK_STREAMS", 0)
        assert _air([_ctr(KEY, TODAY, eid=b"\x00\x00\x00\x00")]).match is None


class TestDeliveryRow:
    def _good(self, **kw):
        return _rows(device=_device(), key=KEY,
                     air=_air([_ctr(KEY, TODAY)]), **kw)

    def test_right_setup_but_nothing_reaches_the_cloud(self):
        row = self._good()["Delivery"]
        assert row.status == vd.FAIL
        assert any("gateway" in line for line in row.advice)

    def test_not_claimed_when_the_setup_itself_is_wrong(self):
        rows = _rows(device=_device(), key=KEY, air=_air([_ctr(KEY, 42)]))
        assert "Delivery" not in rows

    def test_not_claimed_when_the_backend_is_decoding(self):
        dev = _device(last_packet_ts={"terrestrial": NOW - 60})
        rows = _rows(device=dev, key=KEY, air=_air([_ctr(KEY, TODAY)]))
        assert "Delivery" not in rows
        assert all(r.status == vd.OK for r in rows.values())

    def test_not_claimed_when_the_cloud_was_asked(self):
        # Sending the packets made this machine the gateway, and the Backend
        # row already says what the cloud made of them.
        rows = self._good(cloud=vd.CloudEvidence("checked", sent=1, key_packets=True))
        assert rows["Backend"].status == vd.FAIL
        assert "Delivery" not in rows


class TestAirScanStopsEarly:
    """AirScan.add() is ble.scan's `until`: True ends the scan."""

    def test_true_only_once_this_keys_packet_authenticates(self):
        scan = vd.AirScan(KEY, now=NOW)
        assert scan.add(_ctr(OTHER, TODAY)) is False
        assert scan.add(_ctr(KEY, TODAY)) is True

    def test_an_eid_match_that_fails_auth_does_not_stop_the_scan(self):
        scan = vd.AirScan(KEY, now=NOW)
        assert scan.add(_ctr(KEY, TODAY, seq=1, tamper=True)) is False
        # A later good packet from the same device does.
        assert scan.add(_ctr(KEY, TODAY, seq=2)) is True
        assert scan.evidence().match.packets == 2

    def test_keeps_this_keys_authenticated_packets_for_the_cloud(self):
        scan = vd.AirScan(KEY, now=NOW)
        tampered, good, later = (_ctr(KEY, TODAY, seq=1, tamper=True),
                                 _ctr(KEY, TODAY, seq=2), _ctr(KEY, TODAY, seq=3))
        for pkt in (_ctr(OTHER, TODAY), tampered, good, later):
            scan.add(pkt)
        assert scan.evidence().packets == (good, later)


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

    def test_last_packet_timestamp_is_normalised_to_seconds(self):
        dev = Device.from_json({"id": "x", "most_recent_packet": {
            "terrestrial": {"timestamp": "5.5"},
            "satellite": {"timestamp": 1_790_000_000_000},
            "other": {"timestamp": "soon"},
        }})
        assert dev.last_packet_ts == {"terrestrial": 5.5, "satellite": 1_790_000_000.0}

    def test_last_packet_timestamp_under_device(self):
        # The shape packets have elsewhere in this API (retrieve_packets).
        dev = Device.from_json({"id": "x", "most_recent_packet": {
            "terrestrial": {"device": {"timestamp": 5.0}, "location": {}},
        }})
        assert dev.last_packet_ts == {"terrestrial": 5.0}

    def test_organization_get_device_parses_the_response(self):
        org = MagicMock(spec=Organization)
        org.credentials, org.env = MagicMock(), MagicMock()
        with patch("hubblenetwork.org.cloud.get_device", return_value={
            "id": "x", "encryption": "AES-256-CTR",
            "eid_rotation": {"counter_source": UNIX_TIME},
        }) as get:
            dev = Organization.get_device(org, "x")
        get.assert_called_once_with(credentials=org.credentials, env=org.env, device_id="x")
        assert (dev.id, dev.encryption, dev.counter_source) == ("x", "AES-256-CTR", UNIX_TIME)

    def test_list_endpoint_shape_leaves_config_unset(self):
        dev = Device.from_json({"id": "x", "name": "n", "active": True})
        assert (dev.encryption, dev.counter_source, dev.last_packet_ts) == (None, None, None)

# ---------------------------------------------------------------------------
# the command
# ---------------------------------------------------------------------------

ANSI = re.compile(r"\033\[[0-9;]*m")
KEY_HEX = KEY.hex()
DEVICE_ID = "3f4b2c0c-2d43-4cbe-9c1f-0a4c2d59e2a1"
# The command scans against the wall clock, not the pinned NOW above.
REAL_TODAY = int(time.time()) // 86400


def _run(*args):
    res = CliRunner().invoke(cli, ["ble", "validate", *args])
    return res, ANSI.sub("", res.output)


def _decoded_as(pkt, device_id):
    """The cloud's answer for `pkt`: decoded as `device_id`."""
    return DecryptedPacket(
        timestamp=pkt.timestamp, device_id=device_id, device_name=f"name-{device_id[:4]}",
        location=None, tags={}, payload=b"hi", rssi=pkt.rssi,
    )


def _decodes(as_device=lambda pkt: DEVICE_ID, side_effect=None):
    """Patch the cloud decode: each packet comes back decoded as the device
    ID ``as_device(pkt)`` returns, or undecoded for None."""
    def fake(*, credentials, env, packets, metadata=None):
        return [
            None if (dev := as_device(p)) is None else _decoded_as(p, dev)
            for p in packets
        ]
    return patch("hubblenetwork.cli.org_mod.decode_packets", side_effect=side_effect or fake)


@pytest.fixture
def _env(monkeypatch):
    monkeypatch.setenv("HUBBLE_ORG_ID", "org")
    monkeypatch.setenv("HUBBLE_API_TOKEN", "tok")
    # The cloud decodes everything as this device unless a test says otherwise.
    with patch("hubblenetwork.cli._doctor_bluetooth", return_value=(_CHECK_OK, "", [])), \
            _decodes():
        yield


def _device_json(counter_source=UNIX_TIME, last_ago=60, **extra):
    """A GET /devices/<id> response; last_ago=None means never decoded."""
    data = {"id": DEVICE_ID, "encryption": "AES-256-CTR",
            "eid_rotation": {"counter_source": counter_source}, **extra}
    if last_ago is not None:
        data["most_recent_packet"] = {"terrestrial": {"timestamp": time.time() - last_ago}}
    return data


def _backend(device=None, missing=False):
    """Patch credentials and the device GET to return `device` (JSON)."""
    env = type("E", (), {"name": "PROD"})()
    get = (patch("hubblenetwork.cli.cloud.get_device",
                 side_effect=NotFoundError("404: unexpected response")) if missing
           else patch("hubblenetwork.cli.cloud.get_device", return_value=device))
    return patch("hubblenetwork.cli.cloud.get_env_from_credentials", return_value=env), get


def _healthy():
    return _backend(_device_json())


def _scan(stream, delivered=None):
    """Patch ble.scan with what it really does: hand each packet to `until`,
    in order, and stop as soon as it returns True."""
    delivered = [] if delivered is None else delivered

    def fake(timeout, until=None):
        for pkt in stream:
            delivered.append(pkt)
            if until is not None and until(pkt):
                break
        return list(delivered)

    return patch("hubblenetwork.cli.ble_mod.scan", side_effect=fake)


@pytest.mark.usefixtures("_env")
class TestInputs:

    def test_device_id_must_be_a_uuid(self):
        # It goes into the URL path, so "abc/x" would reach another endpoint.
        with patch("hubblenetwork.cli.cloud.get_device") as get:
            res, out = _run("-d", "abc/x", "-k", KEY_HEX)
        get.assert_not_called()
        assert res.exit_code == 2
        assert "must be a UUID" in out

    def test_device_id_is_sent_in_canonical_form(self):
        # UUID() accepts no hyphens, braces and urn:uuid:; the API path does not.
        creds, get = _healthy()
        with creds, get as mock_get:
            _run("-d", "{" + DEVICE_ID.replace("-", "").upper() + "}", "-k", KEY_HEX, "-t", "0")
        assert mock_get.call_args.kwargs["device_id"] == DEVICE_ID

    def test_nothing_checked_is_not_a_pass(self):
        # --timeout 0 and no --device-id: every row is a SKIP.
        res, out = _run("-k", KEY_HEX, "-t", "0")
        assert res.exit_code == 1
        assert "Nothing was checked." in out
        assert "looks right" not in out

    def test_bad_key_is_a_usage_error(self):
        res, out = _run("-d", DEVICE_ID, "--key", "not-a-key")
        assert res.exit_code == 2
        assert "--key" in out

@pytest.mark.usefixtures("_env")
class TestReplacesOldCommands:
    """ble validate took over `ble check-time` and the old `ble validate`;
    their inputs still have to work."""

    def test_key_alone_needs_no_credentials(self, monkeypatch):
        # `ble check-time --key K`: no device ID, no org.
        monkeypatch.delenv("HUBBLE_ORG_ID")
        monkeypatch.delenv("HUBBLE_API_TOKEN")
        with patch("hubblenetwork.cli.cloud.get_env_from_credentials") as env, \
                _scan([_ctr(KEY, REAL_TODAY)]):
            res, out = _run("--key", KEY_HEX)
        env.assert_not_called()
        assert res.exit_code == 0
        assert "not checked (no --device-id)" in out
        assert "device clock is on today" in out
        assert "Credentials" not in out

    def test_key_alone_reports_a_clock_out_of_spec(self):
        with _scan([_ctr(KEY, REAL_TODAY - 5)]):
            res, out = _run("-k", KEY_HEX)
        assert res.exit_code == 1
        assert "device clock is 5 days behind" in out

    @pytest.mark.parametrize("old", [["ble", "detect"], ["ble", "check-time"], ["detect"]])
    def test_old_names_point_to_validate(self, old):
        res = CliRunner().invoke(cli, [*old, "-k", KEY_HEX])
        out = ANSI.sub("", res.output)
        assert res.exit_code == 2
        assert "it was replaced by" in out
        assert "hubblenetwork ble validate --key <key>" in out

    def test_validate_inputs_still_work(self):
        # The old `ble validate --key K --device-id D --timeout 30`, on a bench
        # with no gateway: the cloud decodes what this machine heard.
        creds, get = _backend(_device_json(last_ago=None))
        pkt = _ctr(KEY, REAL_TODAY)
        with creds, get, _scan([_ctr(OTHER, REAL_TODAY), pkt]), _decodes() as decode:
            res, out = _run("--key", KEY_HEX, "--device-id", DEVICE_ID, "--timeout", "30")
        # Only this key's packet is sent, not the other device's.
        assert decode.call_args.kwargs["packets"] == [pkt]
        assert res.exit_code == 0, out
        assert "decoded 1 of 1 packet heard just now as this device" in out
        assert "Key setup looks right." in out


@pytest.mark.usefixtures("_env")
class TestCloudDecode:
    """--device-id sends packets heard to the cloud, which says whose they are."""

    def test_device_id_alone_needs_no_key(self):
        # Paul's case: org credentials and a device ID, no key to hand.
        creds, get = _backend(_device_json(last_ago=None))
        mine, other = _ctr(KEY, REAL_TODAY), _ctr(OTHER, REAL_TODAY)
        with creds, get, _scan([other, mine]) as scan, \
                _decodes(lambda p: DEVICE_ID if p is mine else "other-device") as decode:
            res, out = _run("--device-id", DEVICE_ID)
        assert scan.call_count == 1  # found in the first window, so it stopped
        assert decode.call_args.kwargs["packets"] == [other, mine]
        assert res.exit_code == 0, out
        assert "2 Hubble packets heard (no --key: the cloud says whose)" in out
        assert "decoded 1 of 2 packets heard just now as this device" in out

    def test_device_id_alone_reports_who_was_heard_instead(self):
        creds, get = _backend(_device_json(last_ago=None))
        with creds, get, _scan([_ctr(OTHER, REAL_TODAY)]), \
                _decodes(lambda p: "11111111-2222-3333-4444-555555555555"):
            res, out = _run("--device-id", DEVICE_ID, "-t", "1")
        assert res.exit_code == 1
        assert "decoded none of the 1 packet heard as this device" in out
        assert "Decoded as other devices in your org: name-1111." in out

    def test_neither_key_nor_device_id_is_a_usage_error(self):
        res, out = _run()
        assert res.exit_code == 2
        assert "Pass --key, --device-id, or both." in out

    def test_key_registered_to_another_device(self):
        creds, get = _healthy()
        with creds, get, _scan([_ctr(KEY, REAL_TODAY)]), \
                _decodes(lambda p: "11111111-2222-3333-4444-555555555555"):
            res, out = _run("-k", KEY_HEX, "-d", DEVICE_ID)
        assert res.exit_code == 1
        assert "decodes this key's packets as name-1111, not this device" in out

    def test_wrong_key_for_a_device_that_is_in_range(self):
        # The device broadcasts with OTHER; --key opens nothing, so everything
        # heard goes to the cloud, which finds the device.
        creds, get = _healthy()
        with creds, get, _scan([_ctr(OTHER, REAL_TODAY)]), _decodes():
            res, out = _run("-k", KEY_HEX, "-d", DEVICE_ID, "-t", "1")
        assert res.exit_code == 1
        assert "its packets don't decrypt with this --key" in out

    def test_without_the_read_packets_scope_it_falls_back(self):
        creds, get = _healthy()  # last decoded a minute ago
        with creds, get, _scan([_ctr(KEY, REAL_TODAY)]), \
                _decodes(side_effect=PermissionDeniedError("403")):
            res, out = _run("-k", KEY_HEX, "-d", DEVICE_ID)
        assert res.exit_code == 0, out
        assert "your packets are being decoded" in out
        assert "lacks the read-packets scope" in out


@pytest.mark.usefixtures("_env")
class TestOutput:
    def test_firmware_without_config_is_a_skip_not_a_failure(self, tmp_path):
        creds, get = _healthy()
        with creds, get:
            res, out = _run("-d", DEVICE_ID, "-k", KEY_HEX, "-t", "0", "--firmware", str(tmp_path))
        assert res.exit_code == 0
        assert "no Hubble config found" in out
        assert "Key setup looks right." in out

    def test_timeout_zero_does_not_scan(self):
        creds, get = _healthy()
        with creds, get, patch("hubblenetwork.cli.ble_mod.scan") as scan:
            _res, out = _run("-d", DEVICE_ID, "--key", KEY_HEX, "--timeout", "0")
        scan.assert_not_called()
        assert "scan disabled" in out

    def test_scan_stops_at_the_first_decoded_packet(self):
        creds, get = _backend(_device_json(counter_source=DEVICE_UPTIME))
        stream = [_ctr(bytes(32), REAL_TODAY, 1), _ctr(KEY, 42, 1), _ctr(KEY, 42, 2)]
        delivered = []
        with creds, get, _scan(stream, delivered):
            res, out = _run("-d", DEVICE_ID, "-k", KEY_HEX, "-t", "15")
        assert len(delivered) == 2  # never waited for the third
        assert "1 packet from this key" in out
        assert "up to 15s" in out
        assert res.exit_code == 0

    def test_unknown_device(self):
        creds, get = _backend(missing=True)
        with creds, get:
            res, out = _run("--device-id", "00000000-0000-0000-0000-000000000000", "-k", KEY_HEX, "-t", "0")
        assert res.exit_code == 1
        assert "no device with this ID" in out
        assert "Backend" not in out

    def test_bad_credentials_skip_the_lookup(self):
        with patch("hubblenetwork.cli.cloud.get_env_from_credentials", return_value=None), \
                patch("hubblenetwork.cli.cloud.get_device") as get:
            res, out = _run("--device-id", DEVICE_ID, "-k", KEY_HEX, "-t", "0")
        get.assert_not_called()
        assert res.exit_code == 1
        assert "rejected" in out
        assert "Registration" not in out

    def test_scan_failure_is_a_row_not_a_crash(self):
        creds, get = _healthy()
        with creds, get, \
                patch("hubblenetwork.cli.ble_mod.scan", side_effect=RuntimeError("no adapter")):
            res, out = _run("-d", DEVICE_ID, "--key", KEY_HEX)
        assert res.exit_code == 1
        assert "BLE scan failed (no adapter)" in out

    def test_malformed_cloud_answer_is_not_a_ble_failure(self):
        creds, get = _backend(_device_json(last_ago=None))
        with creds, get, _scan([_ctr(KEY, REAL_TODAY)]), \
                _decodes(side_effect=KeyError("rssi")):
            res, out = _run("-d", DEVICE_ID)
        assert "BLE scan failed" not in out
        assert "1 Hubble packet heard" in out
        assert "unexpected answer from the decode endpoint" in out
        assert "Traceback" not in out


@pytest.mark.usefixtures("_env")
class TestCloudCheckLimits:
    def test_crowded_rf_still_reaches_the_device(self):
        # Neighbours send far more distinct advertisements than the cap; the
        # cap counts devices, so the one being checked still gets sent.
        neighbours = [_ctr(OTHER, REAL_TODAY, seq=s) for s in range(300)]
        creds, get = _backend(_device_json(last_ago=None))
        mine = _ctr(KEY, REAL_TODAY)
        with creds, get, _scan([*neighbours, mine]), \
                _decodes(lambda p: DEVICE_ID if p is mine else None) as decode:
            res, out = _run("-d", DEVICE_ID, "-t", "1")
        assert res.exit_code == 0, out
        assert [len(c.kwargs["packets"]) for c in decode.call_args_list] == [2]

    def test_a_later_failure_keeps_earlier_answers(self):
        # Window 1 is answered (another device); window 2's request fails.
        creds, get = _backend(_device_json(last_ago=None))
        other_dev = "11111111-2222-3333-4444-555555555555"
        windows = iter([[_ctr(OTHER, REAL_TODAY)], [_ctr(bytes(32), REAL_TODAY)]])

        def scan(timeout, until=None):
            for pkt in next(windows, []):
                until(pkt)

        answers = iter([lambda ps: [_decoded_as(p, other_dev) for p in ps], None])

        def decode(*, credentials, env, packets, metadata=None):
            answer = next(answers)
            if answer is None:
                raise RateLimitError("429")
            return answer(packets)

        with creds, get, patch("hubblenetwork.cli.ble_mod.scan", side_effect=scan), \
                _decodes(side_effect=decode):
            res, out = _run("-d", DEVICE_ID, "-t", "30")
        assert res.exit_code == 1
        assert "decoded none of the 1 packet heard as this device" in out
        assert "name-1111" in out
        assert "A later request failed" in out
        assert "could not be checked" not in out
