"""Unit tests for Device.from_json config parsing."""
from hubblenetwork import Device


def test_from_json_parses_full_config():
    d = Device.from_json({
        "id": "abc", "name": "n", "tags": {}, "created_ts": 1, "active": True,
        "encryption": "AES-128-EAX",
        "eid_rotation": {"counter_source": "DEVICE_UPTIME", "period_exponent": 12},
    })
    assert d.encryption == "AES-128-EAX"
    assert d.counter_source == "DEVICE_UPTIME"
    assert d.period_exponent == 12


def test_from_json_parses_ctr_without_period():
    d = Device.from_json({
        "id": "abc", "name": "n", "tags": {}, "created_ts": 1, "active": True,
        "encryption": "AES-256-CTR",
        "eid_rotation": {"counter_source": "UNIX_TIME"},
    })
    assert d.encryption == "AES-256-CTR"
    assert d.counter_source == "UNIX_TIME"
    assert d.period_exponent is None


def test_from_json_tolerates_missing_config():
    d = Device.from_json({"id": "abc", "name": "n", "tags": {}, "created_ts": 1})
    assert d.encryption is None
    assert d.counter_source is None
    assert d.period_exponent is None
