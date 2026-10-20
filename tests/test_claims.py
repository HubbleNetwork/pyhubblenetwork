"""Device claims: the cloud calls, the Organization methods and `claim` CLI.

Wire shapes here come from the cloud's platform-api handlers: claims live at
/org/{id}/device_claims, PATCH fields are `set_*`, "" clears a field, a token
is looked up as unpadded base64url with `id_type=claim_token`, and errors come
back as {"code", "name", "description"}.
"""

import base64
import json
import re
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from hubblenetwork import cloud
from hubblenetwork.claim import DeviceClaim, encode_claim_token
from hubblenetwork.cli import cli
from hubblenetwork.cloud import Credentials, Environment
from hubblenetwork.device import Device
from hubblenetwork.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    RequestError,
    ValidationError,
    raise_for_response,
)
from hubblenetwork.org import Organization

ANSI = re.compile(r"\033\[[0-9;]*m")
CREDS = ["claim", "--org-id", "org-src", "--token", "fake-token"]
CREDENTIALS = Credentials("org-src", "tok")
ENV = Environment("TESTING", "https://example.invalid")
CLAIM_ID = "a1b2c3d4-e5f6-4789-a012-3456789abcde"
DEST = "b2b1c3d4-5e6f-4789-a012-3456789abcde"


def _claim_json(**over):
    data = {
        "claim_id": CLAIM_ID,
        "source_org_id": "org-src",
        "status": "AVAILABLE",
        "created_ts": 1735776000,
    }
    data.update(over)
    return data


def _claim(**over):
    return DeviceClaim.from_json(_claim_json(**over))


def _org():
    """An Organization without the two network calls its constructor makes."""
    org = Organization.__new__(Organization)
    org.credentials = CREDENTIALS
    org.env = ENV
    org.name = "Factory"
    return org


def _mock_org():
    org = MagicMock(spec=Organization)
    org.name = "Factory"
    org.org_id = "org-src"
    return org


def _run(args, org, input=None):
    with patch("hubblenetwork.cli.Organization", return_value=org):
        res = CliRunner().invoke(cli, CREDS + args, input=input)
    return res


def _plain(text):
    return ANSI.sub("", text or "")


# ---------------------------------------------------------------------------
# model and errors
# ---------------------------------------------------------------------------


class TestModel:
    def test_token_is_unpadded_base64url(self):
        token = "(01)12345678901231(21)ABC123"
        seg = encode_claim_token(token)
        assert "=" not in seg and "+" not in seg and "/" not in seg
        assert base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode() == token

    def test_from_json_minimal_claim_is_directionless(self):
        c = _claim()
        assert c.claim_id == CLAIM_ID
        assert c.destination_org_id is None and not c.directional
        assert c.device_count is None and c.device_ids is None

    def test_from_json_full_single_get(self):
        c = _claim(
            destination_org_id=DEST, claim_token="tok", name="lot 42",
            device_count=1, devices=[{"device_id": "dev-1", "name": "x"}],
            completed_ts=1735776500, status="COMPLETED",
        )
        assert c.directional
        assert c.device_ids == ["dev-1"]
        assert (c.name, c.claim_token, c.completed_ts) == ("lot 42", "tok", 1735776500)


class TestErrors:
    def test_description_field_is_the_message(self):
        with pytest.raises(NotFoundError, match="no device claim found"):
            raise_for_response(
                404, {"code": 404, "name": "Not Found",
                      "description": 'no device claim found for claim_id "x"'},
            )

    def test_409_is_a_conflict(self):
        with pytest.raises(ConflictError, match="not AVAILABLE"):
            raise_for_response(409, {"description": "device claim x is not AVAILABLE"})


# ---------------------------------------------------------------------------
# cloud.py wire format
# ---------------------------------------------------------------------------


@pytest.fixture
def req():
    with patch.object(cloud, "cloud_request") as m:
        m.return_value = ({"claim_id": CLAIM_ID}, None)
        yield m


class TestCloudCalls:
    def test_create_sends_only_given_fields(self, req):
        cloud.create_claim(credentials=CREDENTIALS, env=ENV, name="lot")
        kw = req.call_args.kwargs
        assert (kw["method"], kw["path"]) == ("POST", "/org/org-src/device_claims")
        assert kw["json"] == {"name": "lot"}

    def test_create_with_nothing_sends_an_empty_object(self, req):
        cloud.create_claim(credentials=CREDENTIALS, env=ENV)
        assert req.call_args.kwargs["json"] == {}

    def test_list_passes_role_status_and_token(self, req):
        cloud.list_claims(
            credentials=CREDENTIALS, env=ENV, role="destination",
            status="AVAILABLE", continuation_token="ct",
        )
        kw = req.call_args.kwargs
        assert kw["params"] == {"role": "destination", "filter_status": "AVAILABLE"}
        assert kw["continuation_token"] == "ct"

    def test_get_by_id(self, req):
        cloud.get_claim(credentials=CREDENTIALS, env=ENV, claim_id=CLAIM_ID)
        kw = req.call_args.kwargs
        assert kw["path"] == f"/org/org-src/device_claims/{CLAIM_ID}"
        assert kw["params"] is None

    def test_get_by_token(self, req):
        cloud.get_claim(credentials=CREDENTIALS, env=ENV, claim_token="0112345678901231")
        kw = req.call_args.kwargs
        seg = encode_claim_token("0112345678901231")
        assert kw["path"] == f"/org/org-src/device_claims/{seg}"
        assert kw["params"] == {"id_type": "claim_token"}

    def test_get_needs_exactly_one_id(self, req):
        with pytest.raises(ValueError):
            cloud.get_claim(credentials=CREDENTIALS, env=ENV)
        with pytest.raises(ValueError):
            cloud.get_claim(credentials=CREDENTIALS, env=ENV, claim_id="a", claim_token="b")

    def test_update_uses_set_fields_and_empty_string_clears(self, req):
        cloud.update_claim(
            credentials=CREDENTIALS, env=ENV, claim_id=CLAIM_ID,
            destination_org_id="", name="new",
        )
        kw = req.call_args.kwargs
        assert kw["method"] == "PATCH"
        assert kw["json"] == {"set_destination_org_id": "", "set_name": "new"}

    def test_delete(self, req):
        cloud.delete_claim(credentials=CREDENTIALS, env=ENV, claim_id=CLAIM_ID)
        kw = req.call_args.kwargs
        assert (kw["method"], kw["path"]) == ("DELETE", f"/org/org-src/device_claims/{CLAIM_ID}")

    def test_redeem_posts_to_claim_action(self, req):
        cloud.redeem_claim(credentials=CREDENTIALS, env=ENV, claim_id=CLAIM_ID)
        kw = req.call_args.kwargs
        assert (kw["method"], kw["path"]) == (
            "POST", f"/org/org-src/device_claims/{CLAIM_ID}/claim"
        )
        assert kw.get("json") is None

    def test_link_and_unlink_patch_the_device(self, req):
        cloud.set_device_claim(credentials=CREDENTIALS, env=ENV, device_id="d1", claim_id=CLAIM_ID)
        assert req.call_args.kwargs["json"] == {"set_device_claim_id": CLAIM_ID}
        assert req.call_args.kwargs["path"] == "/org/org-src/devices/d1"
        cloud.set_device_claim(credentials=CREDENTIALS, env=ENV, device_id="d1", claim_id="")
        assert req.call_args.kwargs["json"] == {"set_device_claim_id": ""}

    def test_batch_update_patches_the_devices_collection(self, req):
        req.return_value = ({"devices": [{"id": "d1"}, {"id": "d2"}]}, None)
        updates = [
            {"device_id": "d1", "set_device_claim_id": CLAIM_ID},
            {"device_id": "d2", "set_device_claim_id": CLAIM_ID},
        ]
        got = cloud.batch_update_devices(credentials=CREDENTIALS, env=ENV, updates=updates)
        kw = req.call_args.kwargs
        assert (kw["method"], kw["path"]) == ("PATCH", "/org/org-src/devices")
        assert kw["json"] == {"updates": updates}
        assert [d["id"] for d in got] == ["d1", "d2"]

    @pytest.mark.parametrize("n", [0, cloud.BATCH_UPDATE_LIMIT + 1])
    def test_batch_update_refuses_out_of_range(self, req, n):
        updates = [{"device_id": f"d{i}", "set_device_claim_id": ""} for i in range(n)]
        with pytest.raises(ValueError):
            cloud.batch_update_devices(credentials=CREDENTIALS, env=ENV, updates=updates)
        req.assert_not_called()

    def test_set_activated_is_sent_alone(self, req):
        cloud.set_device_activated(credentials=CREDENTIALS, env=ENV, device_id="d1", activated=False)
        assert req.call_args.kwargs["json"] == {"set_activated": False}

    def test_register_with_claims_and_deactivated(self, req):
        req.return_value = ({"devices": []}, None)
        cloud.register_device(
            credentials=CREDENTIALS, env=ENV, n_devices=2, activated=False,
            tags={"a": "b"}, device_claims=[{"claim_id": CLAIM_ID}] * 2,
        )
        body = req.call_args.kwargs["json"]
        assert body["n_devices"] == 2
        assert body["activated"] is False
        assert body["tags"] == [{"a": "b"}, {"a": "b"}]
        assert body["device_claims"] == [{"claim_id": CLAIM_ID}] * 2

    def test_register_default_body_unchanged(self, req):
        req.return_value = ({"devices": []}, None)
        cloud.register_device(credentials=CREDENTIALS, env=ENV)
        assert req.call_args.kwargs["json"] == {"n_devices": 1, "encryption": "AES-256-CTR"}


# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------


def _reg_response(n):
    return {
        "devices": [
            {"device_id": f"dev-{i}", "key": base64.b64encode(bytes(32)).decode(),
             "created_ts": 1, "activated": False}
            for i in range(n)
        ]
    }


class TestOrganization:
    def test_register_devices_new_claim_uses_device_id(self):
        org = _org()
        with patch.object(cloud, "register_device", return_value=_reg_response(2)) as m:
            devices = org.register_devices(2, new_claim=True, destination_org_id=DEST, activated=False)
        kw = m.call_args.kwargs
        assert kw["n_devices"] == 2
        assert kw["device_claims"] == [
            {"new_claim_using_device_id": True, "destination_org_id": DEST}
        ] * 2
        assert [d.claim_id for d in devices] == ["dev-0", "dev-1"]
        assert devices[0].key == bytes(32)
        assert devices[0].active is False

    def test_register_devices_existing_claim(self):
        org = _org()
        with patch.object(cloud, "register_device", return_value=_reg_response(3)) as m:
            devices = org.register_devices(3, claim_id=CLAIM_ID)
        assert m.call_args.kwargs["device_claims"] == [{"claim_id": CLAIM_ID}] * 3
        assert {d.claim_id for d in devices} == {CLAIM_ID}

    def test_register_devices_without_claim_sends_no_claims(self):
        org = _org()
        with patch.object(cloud, "register_device", return_value=_reg_response(1)) as m:
            org.register_devices(1)
        assert m.call_args.kwargs["device_claims"] is None
        assert m.call_args.kwargs["activated"] is None

    @pytest.mark.parametrize("kwargs", [
        {"claim_id": CLAIM_ID, "new_claim": True},
        {"destination_org_id": DEST},
        {"claim_id": CLAIM_ID, "destination_org_id": DEST},
    ])
    def test_register_devices_rejects_bad_claim_combos(self, kwargs):
        with patch.object(cloud, "register_device") as m, pytest.raises(ValidationError):
            _org().register_devices(1, **kwargs)
        m.assert_not_called()

    def test_register_device_still_returns_one_device(self):
        with patch.object(cloud, "register_device", return_value=_reg_response(1)) as m:
            dev = _org().register_device(encryption="AES-128-CTR")
        assert isinstance(dev, Device) and dev.id == "dev-0"
        assert m.call_args.kwargs["n_devices"] == 1

    def test_register_devices_up_to_limit_is_one_request(self):
        with patch.object(cloud, "register_device", return_value=_reg_response(1000)) as m:
            devices = _org().register_devices(1000, claim_id=CLAIM_ID)
        assert m.call_count == 1
        assert m.call_args.kwargs["n_devices"] == 1000
        assert len(m.call_args.kwargs["device_claims"]) == 1000
        assert len(devices) == 1000

    def test_register_devices_splits_into_batches_of_1000(self):
        calls = []

        def fake(**kw):
            calls.append(kw)
            start = sum(c["n_devices"] for c in calls[:-1])
            return {"devices": [
                {"device_id": f"dev-{start + i}", "key": base64.b64encode(bytes(32)).decode()}
                for i in range(kw["n_devices"])
            ]}

        progress = []
        tags = {"batch": "7"}
        with patch.object(cloud, "register_device", side_effect=fake):
            devices = _org().register_devices(
                2500, new_claim=True, tags=tags,
                on_batch=lambda done, total: progress.append((done, total)),
            )
        assert [c["n_devices"] for c in calls] == [1000, 1000, 500]
        for c in calls:
            assert len(c["device_claims"]) == c["n_devices"]
            assert c["tags"] == tags  # cloud.register_device repeats it n_devices times
        assert [d.id for d in devices] == [f"dev-{i}" for i in range(2500)]
        assert [d.claim_id for d in devices[:2]] == ["dev-0", "dev-1"]
        assert progress == [(1000, 2500), (2000, 2500), (2500, 2500)]

    def test_cloud_repeats_tags_per_device_in_each_request(self):
        with patch.object(cloud, "cloud_request", return_value=({}, None)) as m:
            cloud.register_device(credentials=CREDENTIALS, env=ENV, n_devices=500,
                                  tags={"a": "b"}, device_claims=[{"claim_id": "c"}] * 500)
        body = m.call_args.kwargs["json"]
        assert len(body["tags"]) == 500 and len(body["device_claims"]) == 500

    def test_register_devices_partial_failure_keeps_registered_devices(self):
        from hubblenetwork.errors import PartialRegistrationError

        boom = RequestError("400: device claim x not found")
        side = [_reg_response(1000), _reg_response(1000), boom]
        with patch.object(cloud, "register_device", side_effect=side), \
                pytest.raises(PartialRegistrationError) as ei:
            _org().register_devices(2500, claim_id=CLAIM_ID)
        exc = ei.value
        assert len(exc.devices) == 2000 and exc.requested == 2500
        assert exc.cause is boom and exc.__cause__ is boom
        assert all(d.key == bytes(32) for d in exc.devices)

    def test_register_devices_first_request_failure_raises_as_is(self):
        boom = RequestError("400: nope")
        with patch.object(cloud, "register_device", side_effect=boom), \
                pytest.raises(RequestError) as ei:
            _org().register_devices(2500)
        assert ei.value is boom

    def test_register_devices_interrupt_keeps_registered_devices(self):
        from hubblenetwork.errors import PartialRegistrationError

        side = [_reg_response(1000), KeyboardInterrupt()]
        with patch.object(cloud, "register_device", side_effect=side), \
                pytest.raises(PartialRegistrationError) as ei:
            _org().register_devices(1500)
        assert len(ei.value.devices) == 1000
        assert isinstance(ei.value.cause, KeyboardInterrupt)

    def test_iter_claims_follows_continuation_tokens(self):
        pages = [
            ({"claims": [_claim_json(claim_id="c1")]}, "next"),
            ({"claims": [_claim_json(claim_id="c2")]}, ""),
        ]
        with patch.object(cloud, "list_claims", side_effect=pages) as m:
            got = [c.claim_id for c in _org().iter_claims(incoming=True)]
        assert got == ["c1", "c2"]
        assert m.call_args_list[0].kwargs["role"] == "destination"
        assert m.call_args_list[1].kwargs["continuation_token"] == "next"

    def test_iter_claims_rejects_unknown_status(self):
        with pytest.raises(ValidationError):
            list(_org().iter_claims(status="DONE"))

    def test_update_claim_needs_a_field(self):
        with pytest.raises(ValidationError):
            _org().update_claim(CLAIM_ID)

    def test_link_device_refuses_empty_claim(self):
        with pytest.raises(ValidationError):
            _org().link_device("d1", "")

    def test_link_devices_sends_one_request_per_thousand(self):
        ids = [f"d{i}" for i in range(2500)]

        def echo(*, credentials, env, updates):
            return [{"id": u["device_id"]} for u in updates]

        with patch.object(cloud, "batch_update_devices", side_effect=echo) as m:
            got = _org().link_devices(ids + ["d0", "d1"], CLAIM_ID)
        sizes = [len(c.kwargs["updates"]) for c in m.call_args_list]
        assert sizes == [1000, 1000, 500]
        assert m.call_args_list[0].kwargs["updates"][0] == {
            "device_id": "d0", "set_device_claim_id": CLAIM_ID,
        }
        # Repeats are sent once.
        assert got == ids

    def test_unlink_devices_sends_empty_claim(self):
        with patch.object(cloud, "batch_update_devices", return_value=[]) as m:
            _org().unlink_devices(["d1", "d2"])
        m.assert_called_once()
        assert m.call_args.kwargs["updates"] == [
            {"device_id": "d1", "set_device_claim_id": ""},
            {"device_id": "d2", "set_device_claim_id": ""},
        ]

    def test_link_devices_refuses_empty_claim(self):
        with patch.object(cloud, "batch_update_devices") as m, pytest.raises(ValidationError):
            _org().link_devices(["d1"], "")
        m.assert_not_called()

    def test_redeem_polls_until_completed(self):
        polls = []
        with patch.object(cloud, "redeem_claim", return_value=_claim_json(status="IN_PROGRESS")), \
             patch.object(cloud, "get_claim", side_effect=[
                 _claim_json(status="IN_PROGRESS"),
                 _claim_json(status="COMPLETED", device_count=2),
             ]) as get, \
             patch("hubblenetwork.org.time.sleep"):
            c = _org().redeem_claim(CLAIM_ID, on_poll=lambda c, t: polls.append(c.status))
        assert c.status == "COMPLETED" and c.device_count == 2
        assert polls == ["IN_PROGRESS", "COMPLETED"]
        assert get.call_args.kwargs["claim_id"] == CLAIM_ID

    def test_redeem_without_wait_does_not_poll(self):
        with patch.object(cloud, "redeem_claim", return_value=_claim_json(status="IN_PROGRESS")), \
             patch.object(cloud, "get_claim") as get:
            c = _org().redeem_claim(CLAIM_ID, wait=False)
        assert c.status == "IN_PROGRESS"
        get.assert_not_called()

    def test_redeem_returns_in_progress_claim_at_timeout(self):
        clock = iter([0.0, 0.0, 5.0, 5.0])
        with patch.object(cloud, "redeem_claim", return_value=_claim_json(status="IN_PROGRESS")), \
             patch.object(cloud, "get_claim", return_value=_claim_json(status="IN_PROGRESS")), \
             patch("hubblenetwork.org.time.sleep"), \
             patch("hubblenetwork.org.time.monotonic", side_effect=lambda: next(clock)):
            c = _org().redeem_claim(CLAIM_ID, timeout=5)
        assert c.status == "IN_PROGRESS"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCliList:
    def test_tabular_rows_on_stdout_summary_on_stderr(self):
        org = _mock_org()
        org.iter_claims.return_value = iter([
            _claim(name="lot 42", destination_org_id=DEST),
            _claim(claim_id="c2", status="COMPLETED"),
        ])
        res = _run(["list"], org)
        assert res.exit_code == 0, res.output
        out, err = _plain(res.stdout), _plain(res.stderr)
        assert CLAIM_ID in out and "lot 42" in out and DEST[:8] in out
        assert "anyone" in out
        assert "2 claims" in err and "1 available" in err and "1 completed" in err
        assert "2 claims" not in out

    def test_one_claim_is_singular_and_own_org_is_named(self):
        org = _mock_org()
        org.iter_claims.return_value = iter([_claim(destination_org_id="org-src")])
        res = _run(["list"], org)
        assert "this org" in _plain(res.stdout)
        assert "1 claim " in _plain(res.stderr) or "1 claim\n" in _plain(res.stderr)
        assert "1 claims" not in _plain(res.stderr)

    def test_incoming_and_status_are_passed(self):
        org = _mock_org()
        org.iter_claims.return_value = iter([])
        res = _run(["list", "--incoming", "--status", "available"], org)
        assert res.exit_code == 0
        kw = org.iter_claims.call_args.kwargs
        assert kw["incoming"] is True and kw["status"] == "AVAILABLE"
        assert "directionless claim never shows up here" in _plain(res.stderr)

    def test_json(self):
        org = _mock_org()
        org.iter_claims.return_value = iter([_claim(name="x")])
        res = _run(["list", "-f", "json"], org)
        data = json.loads(res.stdout)
        assert data[0]["claim_id"] == CLAIM_ID and data[0]["name"] == "x"
        assert data[0]["destination_org_id"] is None

    def test_limit_stops_and_says_so(self):
        org = _mock_org()
        org.iter_claims.return_value = iter([_claim(claim_id=f"c{i}") for i in range(5)])
        res = _run(["list", "-n", "2"], org)
        assert _plain(res.stdout).count("AVAILABLE") == 2
        assert "drop --limit" in _plain(res.stderr)


class TestCliGetCreateUpdateDelete:
    def test_get_shows_fields(self):
        org = _mock_org()
        org.get_claim.return_value = _claim(device_count=1, devices=[{"device_id": "dev-9"}])
        res = _run(["get", CLAIM_ID], org)
        out = _plain(res.stdout)
        assert res.exit_code == 0
        assert "Unnamed claim" in out and "dev-9" in out
        assert "directionless" in out and "this org" in out
        org.get_claim.assert_called_once_with(CLAIM_ID, claim_token=None)

    def test_get_by_token(self):
        org = _mock_org()
        org.get_claim.return_value = _claim()
        res = _run(["get", "--claim-token", "0112345678901231"], org)
        assert res.exit_code == 0
        org.get_claim.assert_called_once_with(None, claim_token="0112345678901231")

    def test_get_needs_one_identifier(self):
        res = _run(["get"], _mock_org())
        assert res.exit_code == 2
        assert "claim list" in _plain(res.output)

    def test_get_not_found_is_explained(self):
        org = _mock_org()
        org.get_claim.side_effect = NotFoundError('404: no device claim found for claim_id "x"')
        res = _run(["get", "x"], org)
        assert res.exit_code == 1
        msg = _plain(res.output)
        assert "no device claim found" in msg and "never as forbidden" in msg

    def test_create_prints_claim_and_next_steps(self):
        org = _mock_org()
        org.create_claim.return_value = _claim(name="lot 42")
        res = _run(["create", "--name", "lot 42"], org)
        assert res.exit_code == 0
        org.create_claim.assert_called_once_with(destination_org_id=None, claim_token=None, name="lot 42")
        err = _plain(res.stderr)
        assert "Directionless" in err
        assert f"claim link {CLAIM_ID} <id>..." in err
        assert f"claim register-device --claim {CLAIM_ID}" in err

    def test_create_json_has_no_chrome(self):
        org = _mock_org()
        org.create_claim.return_value = _claim(destination_org_id=DEST)
        res = _run(["create", "--destination-org", DEST, "-f", "json"], org)
        assert json.loads(res.stdout)["destination_org_id"] == DEST
        assert res.stderr == ""

    def test_create_without_entitlement(self):
        org = _mock_org()
        org.create_claim.side_effect = PermissionDeniedError(
            "403: originating a device claim requires the can_create_device_claims"
            " entitlement for this organization"
        )
        res = _run(["create"], org)
        assert res.exit_code == 1
        assert "needs the can_create_device_claims entitlement" in _plain(res.output)

    def test_update_clears_with_empty_strings(self):
        org = _mock_org()
        org.update_claim.return_value = _claim()
        res = _run(["update", CLAIM_ID, "--directionless", "--clear-name", "--claim-token", "t"], org)
        assert res.exit_code == 0, res.output
        org.update_claim.assert_called_once_with(
            CLAIM_ID, destination_org_id="", claim_token="t", name=""
        )

    def test_update_with_nothing_is_a_usage_error(self):
        org = _mock_org()
        res = _run(["update", CLAIM_ID], org)
        assert res.exit_code == 2 and "Nothing to change" in _plain(res.output)
        org.update_claim.assert_not_called()

    def test_update_set_and_clear_conflict(self):
        res = _run(["update", CLAIM_ID, "--name", "a", "--clear-name"], _mock_org())
        assert res.exit_code == 2

    def test_update_after_redeem_is_a_conflict(self):
        org = _mock_org()
        org.update_claim.side_effect = ConflictError("409: device claim x is not AVAILABLE")
        res = _run(["update", CLAIM_ID, "--name", "a"], org)
        assert res.exit_code == 1
        assert "Only an AVAILABLE claim" in _plain(res.output)
        assert f"hubblenetwork claim get {CLAIM_ID}" in _plain(res.output)

    def test_declining_the_prompt_aborts_cleanly(self, capsys, monkeypatch):
        from hubblenetwork.cli import main

        monkeypatch.setattr("sys.stdin", __import__("io").StringIO("n\n"))
        with patch("hubblenetwork.cli.Organization", return_value=_mock_org()):
            code = main(CREDS + ["delete", CLAIM_ID])
        err = capsys.readouterr().err
        assert code == 1
        assert "Aborted!" in err and "Unexpected error" not in err

    def test_delete_confirms(self):
        org = _mock_org()
        res = _run(["delete", CLAIM_ID], org, input="n\n")
        assert res.exit_code != 0
        org.delete_claim.assert_not_called()
        res = _run(["delete", CLAIM_ID, "-y"], org)
        assert res.exit_code == 0
        org.delete_claim.assert_called_once_with(CLAIM_ID)


class TestCliDevices:
    def test_link_sends_one_batch_and_marks_each_device(self):
        org = _mock_org()
        res = _run(["link", CLAIM_ID, "d1", "d2", "d1"], org)
        assert res.exit_code == 0
        org.link_devices.assert_called_once_with(["d1", "d2"], CLAIM_ID)
        org.link_device.assert_not_called()
        out = _plain(res.stdout)
        assert "d1  linked" in out and "d2  linked" in out
        assert out.count("linked") == 2
        assert f"Linked 2 devices to claim {CLAIM_ID}." in _plain(res.stderr)
        assert "Linked" not in out

    def test_link_chunks_by_the_batch_limit(self):
        org = _mock_org()
        ids = [f"d{i}" for i in range(2001)]
        res = _run(["link", CLAIM_ID, *ids], org)
        assert res.exit_code == 0
        sizes = [len(c.args[0]) for c in org.link_devices.call_args_list]
        assert sizes == [1000, 1000, 1]
        assert f"Linked 2001 devices to claim {CLAIM_ID}." in _plain(res.stderr)

    def test_link_drops_a_named_missing_device_and_resends_the_rest(self):
        # The cloud checks the batch before writing: a missing device fails
        # it whole (400) and names only that device.
        org = _mock_org()
        org.link_devices.side_effect = [
            RequestError("400: device d2 not found"),
            RequestError("400: device d4 not found"),
            None,
        ]
        res = _run(["link", CLAIM_ID, "d1", "d2", "d3", "d4"], org)
        assert res.exit_code == 1
        calls = [c.args[0] for c in org.link_devices.call_args_list]
        assert calls == [["d1", "d2", "d3", "d4"], ["d1", "d3", "d4"], ["d1", "d3"]]
        out = _plain(res.stdout)
        assert "d1  linked" in out and "d3  linked" in out
        assert "d2  linked" not in out and "d4  linked" not in out
        # The cloud's message already names the device, so it isn't repeated.
        assert "device d2 not found" in out and "d2  device d2" not in out
        assert f"Linked 2 of 4 devices to claim {CLAIM_ID}; 2 failed." in _plain(res.stderr)

    def test_link_unnamed_failure_fails_the_whole_batch_only(self):
        org = _mock_org()
        org.link_devices.side_effect = [
            None,
            ConflictError("409: device claim is not AVAILABLE"),
        ]
        ids = [f"d{i}" for i in range(1003)]
        res = _run(["link", CLAIM_ID, *ids], org)
        assert res.exit_code == 1
        assert org.link_devices.call_count == 2
        out = _plain(res.stdout)
        assert "d999  linked" in out
        assert "d1000  linked" not in out
        assert "3 devices, d1000 .. d1002  device claim is not AVAILABLE" in out
        assert f"Linked 1000 of 1003 devices to claim {CLAIM_ID}; 3 failed." in _plain(res.stderr)

    def test_link_message_not_naming_a_sent_device_fails_the_batch(self):
        org = _mock_org()
        org.link_devices.side_effect = RequestError("400: device d10 not found")
        res = _run(["link", CLAIM_ID, "d1"], org)
        assert res.exit_code == 1
        assert org.link_devices.call_count == 1
        assert "d1  device d10 not found" in _plain(res.stdout)

    def test_link_entitlement_stops_the_run(self):
        org = _mock_org()
        org.link_devices.side_effect = PermissionDeniedError(
            "403: originating a device claim requires the can_create_device_claims entitlement"
        )
        ids = [f"d{i}" for i in range(1500)]
        res = _run(["link", CLAIM_ID, *ids], org)
        assert res.exit_code == 1
        assert org.link_devices.call_count == 1
        assert "can_create_device_claims" in _plain(res.output)

    def test_unlink(self):
        org = _mock_org()
        res = _run(["unlink", "d1", "d2"], org)
        assert res.exit_code == 0
        org.unlink_devices.assert_called_once_with(["d1", "d2"])
        org.unlink_device.assert_not_called()
        assert "Unlinked 2 devices." in _plain(res.stderr)

    def test_link_needs_devices(self):
        res = _run(["link", CLAIM_ID], _mock_org())
        assert res.exit_code == 2
        assert "org list-devices" in _plain(res.output)

    @pytest.mark.parametrize("cmd,value", [("activate", True), ("deactivate", False)])
    def test_activation(self, cmd, value):
        org = _mock_org()
        res = _run([cmd, "d1", "d2"], org)
        assert res.exit_code == 0
        assert [c.args for c in org.set_device_activated.call_args_list] == [
            ("d1", value), ("d2", value)
        ]

    def test_deactivate_without_entitlement(self):
        org = _mock_org()
        org.set_device_activated.side_effect = PermissionDeniedError(
            "403: activated: false requires the can_deactivate_devices entitlement"
        )
        res = _run(["deactivate", "d1"], org)
        assert res.exit_code == 1
        assert "Deactivating devices needs the can_deactivate_devices" in _plain(res.output)


class TestCliRedeem:
    """`claim redeem` previews the claim and asks before an irreversible move."""

    def _org(self, before=None, after=None):
        org = _mock_org()
        org.org_id = DEST  # the destination org redeems; the claim is from org-src
        org.get_claim.return_value = before or _claim(device_count=3, name="lot 42")
        org.redeem_claim.return_value = after or _claim(
            status="COMPLETED", destination_org_id=DEST, device_count=3,
            completed_ts=1735776500,
        )
        return org

    def test_completed(self):
        org = self._org()
        res = _run(["redeem", CLAIM_ID, "--yes"], org)
        assert res.exit_code == 0, res.output
        assert org.redeem_claim.call_args.kwargs["wait"] is True
        assert "3 devices now in this org" in _plain(res.stderr)

    def test_preview_shows_source_and_device_count_then_asks(self):
        org = self._org()
        res = _run(["redeem", CLAIM_ID], org, input="y\n")
        assert res.exit_code == 0, res.output
        err = _plain(res.stderr)
        assert "lot 42" in err and "org-src" in err
        assert "Devices   3" in err
        assert f"Redeem claim {CLAIM_ID}? 3 devices move into Factory permanently." in err
        org.get_claim.assert_called_once_with(CLAIM_ID)
        org.redeem_claim.assert_called_once()

    def test_declining_does_not_redeem(self):
        org = self._org()
        res = _run(["redeem", CLAIM_ID], org, input="n\n")
        assert res.exit_code == 1
        org.redeem_claim.assert_not_called()
        assert "Not redeemed" in _plain(res.stderr)

    def test_unrecognised_answer_asks_again(self):
        org = self._org()
        res = _run(["redeem", CLAIM_ID], org, input="maybe\ny\n")
        assert res.exit_code == 0, res.output
        assert "invalid input" in _plain(res.stderr)
        org.redeem_claim.assert_called_once()

    def test_default_answer_is_no(self):
        org = self._org()
        res = _run(["redeem", CLAIM_ID], org, input="\n")
        assert res.exit_code == 1
        org.redeem_claim.assert_not_called()

    def test_no_terminal_says_to_pass_yes(self):
        org = self._org()
        res = _run(["redeem", CLAIM_ID], org)  # stdin at EOF
        assert res.exit_code == 1
        org.redeem_claim.assert_not_called()
        msg = _plain(res.output)
        assert f"hubblenetwork claim redeem {CLAIM_ID} --yes" in msg

    def test_yes_skips_the_prompt_but_still_previews(self):
        org = self._org()
        res = _run(["redeem", CLAIM_ID, "-y"], org)
        assert res.exit_code == 0, res.output
        err = _plain(res.stderr)
        assert "permanently" not in err and "Devices   3" in err
        org.redeem_claim.assert_called_once()

    def test_json_stdout_stays_json_with_prompt(self):
        org = self._org()
        res = _run(["redeem", CLAIM_ID, "-f", "json"], org, input="y\n")
        assert res.exit_code == 0, res.output
        # Nothing but the JSON on stdout: not the preview, not the prompt,
        # not even the stray space click.confirm would leave there.
        assert res.stdout.startswith("{")
        data = json.loads(res.stdout)
        assert data["status"] == "COMPLETED" and data["device_count"] == 3
        assert "permanently" in _plain(res.stderr)

    def test_json_with_yes(self):
        org = self._org()
        res = _run(["redeem", CLAIM_ID, "--yes", "-f", "json"], org)
        assert res.exit_code == 0, res.output
        assert json.loads(res.stdout)["claim_id"] == CLAIM_ID

    def test_empty_claim_warns_nothing_moves(self):
        org = self._org(before=_claim(device_count=0))
        res = _run(["redeem", CLAIM_ID], org, input="n\n")
        err = _plain(res.stderr)
        assert "nothing will move" in err
        assert f"Redeem empty claim {CLAIM_ID} anyway?" in err
        org.redeem_claim.assert_not_called()

    def test_by_token_looks_up_once(self):
        org = self._org()
        res = _run(["redeem", "--claim-token", "0112345678901231", "--yes"], org)
        assert res.exit_code == 0, res.output
        org.get_claim.assert_called_once_with(claim_token="0112345678901231")
        assert org.redeem_claim.call_args.args == (CLAIM_ID,)

    def test_in_progress_for_this_org_rejoins_without_asking(self):
        org = self._org(before=_claim(status="IN_PROGRESS", destination_org_id=DEST))
        res = _run(["redeem", CLAIM_ID], org)  # no input: must not prompt
        assert res.exit_code == 0, res.output
        org.redeem_claim.assert_called_once()
        assert "rejoining" in _plain(res.stderr)

    def test_in_progress_for_another_org(self):
        org = self._org(before=_claim(status="IN_PROGRESS", destination_org_id="org-other"))
        res = _run(["redeem", CLAIM_ID], org)
        assert res.exit_code == 1
        org.redeem_claim.assert_not_called()
        assert "already being redeemed by another org" in _plain(res.output)

    def test_already_completed_into_this_org_is_a_no_op(self):
        org = self._org(before=_claim(status="COMPLETED", destination_org_id=DEST))
        res = _run(["redeem", CLAIM_ID], org)
        assert res.exit_code == 0, res.output
        org.redeem_claim.assert_not_called()
        assert "Already redeemed into this org" in _plain(res.stderr)

    def test_already_completed_elsewhere(self):
        org = self._org(before=_claim(status="COMPLETED", destination_org_id="org-other"))
        res = _run(["redeem", CLAIM_ID], org)
        assert res.exit_code == 1
        org.redeem_claim.assert_not_called()
        assert "already redeemed by org org-other" in _plain(res.output)

    def test_not_visible_keeps_not_found_guidance(self):
        org = self._org()
        org.get_claim.side_effect = NotFoundError("404: device claim not found")
        res = _run(["redeem", CLAIM_ID, "--yes"], org)
        assert res.exit_code == 1
        org.redeem_claim.assert_not_called()
        assert "pinned to another org reads as not found" in _plain(res.output)

    def test_timeout_exits_one(self):
        org = self._org(after=_claim(status="IN_PROGRESS"))
        res = _run(["redeem", CLAIM_ID, "--timeout", "1", "--yes"], org)
        assert res.exit_code == 1
        assert "Still IN_PROGRESS" in _plain(res.stderr)

    def test_no_wait_exits_zero(self):
        org = self._org(after=_claim(status="IN_PROGRESS"))
        res = _run(["redeem", CLAIM_ID, "--no-wait", "--yes"], org)
        assert res.exit_code == 0
        assert org.redeem_claim.call_args.kwargs["wait"] is False

    def test_lost_race_is_a_conflict(self):
        org = self._org()
        org.redeem_claim.side_effect = ConflictError(
            "409: device claim x is not available for redemption"
        )
        res = _run(["redeem", CLAIM_ID, "--yes"], org)
        assert res.exit_code == 1
        assert "not available for redemption" in _plain(res.output)


class TestCliRegisterDevice:
    def _devices(self, claim_id=None, n=2):
        return [
            Device(id=f"dev-{i}", key=bytes(range(32)), active=False,
                   claim_id=claim_id or f"dev-{i}")
            for i in range(n)
        ]

    def test_new_claim_deactivated(self):
        org = _mock_org()
        org.register_devices.return_value = self._devices()
        res = _run(["register-device", "-n", "2", "--new-claim", "--deactivated",
                    "--destination-org", DEST], org)
        assert res.exit_code == 0, res.output
        kw = org.register_devices.call_args.kwargs
        assert org.register_devices.call_args.args == (2,)
        assert kw["new_claim"] is True and kw["activated"] is False
        assert kw["destination_org_id"] == DEST and kw["claim_id"] is None
        out = _plain(res.stdout)
        assert "dev-0" in out and base64.b64encode(bytes(range(32))).decode() in out
        assert "each in its own claim" in _plain(res.stderr)
        assert "deactivated until claimed" in _plain(res.stderr)

    def test_existing_claim_names_it_in_the_next_step(self):
        org = _mock_org()
        org.register_devices.return_value = [
            Device(id="dev-0", key=bytes(16), active=None, claim_id=CLAIM_ID)
        ]
        res = _run(["register-device", "--claim", CLAIM_ID], org)
        err = _plain(res.stderr)
        assert f"hubblenetwork claim redeem {CLAIM_ID}" in err
        # Activation not confirmed by the response is not reported as done.
        assert "activating" in err

    def test_json(self):
        org = _mock_org()
        org.register_devices.return_value = self._devices(claim_id=CLAIM_ID, n=1)
        res = _run(["register-device", "--claim", CLAIM_ID, "-f", "json"], org)
        data = json.loads(res.stdout)
        assert data == [{
            "device_id": "dev-0",
            "key": base64.b64encode(bytes(range(32))).decode(),
            "claim_id": CLAIM_ID,
            "activated": False,
        }]

    def test_claim_and_new_claim_conflict(self):
        org = _mock_org()
        res = _run(["register-device", "--claim", CLAIM_ID, "--new-claim"], org)
        assert res.exit_code == 2
        org.register_devices.assert_not_called()

    def test_destination_needs_new_claim(self):
        res = _run(["register-device", "--destination-org", DEST], _mock_org())
        assert res.exit_code == 2
        assert "claim update <claim-id> --destination-org" in _plain(res.output)

    def test_sdk_validation_is_a_usage_error(self):
        org = _mock_org()
        org.register_devices.side_effect = ValidationError(
            "period_seconds/period_exponent requires encryption='AES-128-EAX'"
        )
        res = _run(["register-device", "--period-exponent", "12"], org)
        assert res.exit_code == 2

    def test_link_failure_warns_devices_may_exist(self):
        org = _mock_org()
        org.register_devices.side_effect = RequestError("400: device claim x not found")
        res = _run(["register-device", "--claim", "x"], org)
        assert res.exit_code == 1
        msg = _plain(res.output)
        assert "device claim x not found" in msg and "some may exist" in msg

    def _partial(self, cause=None):
        from hubblenetwork.errors import PartialRegistrationError

        cause = cause or RequestError("400: device claim x not found")
        return PartialRegistrationError(self._devices(claim_id=CLAIM_ID, n=2), 2500, cause)

    def test_partial_failure_prints_registered_keys_tabular(self):
        org = _mock_org()
        org.register_devices.side_effect = self._partial()
        res = _run(["register-device", "-n", "2500", "--claim", CLAIM_ID], org)
        assert res.exit_code == 1
        out = _plain(res.stdout)
        key = base64.b64encode(bytes(range(32))).decode()
        assert "dev-0" in out and "dev-1" in out and key in out
        err = _plain(res.stderr)
        assert "Registered 2 of 2,500 devices" in err
        assert "device claim x not found" in err
        assert "-n 2498" in err
        assert "some may exist" in err  # the failing request may have left some unlinked

    def test_partial_failure_prints_registered_keys_json(self):
        org = _mock_org()
        org.register_devices.side_effect = self._partial()
        res = _run(["register-device", "-n", "2500", "--claim", CLAIM_ID, "-f", "json"], org)
        assert res.exit_code == 1
        data = json.loads(res.stdout)
        assert [d["device_id"] for d in data] == ["dev-0", "dev-1"]
        assert data[0]["key"] == base64.b64encode(bytes(range(32))).decode()
        assert "Registered 2 of 2,500 devices" in _plain(res.stderr)

    def test_partial_failure_on_interrupt(self):
        org = _mock_org()
        org.register_devices.side_effect = self._partial(KeyboardInterrupt())
        res = _run(["register-device", "-n", "2500"], org)
        assert res.exit_code == 130
        assert "dev-0" in _plain(res.stdout)
        assert "interrupted" in _plain(res.stderr)

    def test_multi_batch_progress_on_stderr_when_tabular(self):
        org = _mock_org()

        def fake(count, **kw):
            kw["on_batch"](1000, count)
            kw["on_batch"](count, count)
            return self._devices(n=2)

        org.register_devices.side_effect = fake
        res = _run(["register-device", "-n", "1500"], org)
        assert res.exit_code == 0, res.output
        assert "registered 1,000 of 1,500 devices" in _plain(res.stderr)
        assert "registered 1,000" not in _plain(res.stdout)
        res = _run(["register-device", "-n", "1500", "-f", "json"], org)
        assert "registered 1,000" not in _plain(res.stderr)
        json.loads(res.stdout)

    def test_single_batch_shows_no_progress(self):
        org = _mock_org()

        def fake(count, **kw):
            kw["on_batch"](count, count)
            return self._devices(n=2)

        org.register_devices.side_effect = fake
        res = _run(["register-device", "-n", "2"], org)
        assert "registered 2 of 2" not in _plain(res.stderr)

    def test_deactivated_points_at_validate_by_key(self):
        org = _mock_org()
        org.register_devices.return_value = self._devices()
        res = _run(["register-device", "-n", "2", "--new-claim", "--deactivated"], org)
        assert "hubblenetwork ble validate --key <key>" in _plain(res.stderr)
        help_res = CliRunner().invoke(cli, ["claim", "register-device", "--help"])
        assert "ble validate --key <key>" in help_res.output


def test_help_needs_no_credentials():
    res = CliRunner().invoke(cli, ["claim", "redeem", "--help"], env={
        "HUBBLE_ORG_ID": "", "HUBBLE_API_TOKEN": "",
    })
    assert res.exit_code == 0
    assert "--claim-token" in res.output
