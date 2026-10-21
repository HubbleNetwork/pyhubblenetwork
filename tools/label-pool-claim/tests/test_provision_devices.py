import argparse
import base64
import csv
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

import claim_device as cd
from internal import common
import provision_devices as pd


class FakePlatform:
    """Stands in for common.PlatformClient across both tools."""

    def __init__(self, *args, **kwargs):
        self.devices: dict[str, dict] = {}
        self.claims: list[dict] = []
        self.links: dict[str, str] = {}
        self.activated: set[str] = set()
        self.fail_patch: set[str] = set()
        self.fail_activate: set[str] = set()
        self.registered_bodies: list[dict] = []

    def check_access(self):
        pass

    def register_devices(self, body):
        self.registered_bodies.append(body)
        out = []
        for i, name in enumerate(body["names"]):
            device_id = f"00000000-0000-4000-8000-{len(self.devices):012d}"
            key = base64.b64encode(bytes([i]) * 32).decode()
            self.devices[device_id] = {"id": device_id, "name": name, "tags": {}}
            out.append({"device_id": device_id, "name": name, "key": key})
        return out

    def create_claim(self, claim_token=None):
        claim = {"claim_id": f"claim-{len(self.claims) + 1}", "claim_token": claim_token}
        self.claims.append(claim)
        return claim

    def set_claim_token(self, claim_id, claim_token):
        return {}

    def get_device(self, device_id):
        if device_id not in self.devices:
            raise common.APIError(f"GET devices/{device_id} -> 404")
        return self.devices[device_id]

    def patch_device(self, device_id, body):
        if body == {"set_activated": True}:
            if device_id in self.fail_activate:
                raise common.APIError("PATCH set_activated -> 403")
            self.activated.add(device_id)
            return {}
        if device_id in self.fail_patch:
            raise common.APIError("PATCH -> 500")
        self.links[device_id] = body["set_device_claim_id"]
        return {}

    def list_devices(self, page_size=1000):
        yield from self.devices.values()


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


class TestNames(unittest.TestCase):
    def test_appends_zero_padded_numbers(self):
        self.assertEqual(pd.device_names("nRF52 WorksWith26", 3),
                         ["nRF52 WorksWith26 01", "nRF52 WorksWith26 02",
                          "nRF52 WorksWith26 03"])

    def test_pad_grows_with_count(self):
        self.assertEqual(pd.device_names("X", 100)[-1], "X 100")
        self.assertEqual(pd.device_names("X", 100)[0], "X 001")

    def test_start_and_explicit_pad(self):
        self.assertEqual(pd.device_names("X", 2, start=21), ["X 21", "X 22"])
        self.assertEqual(pd.device_names("X", 2, pad=1), ["X 1", "X 2"])

    def test_empty_name_is_rejected(self):
        with self.assertRaises(ValueError):
            pd.device_names("  ", 1)


class TestRegistrationBody(unittest.TestCase):
    def test_unix_leaves_counter_at_platform_default(self):
        body = pd.registration_body(["a"], "AES-128-CTR", "UNIX_TIME")
        self.assertNotIn("eid_rotation", body)
        self.assertEqual(body["encryption"], "AES-128-CTR")
        self.assertIs(body["activated"], False)

    def test_uptime_is_sent_explicitly(self):
        body = pd.registration_body(["a", "b"], "AES-256-CTR", "DEVICE_UPTIME")
        self.assertEqual(body["eid_rotation"], {"counter_source": "DEVICE_UPTIME"})
        self.assertEqual(body["n_devices"], 2)


class TestEnsureClaim(unittest.TestCase):
    def test_creates_and_links(self):
        client, row = FakePlatform(), {}
        self.assertEqual(common.ensure_claim(client, "d", row), "created")
        self.assertEqual(client.links["d"], "claim-1")
        self.assertTrue(row["claim_token"])

    def test_existing_complete_claim_is_left_alone(self):
        client = FakePlatform()
        row = {"claim_id": "c", "claim_token": "t", "error": ""}
        self.assertEqual(common.ensure_claim(client, "d", row), "existing")
        self.assertEqual(client.claims, [])

    def test_unlinked_claim_is_linked_not_duplicated(self):
        client = FakePlatform()
        row = {"claim_id": "c", "claim_token": "t", "error": "APIError: boom"}
        self.assertEqual(common.ensure_claim(client, "d", row), "linked")
        self.assertEqual(client.claims, [])
        self.assertEqual(client.links["d"], "c")
        self.assertEqual(row["error"], "")

    def test_new_replaces_an_existing_claim(self):
        client = FakePlatform()
        row = {"claim_id": "c", "claim_token": "t", "error": ""}
        self.assertEqual(common.ensure_claim(client, "d", row, new=True), "created")
        self.assertEqual(row["claim_id"], "claim-1")

    def test_patch_failure_keeps_the_claim_in_the_row(self):
        client = FakePlatform()
        client.fail_patch.add("d")
        row = {}
        with self.assertRaises(common.APIError):
            common.ensure_claim(client, "d", row)
        self.assertEqual(row["claim_id"], "claim-1")


class TempKeysDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.keys = os.path.join(self.tmp.name, "keys")
        env = os.path.join(self.tmp.name, ".env")
        with open(env, "w") as fh:
            fh.write("HUBBLE_API_TOKEN=tok\nHUBBLE_ORG_ID=org-1\n")
        self.env = env
        self.fake = FakePlatform()
        for target, value in ((pd, "KEYS_DIR"), (cd, "KEYS_DIR")):
            patcher = mock.patch.object(target, value, self.keys)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(cd, "ADHOC_LOG", os.path.join(self.keys, "claims.csv"))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(common, "PlatformClient", lambda *a, **k: self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_tool(self, module, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = module.main([*argv, "--env-file", self.env])
        return code, out.getvalue() + err.getvalue()

    def provision(self, *extra):
        out = os.path.join(self.keys, "batch.csv")
        code, log = self.run_tool(pd, "-n", "3", "--name", "nRF52 WorksWith26",
                                  "--key-size", "256", "--counter", "uptime",
                                  "--yes", "--out", out, *extra)
        return code, log, out


class TestProvision(TempKeysDir):
    def test_registers_writes_keys_and_claims_every_device(self):
        code, log, out = self.provision()
        self.assertEqual(code, 0, log)
        rows = read_csv(out)
        self.assertEqual([r["device_name"] for r in rows],
                         ["nRF52 WorksWith26 01", "nRF52 WorksWith26 02",
                          "nRF52 WorksWith26 03"])
        self.assertTrue(all(r["key"] and r["claim_id"] and r["claim_token"] for r in rows))
        self.assertEqual({r["counter_source"] for r in rows}, {"DEVICE_UPTIME"})
        self.assertEqual(len(self.fake.links), 3)
        self.assertEqual(self.fake.activated, set(self.fake.links))
        # registered inactive; activation follows the claim
        self.assertIs(self.fake.registered_bodies[0]["activated"], False)

    def test_no_activate_and_no_claims_leave_devices_inactive(self):
        code, log, _ = self.provision("--no-activate")
        self.assertEqual(code, 0, log)
        self.assertEqual(len(self.fake.links), 3)
        self.assertEqual(self.fake.activated, set())
        self.fake.links.clear()
        os.remove(os.path.join(self.keys, "batch.csv"))
        code, log, _ = self.provision("--no-claims")
        self.assertEqual((code, self.fake.links, self.fake.activated), (0, {}, set()))

    def test_failed_activation_is_finished_by_claim_device_csv(self):
        self.fake.fail_activate.add("00000000-0000-4000-8000-000000000002")
        code, log, out = self.provision()
        self.assertEqual(code, 1, log)
        self.assertIn("activation failed", read_csv(out)[2]["error"])

        self.fake.fail_activate.clear()
        code, log = self.run_tool(cd, "--csv", out)
        self.assertEqual(code, 0, log)
        self.assertEqual(len(self.fake.claims), 3)
        self.assertIn("00000000-0000-4000-8000-000000000002", self.fake.activated)

    def test_dry_run_registers_nothing(self):
        code, log, out = self.provision("--dry-run")
        self.assertEqual(code, 0, log)
        self.assertEqual(self.fake.registered_bodies, [])
        self.assertFalse(os.path.exists(out))

    def test_refuses_to_overwrite_an_existing_output(self):
        os.makedirs(self.keys)
        open(os.path.join(self.keys, "batch.csv"), "w").close()
        with self.assertRaises(SystemExit):
            self.provision()
        self.assertEqual(self.fake.registered_bodies, [])

    def test_failed_link_is_finished_by_claim_device_csv(self):
        self.fake.fail_patch.add("00000000-0000-4000-8000-000000000001")
        code, log, out = self.provision()
        self.assertEqual(code, 1, log)
        failed = read_csv(out)[1]
        self.assertTrue(failed["error"])
        self.assertTrue(failed["claim_id"])

        self.fake.fail_patch.clear()
        code, log = self.run_tool(cd, "--csv", out)
        self.assertEqual(code, 0, log)
        self.assertEqual(len(self.fake.claims), 3)  # linked, not re-created
        self.assertEqual(read_csv(out)[1]["error"], "")


class TestClaimDevice(TempKeysDir):
    def setUp(self):
        super().setUp()
        _, _, self.out = self.provision("--no-claims")
        self.rows = read_csv(self.out)

    def test_classify(self):
        key = self.rows[0]["key"]
        self.assertEqual(cd.classify(self.rows[0]["device_id"])[0], "id")
        self.assertEqual(cd.classify(key), ("key", key))
        hexkey = base64.b64decode(key).hex()
        self.assertEqual(cd.classify(hexkey), ("key", key))
        self.assertEqual(cd.classify("0x" + hexkey.upper()), ("key", key))
        self.assertEqual(cd.classify("nRF52 WorksWith26 01")[0], "name")

    def test_claims_by_key_and_writes_back_to_the_csv(self):
        code, log = self.run_tool(cd, self.rows[1]["key"])
        self.assertEqual(code, 0, log)
        row = read_csv(self.out)[1]
        self.assertEqual(row["claim_id"], "claim-1")
        self.assertEqual(self.fake.links[row["device_id"]], "claim-1")

    def test_second_run_prints_the_existing_claim(self):
        self.run_tool(cd, "nrf52 workswith26 02")
        code, log = self.run_tool(cd, "nRF52 WorksWith26 02")
        self.assertEqual(code, 0, log)
        self.assertIn("already claimed", log)
        self.assertEqual(len(self.fake.claims), 1)

    def test_claiming_activates_and_an_existing_claim_still_gets_activated(self):
        device_id = self.rows[0]["device_id"]
        self.run_tool(cd, device_id)
        self.assertIn(device_id, self.fake.activated)
        self.fake.activated.clear()
        code, log = self.run_tool(cd, device_id)  # already claimed
        self.assertEqual(code, 0, log)
        self.assertIn(device_id, self.fake.activated)

    def test_no_activate_and_dry_run(self):
        code, log = self.run_tool(cd, self.rows[0]["device_id"], "--no-activate")
        self.assertEqual(code, 0, log)
        self.assertEqual(self.fake.activated, set())
        code, log = self.run_tool(cd, self.rows[1]["device_id"], "--dry-run")
        self.assertEqual(code, 0, log)
        self.assertEqual(self.fake.activated, set())
        self.assertIn("set_activated", log)

    def test_unknown_key_fails_with_a_hint(self):
        code, log = self.run_tool(cd, base64.b64encode(b"\xff" * 16).decode())
        self.assertEqual(code, 1)
        self.assertIn("can't be searched by key", log)

    def test_device_not_in_any_csv_is_found_by_name_on_the_platform(self):
        self.fake.devices["11111111-1111-4111-8111-111111111111"] = {
            "id": "11111111-1111-4111-8111-111111111111", "name": "Loose Device"}
        code, log = self.run_tool(cd, "loose device")
        self.assertEqual(code, 0, log)
        logged = read_csv(os.path.join(self.keys, "claims.csv"))
        self.assertEqual(logged[0]["device_name"], "Loose Device")
        self.assertEqual(logged[0]["claim_id"], "claim-1")

    def test_device_logged_in_claims_csv_is_not_claimed_twice(self):
        # Its only record is keys/claims.csv; a second claim would orphan the
        # token already printed on its label.
        device_id = "11111111-1111-4111-8111-111111111111"
        self.fake.devices[device_id] = {"id": device_id, "name": "Loose Device"}
        self.run_tool(cd, "Loose Device")
        code, log = self.run_tool(cd, "Loose Device")
        self.assertEqual(code, 0, log)
        self.assertIn("already claimed", log)
        self.assertEqual(len(self.fake.claims), 1)

        # --new replaces it in place, and later appends still line up.
        self.run_tool(cd, "Loose Device", "--new")
        other = "22222222-2222-4222-8222-222222222222"
        self.fake.devices[other] = {"id": other, "name": "Other Device"}
        self.run_tool(cd, "Other Device")
        rows = read_csv(os.path.join(self.keys, "claims.csv"))
        self.assertEqual([(r["device_name"], r["claim_id"]) for r in rows],
                         [("Loose Device", "claim-2"), ("Other Device", "claim-3")])

    def test_ambiguous_platform_name_fails(self):
        for n in (1, 2):
            device_id = f"2222222{n}-2222-4222-8222-222222222222"
            self.fake.devices[device_id] = {"id": device_id, "name": "Dup"}
        code, log = self.run_tool(cd, "Dup")
        self.assertEqual(code, 1)
        self.assertIn("2 devices are named", log)
        self.assertEqual(self.fake.claims, [])


class TestResolveOrg(unittest.TestCase):
    def parse(self, *argv):
        parser = argparse.ArgumentParser()
        common.add_org_args(parser)
        return parser, parser.parse_args(list(argv))

    def test_flags_win_over_the_env_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write("HUBBLE_API_KEY=file-token\nHUBBLE_ORG_ID=file-org\n")
        self.addCleanup(os.remove, fh.name)
        with mock.patch.dict(os.environ, {}, clear=True):
            parser, args = self.parse("--env-file", fh.name, "--org-id", "flag-org")
            org = common.resolve_org(args, parser)
        self.assertEqual((org.org_id, org.token), ("flag-org", "file-token"))

    def test_env_name_picks_dot_env_dot_name_next_to_the_script(self):
        parser, args = self.parse("--env", "does-not-exist-xyz")
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            common.resolve_org(args, parser)


if __name__ == "__main__":
    unittest.main()
