"""Tests for claim_pool. Run: python3 -m unittest -v test_claim_pool"""
import csv
import io
import os
import tempfile
import unittest
import uuid

from internal import common
from kiosk import claim_pool as cp


class TestDeviceName(unittest.TestCase):
    def test_pads_to_two_and_three(self):
        self.assertEqual(cp.device_name("1", "1"), "Temp Name 01-001")

    def test_preserves_existing_padding(self):
        self.assertEqual(cp.device_name("01", "001"), "Temp Name 01-001")

    def test_does_not_truncate_longer_values(self):
        self.assertEqual(cp.device_name("100", "1234"), "Temp Name 100-1234")

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(cp.device_name(" 2 ", " 7 "), "Temp Name 02-007")


class TestDotenv(unittest.TestCase):
    def _write(self, text, name=".env"):
        d = tempfile.mkdtemp()
        path = os.path.join(d, name)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def test_parses_simple_pairs(self):
        env = common.parse_dotenv(self._write("HUBBLE_API_TOKEN=abc123\nHUBBLE_ORG_ID=org-1\n"))
        self.assertEqual(env["HUBBLE_API_TOKEN"], "abc123")
        self.assertEqual(env["HUBBLE_ORG_ID"], "org-1")

    def test_ignores_comments_and_blank_lines(self):
        env = common.parse_dotenv(self._write("# a comment\n\nHUBBLE_ORG_ID=org-1\n\n"))
        self.assertEqual(env, {"HUBBLE_ORG_ID": "org-1"})

    def test_strips_export_prefix_and_surrounding_quotes(self):
        env = common.parse_dotenv(self._write(
            'export HUBBLE_API_TOKEN="tok en"\n'
            "HUBBLE_ORG_ID='org-1'\n"
            "HUBBLE_ENDPOINT = https://api.hubble.com \n"))
        self.assertEqual(env["HUBBLE_API_TOKEN"], "tok en")
        self.assertEqual(env["HUBBLE_ORG_ID"], "org-1")
        self.assertEqual(env["HUBBLE_ENDPOINT"], "https://api.hubble.com")

    def test_value_containing_equals_is_kept_whole(self):
        env = common.parse_dotenv(self._write("HUBBLE_API_TOKEN=ab=cd==\n"))
        self.assertEqual(env["HUBBLE_API_TOKEN"], "ab=cd==")

    def test_ignores_malformed_lines(self):
        env = common.parse_dotenv(self._write("not a pair\nHUBBLE_ORG_ID=org-1\n"))
        self.assertEqual(env, {"HUBBLE_ORG_ID": "org-1"})

    def test_dotenv_wins_over_real_environment(self):
        # A permanent personal-org token/org-id in the shell profile must not
        # silently shadow the .env this pool is meant to use.
        path = self._write("HUBBLE_ORG_ID=from-file\nHUBBLE_API_TOKEN=from-file\n")
        environ = {"HUBBLE_ORG_ID": "from-shell"}
        loaded = common.apply_dotenv(path, environ)
        self.assertEqual(loaded, path)
        self.assertEqual(environ["HUBBLE_ORG_ID"], "from-file")
        self.assertEqual(environ["HUBBLE_API_TOKEN"], "from-file")

    def test_api_key_is_accepted_as_a_token_alias(self):
        self.assertIn("HUBBLE_API_KEY", common.TOKEN_VARS)
        self.assertIn("HUBBLE_API_TOKEN", common.TOKEN_VARS)
        # HUBBLE_API_TOKEN takes precedence when both are set
        self.assertLess(common.TOKEN_VARS.index("HUBBLE_API_TOKEN"),
                        common.TOKEN_VARS.index("HUBBLE_API_KEY"))

    def test_file_api_key_beats_an_environment_api_token(self):
        # HUBBLE_API_TOKEN is checked first, so a shell-level one would
        # otherwise shadow the file's HUBBLE_API_KEY.
        path = self._write("HUBBLE_API_KEY=from-file\n")
        env = {"HUBBLE_API_TOKEN": "from-shell", "HUBBLE_ENDPOINT": "https://x"}
        common.apply_dotenv(path, env)
        token = next(env[v] for v in common.TOKEN_VARS if env.get(v))
        self.assertEqual(token, "from-file")
        self.assertEqual(env["HUBBLE_ENDPOINT"], "https://x")  # untouched group

    def test_missing_file_is_not_an_error(self):
        environ = {}
        self.assertIsNone(common.apply_dotenv("/nonexistent/.env", environ))
        self.assertEqual(environ, {})

    def test_find_dotenv_prefers_the_first_candidate_that_exists(self):
        first = self._write("A=1")
        second = self._write("B=2")
        found = common.find_dotenv([os.path.join(os.path.dirname(first), "nope"),
                                second, first])
        self.assertEqual(found, second)


class TestResolveName(unittest.TestCase):
    def _pool(self, fieldnames, colmap, row):
        return cp.Pool(comments=[], fieldnames=fieldnames, rows=[row], colmap=colmap)

    def test_uses_the_csv_column_verbatim(self):
        pool = self._pool(
            ["actual_device_id", "box_no", "label_no", "device_name"],
            {"actual_device_id": "actual_device_id", "box_no": "box_no",
             "label_no": "label_no", "device_name": "device_name"},
            {"actual_device_id": "dev-1", "box_no": "01", "label_no": "001",
             "device_name": "Booth Label A"},
        )
        self.assertEqual(cp.resolve_name(pool, pool.rows[0]), "Booth Label A")

    def test_does_not_reformat_or_pad_the_csv_value(self):
        pool = self._pool(
            ["actual_device_id", "box_no", "label_no", "label_name"],
            {"actual_device_id": "actual_device_id", "box_no": "box_no",
             "label_no": "label_no", "device_name": "label_name"},
            {"actual_device_id": "dev-1", "box_no": "1", "label_no": "1",
             "label_name": "  Temp Name 1-1  "},
        )
        self.assertEqual(cp.resolve_name(pool, pool.rows[0]), "Temp Name 1-1")

    def test_blank_cell_in_a_present_column_is_a_row_error(self):
        pool = self._pool(
            ["actual_device_id", "box_no", "label_no", "device_name"],
            {"actual_device_id": "actual_device_id", "box_no": "box_no",
             "label_no": "label_no", "device_name": "device_name"},
            {"actual_device_id": "dev-1", "box_no": "01", "label_no": "001",
             "device_name": ""},
        )
        with self.assertRaises(cp.RowError):
            cp.resolve_name(pool, pool.rows[0])

    def test_falls_back_to_box_label_when_column_is_absent(self):
        pool = self._pool(
            ["actual_device_id", "box_no", "label_no"],
            {"actual_device_id": "actual_device_id", "box_no": "box_no",
             "label_no": "label_no"},
            {"actual_device_id": "dev-1", "box_no": "1", "label_no": "1"},
        )
        self.assertEqual(cp.resolve_name(pool, pool.rows[0]), "Temp Name 01-001")


class TestReadRows(unittest.TestCase):
    def _read(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
            fh.write(text)
            path = fh.name
        self.addCleanup(os.unlink, path)
        return cp.read_pool(path)

    def test_skips_leading_comments_and_keeps_them(self):
        pool = self._read(
            "# exported from the demo org\n"
            "# one row per label\n"
            "actual_device_id,box_no,label_no\n"
            "11111111-1111-4111-8111-111111111111,01,001\n"
        )
        self.assertEqual(
            pool.comments,
            ["# exported from the demo org", "# one row per label"],
        )
        self.assertEqual(len(pool.rows), 1)
        self.assertEqual(pool.rows[0]["box_no"], "01")

    def test_header_matching_is_case_insensitive_and_tolerates_variants(self):
        pool = self._read(
            "Actual_Device_ID,Box,Label\n"
            "11111111-1111-4111-8111-111111111111,3,9\n"
        )
        row = pool.rows[0]
        self.assertEqual(cp.field(pool, row, "actual_device_id"),
                         "11111111-1111-4111-8111-111111111111")
        self.assertEqual(cp.field(pool, row, "box_no"), "3")
        self.assertEqual(cp.field(pool, row, "label_no"), "9")

    def test_name_column_is_recognized_by_alias(self):
        pool = self._read(
            "actual_device_id,box_no,label_no,Label Name\n"
            "11111111-1111-4111-8111-111111111111,1,1,My Label\n"
        )
        self.assertEqual(pool.colmap["device_name"], "Label Name")
        self.assertEqual(cp.resolve_name(pool, pool.rows[0]), "My Label")

    def test_name_column_is_optional(self):
        pool = self._read(
            "actual_device_id,box_no,label_no\n"
            "11111111-1111-4111-8111-111111111111,1,1\n"
        )
        self.assertNotIn("device_name", pool.colmap)

    def test_missing_required_column_is_an_error(self):
        with self.assertRaises(cp.PoolError):
            self._read("box_no,label_no\n01,001\n")


class TestWriteRows(unittest.TestCase):
    def test_round_trip_preserves_comments_and_appends_columns(self):
        pool = cp.Pool(
            comments=["# a comment"],
            fieldnames=["actual_device_id", "box_no", "label_no"],
            rows=[{"actual_device_id": "dev-1", "box_no": "01", "label_no": "001"}],
            colmap={"actual_device_id": "actual_device_id",
                    "box_no": "box_no", "label_no": "label_no"},
        )
        pool.rows[0]["claim_id"] = "claim-1"
        pool.rows[0]["claim_token"] = "tok-1"
        pool.rows[0]["device_name"] = "Temp Name 01-001"

        buf = io.StringIO()
        common.write_pool(buf, pool)
        text = buf.getvalue()

        self.assertTrue(text.startswith("# a comment\n"))
        body = list(csv.DictReader(io.StringIO(
            "\n".join(l for l in text.splitlines() if not l.startswith("#")))))
        self.assertEqual(body[0]["claim_id"], "claim-1")
        self.assertEqual(body[0]["claim_token"], "tok-1")
        self.assertEqual(body[0]["device_name"], "Temp Name 01-001")
        self.assertEqual(body[0]["actual_device_id"], "dev-1")


class TestOutputPath(unittest.TestCase):
    """Resume depends on reading and writing the same file, so writing back to
    the input is the default; anything else must be asked for explicitly."""

    def test_default_is_the_input_path(self):
        self.assertEqual(cp.output_path("pool.csv", out=None), "pool.csv")

    def test_out_redirects(self):
        self.assertEqual(cp.output_path("pool.csv", out="other.csv"), "other.csv")

    def test_redirecting_is_flagged_as_breaking_resume(self):
        self.assertTrue(cp.breaks_resume("pool.csv", "other.csv"))
        self.assertFalse(cp.breaks_resume("pool.csv", "pool.csv"))


class FakeClient:
    """Records calls; lets a test force a failure on a chosen device.

    Mirrors the real API: claim_token comes back only if it was sent in.
    """

    def __init__(self, fail_on_patch=(), fail_on_claim=(), echo_token=True,
                 fail_on_activate=()):
        self.claims = 0
        self.patched = []
        self.activated = []
        self.fail_on_activate = set(fail_on_activate)
        self.gets = []
        self.fail_on_patch = set(fail_on_patch)
        self.fail_on_claim = set(fail_on_claim)
        self.tokens_sent = []
        self.tokens_set = []
        self.echo_token = echo_token

    def create_claim(self, claim_token=None):
        self.claims += 1
        n = self.claims
        if n in self.fail_on_claim:
            raise cp.APIError("claim boom")
        self.tokens_sent.append(claim_token)
        body = {"claim_id": f"claim-{n}"}
        if claim_token and self.echo_token:
            body["claim_token"] = claim_token
        return body

    def set_claim_token(self, claim_id, claim_token):
        self.tokens_set.append((claim_id, claim_token))
        return {"claim_id": claim_id, "claim_token": claim_token}

    def get_device(self, device_id):
        self.gets.append(device_id)
        return {"id": device_id, "tags": {"_env": "production"}}

    def patch_device(self, device_id, body):
        # Activation is its own PATCH; record it apart from the link PATCH
        # the tests below reason about.
        if body == {"set_activated": True}:
            if device_id in self.fail_on_activate:
                raise cp.APIError("activate boom")
            self.activated.append(device_id)
            return
        if device_id in self.fail_on_patch:
            raise cp.APIError("patch boom")
        self.patched.append((device_id, body))


class TestProcess(unittest.TestCase):
    def _pool(self, rows, named=False):
        fieldnames = ["actual_device_id", "box_no", "label_no"]
        colmap = {"actual_device_id": "actual_device_id",
                  "box_no": "box_no", "label_no": "label_no"}
        if named:
            fieldnames.append("device_name")
            colmap["device_name"] = "device_name"
        return cp.Pool(comments=[], fieldnames=fieldnames, rows=rows, colmap=colmap)

    def test_patch_uses_the_name_from_the_csv(self):
        pool = self._pool([{"actual_device_id": "dev-1", "box_no": "01",
                            "label_no": "001", "device_name": "Booth Label A"}],
                          named=True)
        client = FakeClient()
        cp.process(pool, client)
        self.assertEqual(client.patched[0][1]["set_name"], "Booth Label A")
        self.assertEqual(pool.rows[0]["device_name"], "Booth Label A")

    def test_blank_name_in_a_present_column_fails_the_row_and_creates_no_claim(self):
        pool = self._pool([{"actual_device_id": "dev-1", "box_no": "01",
                            "label_no": "001", "device_name": ""}], named=True)
        client = FakeClient()
        summary = cp.process(pool, client)
        self.assertEqual(summary.failed, 1)
        self.assertEqual(client.claims, 0)
        self.assertEqual(client.patched, [])
        self.assertIn("device_name", pool.rows[0]["error"])

    def test_generates_and_sends_a_claim_token(self):
        pool = self._pool([{"actual_device_id": "dev-1",
                            "box_no": "01", "label_no": "001"}])
        client = FakeClient()
        cp.process(pool, client)

        sent = client.tokens_sent[0]
        self.assertTrue(sent, "a claim_token must be supplied; the API generates none")
        uuid.UUID(sent)  # well-formed
        self.assertEqual(pool.rows[0]["claim_token"], sent)

    def test_token_is_recorded_even_if_the_response_omits_it(self):
        pool = self._pool([{"actual_device_id": "dev-1",
                            "box_no": "01", "label_no": "001"}])
        client = FakeClient(echo_token=False)
        cp.process(pool, client)
        self.assertEqual(pool.rows[0]["claim_token"], client.tokens_sent[0])

    def test_each_device_gets_a_distinct_token(self):
        pool = self._pool([{"actual_device_id": f"dev-{i}", "box_no": "01",
                            "label_no": f"{i:03d}"} for i in range(1, 6)])
        client = FakeClient()
        cp.process(pool, client)
        self.assertEqual(len(set(client.tokens_sent)), 5)

    def test_backfills_a_token_on_a_claim_that_has_none(self):
        """The real failure mode: a claim created before tokens were supplied."""
        pool = self._pool([{"actual_device_id": "dev-1", "box_no": "01",
                            "label_no": "001",
                            "claim_id": "claim-existing", "claim_token": ""}])
        client = FakeClient()
        summary = cp.process(pool, client)

        self.assertEqual(client.claims, 0, "must not create a second claim")
        self.assertEqual(len(client.tokens_set), 1)
        claim_id, token = client.tokens_set[0]
        self.assertEqual(claim_id, "claim-existing")
        uuid.UUID(token)
        self.assertEqual(pool.rows[0]["claim_token"], token)
        self.assertEqual(summary.repaired, 1)

    def test_a_fully_claimed_row_is_left_alone(self):
        pool = self._pool([{"actual_device_id": "dev-1", "box_no": "01",
                            "label_no": "001", "claim_id": "c1",
                            "claim_token": "t1"}])
        client = FakeClient()
        summary = cp.process(pool, client)
        self.assertEqual(summary.skipped, 1)
        self.assertEqual(client.claims, 0)
        self.assertEqual(client.tokens_set, [])

    def test_happy_path_sends_one_combined_patch(self):
        pool = self._pool([{"actual_device_id": "dev-1",
                            "box_no": "01", "label_no": "001"}])
        client = FakeClient()
        summary = cp.process(pool, client)

        self.assertEqual(summary.claimed, 1)
        self.assertEqual(summary.failed, 0)
        self.assertEqual(client.claims, 1)
        self.assertEqual(len(client.patched), 1)

        device_id, body = client.patched[0]
        self.assertEqual(device_id, "dev-1")
        self.assertEqual(body["set_name"], "Temp Name 01-001")
        self.assertEqual(body["set_device_claim_id"], "claim-1")
        # existing tags survive the merge
        self.assertEqual(body["set_tags"],
                         {"_env": "production", "box_no": "01", "label_no": "001"})

        self.assertEqual(pool.rows[0]["claim_id"], "claim-1")
        self.assertTrue(pool.rows[0]["claim_token"])
        self.assertEqual(pool.rows[0]["device_name"], "Temp Name 01-001")

    def test_claimed_devices_are_activated_and_skipped_ones_are_not(self):
        pool = self._pool([
            {"actual_device_id": "dev-1", "box_no": "01", "label_no": "001",
             "claim_id": "claim-existing", "claim_token": "tok-existing"},
            {"actual_device_id": "dev-2", "box_no": "01", "label_no": "002"},
        ])
        client = FakeClient()
        cp.process(pool, client)
        self.assertEqual(client.activated, ["dev-2"])

    def test_no_activate_and_dry_run_activate_nothing(self):
        for kwargs in ({"activate": False}, {"dry_run": True}):
            pool = self._pool([{"actual_device_id": "dev-1",
                                "box_no": "01", "label_no": "001"}])
            client = FakeClient()
            cp.process(pool, client, **kwargs)
            self.assertEqual(client.activated, [], kwargs)

    def test_failed_activation_is_retried_without_a_second_claim(self):
        pool = self._pool([{"actual_device_id": "dev-1",
                            "box_no": "01", "label_no": "001"}])
        client = FakeClient(fail_on_activate={"dev-1"})
        summary = cp.process(pool, client)
        self.assertEqual(summary.failed, 1)
        self.assertIn("activation failed", pool.rows[0]["error"])
        self.assertEqual(pool.rows[0]["claim_id"], "claim-1")

        client.fail_on_activate.clear()
        summary = cp.process(pool, client)
        self.assertEqual(summary.claimed, 1)
        self.assertEqual(client.claims, 1)
        self.assertEqual(client.activated, ["dev-1"])
        self.assertEqual(pool.rows[0]["error"], "")

    def test_rows_with_existing_claim_id_are_skipped(self):
        pool = self._pool([
            {"actual_device_id": "dev-1", "box_no": "01", "label_no": "001",
             "claim_id": "claim-existing", "claim_token": "tok-existing"},
            {"actual_device_id": "dev-2", "box_no": "01", "label_no": "002"},
        ])
        client = FakeClient()
        summary = cp.process(pool, client)

        self.assertEqual(summary.skipped, 1)
        self.assertEqual(summary.claimed, 1)
        self.assertEqual(client.claims, 1)
        self.assertEqual([d for d, _ in client.patched], ["dev-2"])
        self.assertEqual(pool.rows[0]["claim_token"], "tok-existing")

    def test_patch_failure_records_error_and_keeps_claim_id(self):
        pool = self._pool([
            {"actual_device_id": "dev-1", "box_no": "01", "label_no": "001"},
            {"actual_device_id": "dev-2", "box_no": "01", "label_no": "002"},
        ])
        client = FakeClient(fail_on_patch={"dev-1"})
        summary = cp.process(pool, client)

        self.assertEqual(summary.failed, 1)
        self.assertEqual(summary.claimed, 1)
        # the orphaned claim is still written out so a retry links it
        self.assertEqual(pool.rows[0]["claim_id"], "claim-1")
        self.assertIn("patch boom", pool.rows[0]["error"])
        # the run continued
        self.assertEqual([d for d, _ in client.patched], ["dev-2"])

    def test_retry_links_an_orphaned_claim_without_creating_a_new_one(self):
        pool = self._pool([
            {"actual_device_id": "dev-1", "box_no": "01", "label_no": "001",
             "claim_id": "claim-1", "claim_token": "tok-1",
             "error": "APIError: patch boom"},
        ])
        client = FakeClient()
        summary = cp.process(pool, client)

        self.assertEqual(client.claims, 0)
        self.assertEqual(summary.claimed, 1)
        self.assertEqual(client.patched[0][1]["set_device_claim_id"], "claim-1")
        self.assertEqual(pool.rows[0]["error"], "")

    def test_claim_failure_records_error_and_sends_no_patch(self):
        pool = self._pool([{"actual_device_id": "dev-1",
                            "box_no": "01", "label_no": "001"}])
        client = FakeClient(fail_on_claim={1})
        summary = cp.process(pool, client)

        self.assertEqual(summary.failed, 1)
        self.assertEqual(client.patched, [])
        self.assertEqual(pool.rows[0]["claim_id"], "")
        self.assertIn("claim boom", pool.rows[0]["error"])

    def test_dry_run_touches_no_write_endpoint(self):
        pool = self._pool([{"actual_device_id": "dev-1",
                            "box_no": "01", "label_no": "001"}])
        client = FakeClient()
        summary = cp.process(pool, client, dry_run=True)

        self.assertEqual(client.claims, 0)
        self.assertEqual(client.patched, [])
        self.assertEqual(summary.claimed, 0)
        self.assertEqual(summary.planned, 1)

    def test_a_repair_counts_against_the_limit(self):
        """--limit is the safety valve: N means N mutations, of any kind."""
        pool = self._pool([
            {"actual_device_id": "dev-1", "box_no": "01", "label_no": "001",
             "claim_id": "claim-existing", "claim_token": ""},
            {"actual_device_id": "dev-2", "box_no": "01", "label_no": "002"},
        ])
        client = FakeClient()
        summary = cp.process(pool, client, limit=1)
        self.assertEqual(summary.repaired, 1)
        self.assertEqual(client.claims, 0, "row 2 must not be touched")
        self.assertEqual(client.patched, [])

    def test_limit_stops_after_n_rows(self):
        pool = self._pool([
            {"actual_device_id": f"dev-{i}", "box_no": "01",
             "label_no": f"{i:03d}"} for i in range(1, 6)
        ])
        client = FakeClient()
        cp.process(pool, client, limit=2)
        self.assertEqual(len(client.patched), 2)

    def test_missing_box_or_label_is_a_row_error_not_a_crash(self):
        pool = self._pool([{"actual_device_id": "dev-1",
                            "box_no": "", "label_no": "001"}])
        client = FakeClient()
        summary = cp.process(pool, client)
        self.assertEqual(summary.failed, 1)
        self.assertEqual(client.claims, 0)
        self.assertIn("box_no", pool.rows[0]["error"])

    def test_tag_cap_is_enforced_before_patching(self):
        class ManyTags(FakeClient):
            def get_device(self, device_id):
                return {"id": device_id,
                        "tags": {f"t{i}": "v" for i in range(10)}}

        pool = self._pool([{"actual_device_id": "dev-1",
                            "box_no": "01", "label_no": "001"}])
        client = ManyTags()
        summary = cp.process(pool, client)
        self.assertEqual(summary.failed, 1)
        self.assertEqual(client.patched, [])
        self.assertIn("10 tag", pool.rows[0]["error"])


if __name__ == "__main__":
    unittest.main()
