import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import make_qr_codes as mq


def write_csv(text):
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", newline="") as fh:
        fh.write(text)
    return path


class TestNaming(unittest.TestCase):
    def test_url_carries_the_token(self):
        self.assertEqual(mq.claim_url(" abc-123 "),
                         "https://dash.hubble.com/claim?claim_token=abc-123&type=device")

    def test_token_is_url_escaped(self):
        self.assertIn("claim_token=a%2Bb%26c", mq.claim_url("a+b&c"))

    def test_file_stem_keeps_the_name_but_drops_unsafe_characters(self):
        self.assertEqual(mq.file_stem("nRF52 WorksWith26 01"), "nRF52 WorksWith26 01")
        self.assertEqual(mq.file_stem('a/b:c*?"<>|.'), "a_b_c______")
        self.assertEqual(mq.file_stem("  "), "unnamed")


class TestPlan(unittest.TestCase):
    def plan(self, text):
        path = write_csv(text)
        self.addCleanup(os.remove, path)
        with redirect_stdout(io.StringIO()):
            return mq.plan([path])

    def test_one_code_per_row_with_a_token(self):
        jobs, skipped = self.plan(
            "device_id,device_name,claim_token\n"
            "d1,Kit 01,t1\n"
            "d2,Kit 02,\n")
        self.assertEqual(jobs, [("Kit 01", mq.claim_url("t1"))])
        self.assertEqual(skipped, 1)

    def test_duplicate_names_get_the_device_id(self):
        jobs, _ = self.plan(
            "device_id,device_name,claim_token\n"
            "d1,Kit,t1\n"
            "d2,kit,t2\n")
        self.assertEqual([stem for stem, _ in jobs], ["Kit d1", "kit d2"])

    @unittest.skipIf(mq.segno is None, "segno not installed")
    def test_writes_one_png_per_device(self):
        path = write_csv("device_id,device_name,claim_token\nd1,Kit 01,t1\n")
        self.addCleanup(os.remove, path)
        with tempfile.TemporaryDirectory() as out, redirect_stdout(io.StringIO()):
            self.assertEqual(mq.main([path, "--out-dir", out]), 0)
            self.assertEqual(os.listdir(out), ["Kit 01.png"])


if __name__ == "__main__":
    unittest.main()
