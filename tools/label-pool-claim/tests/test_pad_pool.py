"""Tests for pad_pool. Run: python3 -m unittest -v test_pad_pool"""
import os
import tempfile
import unittest

from kiosk import claim_pool as cp
from kiosk import pad_pool as pp


class TestPadName(unittest.TestCase):
    def test_pads_trailing_box_label_pair(self):
        self.assertEqual(pp.pad_name("Hubble Smart Label 1-1", "1", "1"),
                         "Hubble Smart Label 01-001")

    def test_leaves_an_already_padded_name_alone(self):
        self.assertEqual(pp.pad_name("Hubble Smart Label 01-001", "01", "001"),
                         "Hubble Smart Label 01-001")

    def test_pads_a_partially_padded_name(self):
        self.assertEqual(pp.pad_name("Hubble Smart Label 2-200", "2", "200"),
                         "Hubble Smart Label 02-200")

    def test_tolerates_spaces_around_the_separator(self):
        self.assertEqual(pp.pad_name("Label 3 - 7", "3", "7"), "Label 03-007")

    def test_refuses_when_embedded_numbers_disagree_with_the_columns(self):
        with self.assertRaises(pp.PadError) as ctx:
            pp.pad_name("Hubble Smart Label 9-9", "1", "1")
        self.assertIn("disagree", str(ctx.exception))

    def test_name_without_a_number_pair_is_left_untouched(self):
        self.assertEqual(pp.pad_name("Booth Label A", "1", "1"), "Booth Label A")

    def test_does_not_touch_digits_that_are_not_the_trailing_pair(self):
        self.assertEqual(pp.pad_name("Gen2 Label 1-1", "1", "1"),
                         "Gen2 Label 01-001")


class TestPadPool(unittest.TestCase):
    def _pool_from(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
            fh.write(text)
            path = fh.name
        self.addCleanup(os.unlink, path)
        return path

    def test_pads_columns_and_names(self):
        path = self._pool_from(
            "box_no,label_no,device_name,actual_device_id,claim_id,claim_token\n"
            "1,1,Hubble Smart Label 1-1,11111111-1111-4111-8111-111111111111,,\n"
            "2,200,Hubble Smart Label 2-200,22222222-2222-4222-8222-222222222222,,\n"
        )
        pool = cp.read_pool(path)
        changed = pp.pad_pool(pool)

        self.assertEqual(changed, 2)
        self.assertEqual(pool.rows[0]["box_no"], "01")
        self.assertEqual(pool.rows[0]["label_no"], "001")
        self.assertEqual(pool.rows[0]["device_name"], "Hubble Smart Label 01-001")
        self.assertEqual(pool.rows[1]["box_no"], "02")
        self.assertEqual(pool.rows[1]["label_no"], "200")
        self.assertEqual(pool.rows[1]["device_name"], "Hubble Smart Label 02-200")

    def test_is_idempotent(self):
        path = self._pool_from(
            "box_no,label_no,device_name,actual_device_id\n"
            "01,001,Hubble Smart Label 01-001,11111111-1111-4111-8111-111111111111\n"
        )
        pool = cp.read_pool(path)
        self.assertEqual(pp.pad_pool(pool), 0)
        self.assertEqual(pool.rows[0]["device_name"], "Hubble Smart Label 01-001")

    def test_preserves_other_columns_and_values(self):
        path = self._pool_from(
            "box_no,label_no,device_name,actual_device_id,claim_id,claim_token\n"
            "1,1,Label 1-1,11111111-1111-4111-8111-111111111111,clm_1,tok_1\n"
        )
        pool = cp.read_pool(path)
        pp.pad_pool(pool)
        self.assertEqual(pool.rows[0]["claim_id"], "clm_1")
        self.assertEqual(pool.rows[0]["claim_token"], "tok_1")
        self.assertEqual(pool.rows[0]["actual_device_id"],
                         "11111111-1111-4111-8111-111111111111")

    def test_a_disagreeing_name_aborts_the_whole_file(self):
        path = self._pool_from(
            "box_no,label_no,device_name,actual_device_id\n"
            "1,1,Label 1-1,11111111-1111-4111-8111-111111111111\n"
            "1,2,Label 9-9,22222222-2222-4222-8222-222222222222\n"
        )
        pool = cp.read_pool(path)
        with self.assertRaises(pp.PadError):
            pp.pad_pool(pool)
        # nothing was mutated: the file is all-or-nothing
        self.assertEqual(pool.rows[0]["box_no"], "1")
        self.assertEqual(pool.rows[0]["device_name"], "Label 1-1")

    def test_pool_without_a_name_column_still_pads_the_numbers(self):
        path = self._pool_from(
            "box_no,label_no,actual_device_id\n"
            "1,1,11111111-1111-4111-8111-111111111111\n"
        )
        pool = cp.read_pool(path)
        self.assertEqual(pp.pad_pool(pool), 1)
        self.assertEqual(pool.rows[0]["label_no"], "001")


class TestCLI(unittest.TestCase):
    def test_writes_a_backup_and_pads_in_place(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "pool.csv")
        with open(path, "w") as fh:
            fh.write("# a comment\n"
                     "box_no,label_no,device_name,actual_device_id\n"
                     "1,1,Label 1-1,11111111-1111-4111-8111-111111111111\n")
        rc = pp.main(["--csv", path])
        self.assertEqual(rc, 0)

        text = open(path).read()
        self.assertIn("# a comment", text)
        self.assertIn("01,001,Label 01-001", text)
        self.assertTrue(os.path.isfile(path + ".bak"))
        self.assertIn("1,1,Label 1-1", open(path + ".bak").read())

    def test_padding_does_not_add_columns(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "pool.csv")
        header = "box_no,label_no,device_name,actual_device_id,claim_id,claim_token"
        with open(path, "w") as fh:
            fh.write(header + "\n"
                     "1,1,Label 1-1,11111111-1111-4111-8111-111111111111,,\n")
        self.assertEqual(pp.main(["--csv", path]), 0)
        self.assertEqual(open(path).read().splitlines()[0], header)

    def test_dry_run_changes_nothing(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "pool.csv")
        original = ("box_no,label_no,device_name,actual_device_id\n"
                    "1,1,Label 1-1,11111111-1111-4111-8111-111111111111\n")
        with open(path, "w") as fh:
            fh.write(original)
        rc = pp.main(["--csv", path, "--dry-run"])
        self.assertEqual(rc, 0)
        self.assertEqual(open(path).read(), original)
        self.assertFalse(os.path.isfile(path + ".bak"))

    def test_refuses_to_pad_a_pool_that_already_has_claims(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "pool.csv")
        with open(path, "w") as fh:
            fh.write("box_no,label_no,device_name,actual_device_id,claim_id\n"
                     "1,1,Label 1-1,11111111-1111-4111-8111-111111111111,clm_1\n")
        rc = pp.main(["--csv", path])
        self.assertEqual(rc, 2)
        self.assertIn("1,1,Label 1-1", open(path).read())


if __name__ == "__main__":
    unittest.main()
