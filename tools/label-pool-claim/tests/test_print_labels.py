import io
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout

import make_qr_codes as mq
import print_labels as pl

needs_render = unittest.skipIf(pl.segno is None, "segno/Pillow not installed")


def write_csv(text):
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", newline="") as fh:
        fh.write(text)
    return path


class TestCollect(unittest.TestCase):
    def collect(self, text, overrides=(), match=None):
        path = write_csv(text)
        self.addCleanup(os.remove, path)
        log = io.StringIO()
        with redirect_stdout(log):
            labels = pl.collect([path], pl.parse_overrides(list(overrides)), match)
        return labels, log.getvalue()

    CSV = ("device_id,device_name,claim_token\n"
           "d3,Kit 03,t3\n"
           "d1,Kit 01,t1\n"
           "d9,Kit Battery Test,t9\n"
           "d2,Kit 02,\n")

    def test_number_comes_from_the_end_of_the_name_and_labels_sort_by_it(self):
        labels, log = self.collect(self.CSV)
        self.assertEqual([(l.number, l.name) for l in labels],
                         [("01", "Kit 01"), ("03", "Kit 03")])
        self.assertIn("Kit Battery Test", log)   # no number: skipped, with a hint
        self.assertIn("Kit 02: no claim_token", log)
        self.assertEqual(labels[0].url, mq.claim_url("t1"))

    def test_override_numbers_an_unnumbered_device(self):
        labels, _ = self.collect(self.CSV, ["kit battery test=05"])
        self.assertEqual([l.number for l in labels], ["01", "03", "05"])

    def test_match_filters_by_name(self):
        labels, _ = self.collect(self.CSV, match=["03"])
        self.assertEqual([l.name for l in labels], ["Kit 03"])

    def test_bad_override_is_rejected(self):
        with self.assertRaises(ValueError):
            pl.parse_overrides(["no-equals-sign"])


class TestDpi(unittest.TestCase):
    def test_read_from_the_zebra_queue_name(self):
        self.assertEqual(pl.dpi_from_printer_name("ZDesigner ZT411-300dpi ZPL"), 300)
        self.assertEqual(pl.dpi_from_printer_name("ZDesigner ZT411-203dpi ZPL"), 203)
        self.assertIsNone(pl.dpi_from_printer_name("Canon MF741C"))
        self.assertIsNone(pl.dpi_from_printer_name(None))


@needs_render
class TestRender(unittest.TestCase):
    label = pl.Label("Kit 05", "05", mq.claim_url("00000000-0000-4000-8000-000000000005"))

    def test_label_is_two_by_one_inches_at_the_printer_resolution(self):
        for dpi, size in ((203, (406, 203)), (300, (600, 300))):
            img = pl.render(self.label, dpi)
            self.assertEqual((img.size, img.mode), (size, "1"))

    def test_zpl_graphic_round_trips_to_the_same_image(self):
        img = pl.render(self.label, 203)
        zpl = pl.to_zpl(img, copies=2)
        w, h, total, row_bytes, data = re.search(
            r"\^PW(\d+)\n\^LL(\d+).*\^GFA,(\d+),\d+,(\d+),([0-9A-F]+)\^FS", zpl, re.S).groups()
        self.assertEqual((int(w), int(h)), img.size)
        raw = bytes.fromhex(data)
        self.assertEqual(len(raw), int(total))
        self.assertEqual(int(row_bytes), (img.width + 7) // 8)
        rebuilt = pl.Image.frombytes("1", img.size, bytes(255 - b for b in raw))
        self.assertEqual(rebuilt.tobytes(), img.tobytes())
        self.assertIn("^PQ2", zpl)

    def test_padding_bits_past_the_right_edge_are_white(self):
        img = pl.render(self.label, 203)  # 406 wide: 2 padding bits per row
        raw = bytes.fromhex(re.search(r"\^GFA,\d+,\d+,\d+,([0-9A-F]+)", pl.to_zpl(img)).group(1))
        row_bytes = (img.width + 7) // 8
        self.assertTrue(all(raw[r * row_bytes + row_bytes - 1] & 0b11 == 0
                            for r in range(img.height)))

    def test_main_writes_previews_and_one_zpl_file(self):
        path = write_csv("device_id,device_name,claim_token\nd1,Kit 01,t1\nd2,Kit 02,t2\n")
        self.addCleanup(os.remove, path)
        with tempfile.TemporaryDirectory() as out, redirect_stdout(io.StringIO()):
            self.assertEqual(pl.main([path, "--out-dir", out]), 0)
            self.assertEqual(sorted(os.listdir(out)), ["Kit 01.png", "Kit 02.png", "labels.zpl"])
            with open(os.path.join(out, "labels.zpl")) as fh:
                self.assertEqual(fh.read().count("^XA"), 2)


if __name__ == "__main__":
    unittest.main()
