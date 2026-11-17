"""Checks for assembling a compressed offline wordlist from GitHub-sized parts."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from prepare_wordlist import prepare_parts


class PrepareWordlistTests(unittest.TestCase):
    def test_reassembles_and_checks_exact_content(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "list.gz"
            payload = b"abcdefghijklm"
            for index in range(4):
                (Path(directory) / f"list.gz.part.{index:03d}").write_bytes(payload[index * 4:(index + 1) * 4])
            prepare_parts(target, len(payload), hashlib.sha256(payload).hexdigest(), 4)
            self.assertEqual(target.read_bytes(), payload)

    def test_rejects_missing_part(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "list.gz"
            (Path(directory) / "list.gz.part.000").write_bytes(b"abcd")
            with self.assertRaises(ValueError):
                prepare_parts(target, 8, hashlib.sha256(b"abcdefgh").hexdigest(), 4)
            self.assertFalse(target.exists())
