import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from launcher_gui import build_command, tail_lines, validated_targets, verified_results


class LauncherLogicTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        data = self.root / "private_data"
        (data / "hashes").mkdir(parents=True)
        self.targets = []
        for name in ("First", "Second", "Third"):
            digest = hashlib.sha256(name.encode()).hexdigest()
            (data / "hashes" / f"{name}.txt").write_text(digest + "\n")
            self.targets.append({"name": name, "hash": digest, "source": f"hashes/{name}.txt"})
        (data / "targets.json").write_text(json.dumps({"targets": self.targets}))
        for name in (
            "tools/python/python.exe", "tools/python/pythonw.exe",
            "tools/hashcat-7.1.2/hashcat.exe",
            "tools/hashcat-7.1.2/rules/best66.rule",
            "tools/john-1.9.0-jumbo-1-win64/run/john.exe",
            "reglas_ciber.rule", "cluster_core.py",
            "private_data/wordlists/seeds.txt",
            "private_data/wordlists/rockyou.txt",
            "private_data/wordlists/xato_top10m.txt",
            "private_data/screenshots/Gorillaz.png",
            "private_data/screenshots/Morat.png",
            "private_data/screenshots/Final_Copa_Sudamericana.png",
        ):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()

    def test_target_validation_compares_all_three_source_files(self):
        self.assertEqual(len(validated_targets(self.root)), 3)
        (self.root / "private_data/hashes/Second.txt").write_text("0" * 64)
        with self.assertRaises(ValueError):
            validated_targets(self.root)

    def test_gpu_and_cpu_commands_are_portable_and_partitioned(self):
        gpu = build_command(self.root, 7, "hashcat")
        self.assertEqual(gpu[0], str(self.root / "tools/python/python.exe"))
        self.assertIn("--computer", gpu)
        self.assertEqual(gpu[gpu.index("--computer") + 1], "7")
        self.assertIn("--masks", gpu)
        self.assertEqual(gpu.count("--wordlist"), 3)
        self.assertEqual(gpu.count("--rule"), 2)
        cpu = build_command(self.root, 20, "john")
        self.assertNotIn("--masks", cpu)
        self.assertEqual(cpu[cpu.index("--john") + 1], str(self.root / "tools/john-1.9.0-jumbo-1-win64/run/john.exe"))
        with self.assertRaises(ValueError):
            build_command(self.root, 21, "hashcat")

    def test_only_verified_results_are_shown(self):
        node = self.root / "state/node-01"
        node.mkdir(parents=True)
        digest = self.targets[0]["hash"]
        (node / "results.json").write_text(json.dumps({"found": [
            {"name": "First", "hash": digest, "plaintext_hex": "4669727374", "flag": "wrong"},
            {"name": "Second", "hash": self.targets[1]["hash"], "plaintext_hex": "77726f6e67", "flag": "wrong"},
        ]}))
        records = verified_results(node, self.targets)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["flag"], "FLAG{" + hashlib.md5(b"First").hexdigest() + "}")

    def test_tail_reads_bounded_utf8_text(self):
        path = self.root / "large.log"
        path.write_text("\n".join(f"línea {i}" for i in range(200)), encoding="utf-8")
        self.assertEqual(tail_lines(path, 2), ["línea 198", "línea 199"])


if __name__ == "__main__":
    unittest.main()
