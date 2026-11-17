import hashlib
import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from collections import Counter
from pathlib import Path

from cluster_core import (
    build_hashcat_command,
    build_mask_command,
    load_targets,
    parse_recovered,
    parse_john_show,
    partition_keyspace,
    run_plan,
    shard_wordlist,
    validate_assignment,
)


class ClusterCoreTests(unittest.TestCase):
    def test_mask_partitions_cover_hashcat_keyspace_without_overlap(self):
        for keyspace in (0, 3, 43, 1188137600):
            intervals = [partition_keyspace(keyspace, n, 20) for n in range(1, 21)]
            self.assertEqual(sum(limit for _, limit in intervals), keyspace)
            self.assertEqual(intervals[0][0], 0)
            for (start, limit), (next_start, _) in zip(intervals, intervals[1:]):
                self.assertEqual(start + limit, next_start)
            self.assertEqual(intervals[-1][0] + intervals[-1][1], keyspace)

    def test_mask_command_uses_exact_interval(self):
        command = build_mask_command(
            Path("hashcat.exe"), Path("hashes.txt"), Path("node-01"),
            "mask-stage", "?d?d?d?d", 5, 7,
        )
        self.assertIn("--skip=5", command)
        self.assertIn("--limit=7", command)
        self.assertEqual(command[-2:], ["hashes.txt", "?d?d?d?d"])

    def test_mask_stage_uses_hashcat_keyspace_for_this_computer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = hashlib.sha256(b"answer").hexdigest()
            manifest = root / "targets.json"
            manifest.write_text(json.dumps({"targets": [{"name": "Example", "hash": digest}]}))
            words = root / "words.txt"
            words.write_text("first\nsecond\n")
            executable = root / "fake_hashcat"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "if '--keyspace' in args:\n"
                "    print('43')\n"
                "    sys.exit(0)\n"
                "if '-a' in args and args[args.index('-a') + 1] == '3':\n"
                "    assert '--skip=3' in args and '--limit=3' in args\n"
                "    out = next(a.split('=', 1)[1] for a in args if a.startswith('--outfile='))\n"
                "    hashes = pathlib.Path(args[-2])\n"
                "    pathlib.Path(out).write_text(hashes.read_text().strip() + ':answer\\n')\n"
            )
            executable.chmod(0o755)
            with contextlib.redirect_stdout(io.StringIO()):
                code = run_plan(manifest, 2, 20, executable, [words], [], root / "state", masks=True)
            self.assertEqual(code, 0)
            node = root / "state" / "node-02"
            result = json.loads((node / "results.json").read_text())
            self.assertEqual(result["found"][0]["plaintext"], "answer")

    def test_shards_cover_every_input_line_exactly_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            words = [f"word-{i}\n".encode() for i in range(43)] + [b"duplicate\n"] * 2
            source = root / "words.txt"
            source.write_bytes(b"".join(words))
            observed = []
            for computer in range(1, 21):
                shard = root / f"shard-{computer}.txt"
                shard_wordlist(source, shard, computer, 20)
                observed.extend(shard.read_bytes().splitlines(keepends=True))
            self.assertEqual(Counter(observed), Counter(words))

    def test_assignment_rejects_invalid_nodes(self):
        for computer, total in ((0, 20), (21, 20), (1, 0), (1, 21)):
            with self.subTest(computer=computer, total=total):
                with self.assertRaises(ValueError):
                    validate_assignment(computer, total)

    def test_targets_require_named_unique_64_hex_values(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "targets.json"
            digest = hashlib.sha256(b"answer").hexdigest()
            source.write_text(json.dumps({"targets": [{"name": "Example", "hash": digest}]}))
            self.assertEqual(load_targets(source), [{"name": "Example", "hash": digest}])
            source.write_text(json.dumps({"targets": [{"name": "Bad", "hash": "a" * 63}]}))
            with self.assertRaises(ValueError):
                load_targets(source)

    def test_target_source_must_match_manifest_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = hashlib.sha256(b"answer").hexdigest()
            (root / "source.txt").write_text(digest + "\n")
            manifest = root / "targets.json"
            manifest.write_text(json.dumps({"targets": [
                {"name": "Example", "hash": digest, "source": "source.txt"}
            ]}))
            self.assertEqual(load_targets(manifest)[0]["hash"], digest)
            (root / "source.txt").write_text("0" * 64 + "\n")
            with self.assertRaises(ValueError):
                load_targets(manifest)

    def test_command_uses_node_local_state_and_rule(self):
        command = build_hashcat_command(
            Path("hashcat.exe"), Path("hashes.txt"), Path("shard.txt"),
            Path("node-01"), "stage_0001", Path("best66.rule"),
        )
        self.assertIn("--session=stage_0001", command)
        self.assertIn("--potfile-path=node-01/hashcat.potfile", command)
        self.assertIn("--outfile=node-01/stage_0001.out", command)
        self.assertEqual(command[-2:], ["-r", "best66.rule"])

    def test_recovered_password_must_reproduce_target_before_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "recovered.out"
            correct = b"Answer:42"
            digest = hashlib.sha256(correct).hexdigest()
            other = hashlib.sha256(b"else").hexdigest()
            source.write_bytes(
                digest.encode() + b":$HEX[" + correct.hex().encode() + b"]\n"
                + other.encode() + b":wrong\n"
            )
            result = parse_recovered(source, [{"name": "Example", "hash": digest}, {"name": "Other", "hash": other}])
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["flag"], "FLAG{" + hashlib.md5(correct).hexdigest() + "}")
            self.assertEqual(result[0]["plaintext_hex"], correct.hex())

    def test_john_show_ignores_unverified_plaintext(self):
        digest = hashlib.sha256(b"answer").hexdigest()
        targets = [{"name": "Example", "hash": digest}]
        records = parse_john_show(b"?:wrong\n?:answer\n1 password hash cracked\n", targets)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["plaintext"], "answer")

    def test_run_uses_local_shard_and_resumes_completed_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            password = b"answer"
            digest = hashlib.sha256(password).hexdigest()
            manifest = root / "targets.json"
            manifest.write_text(json.dumps({"targets": [{"name": "Example", "hash": digest}]}))
            words = root / "words.txt"
            words.write_bytes(b"first\nanswer\nthird\n")
            other = root / "other.txt"
            other.write_bytes(b"unused\n")
            executable = root / "fake_hashcat"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "out = next(a.split('=', 1)[1] for a in args if a.startswith('--outfile='))\n"
                "hashes = next(pathlib.Path(a) for a in args if a.endswith('targets_sha256.txt'))\n"
                "wordlist = next(pathlib.Path(a) for a in args if 'wordlist_' in a and a.endswith('.txt'))\n"
                "with pathlib.Path('invocations.txt').open('a') as log: log.write('run\\n')\n"
                "if b'answer\\n' in wordlist.read_bytes().splitlines(keepends=True):\n"
                "    pathlib.Path(out).write_text(hashes.read_text().strip() + ':answer\\n')\n"
                "sys.exit(0)\n"
            )
            executable.chmod(0o755)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run_plan(manifest, 2, 2, executable, [words, other], [], root / "state"), 0)
                self.assertEqual(run_plan(manifest, 2, 2, executable, [words, other], [], root / "state"), 0)
            node = root / "state" / "node-02"
            result = json.loads((node / "results.json").read_text())
            self.assertEqual(result["found"][0]["plaintext"], "answer")
            self.assertEqual((root / "invocations.txt").read_text(), "run\n")
            self.assertEqual((node / "wordlist_01.txt").read_bytes(), b"answer\n")

    def test_explicit_john_engine_uses_the_same_shard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = hashlib.sha256(b"answer").hexdigest()
            manifest = root / "targets.json"
            manifest.write_text(json.dumps({"targets": [{"name": "Example", "hash": digest}]}))
            words = root / "words.txt"
            words.write_bytes(b"first\nanswer\nthird\n")
            john = root / "fake_john"
            john.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "if '--show' in args:\n"
                "    print('?:answer')\n"
                "else:\n"
                "    wordlist = pathlib.Path(next(a.split('=', 1)[1] for a in args if a.startswith('--wordlist=')))\n"
                "    assert wordlist.read_bytes() == b'answer\\n'\n"
            )
            john.chmod(0o755)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run_plan(manifest, 2, 2, john, [words], [], root / "state", "john"), 0)
            result = json.loads((root / "state" / "node-02" / "results.json").read_text())
            self.assertEqual(result["found"][0]["plaintext"], "answer")

    def test_john_can_use_same_computer_after_hashcat_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = hashlib.sha256(b"answer").hexdigest()
            manifest = root / "targets.json"
            manifest.write_text(json.dumps({"targets": [{"name": "Example", "hash": digest}]}))
            words = root / "words.txt"
            words.write_text("answer\n")
            hashcat = root / "fake_hashcat"
            hashcat.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(2)\n")
            hashcat.chmod(0o755)
            john = root / "fake_john"
            john.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "if '--show' in sys.argv: print('?:answer')\n"
            )
            john.chmod(0o755)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run_plan(manifest, 1, 1, hashcat, [words], [], root / "state"), 1)
                self.assertEqual(run_plan(manifest, 1, 1, john, [words], [], root / "state", "john"), 0)
            node = root / "state" / "node-01"
            self.assertTrue((node / "state_hashcat.json").is_file())
            self.assertTrue((node / "state_john.json").is_file())
            result = json.loads((node / "results.json").read_text())
            self.assertEqual(result["found"][0]["plaintext"], "answer")

    def test_stop_flag_interrupts_active_hashcat_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = hashlib.sha256(b"answer").hexdigest()
            manifest = root / "targets.json"
            manifest.write_text(json.dumps({"targets": [{"name": "Example", "hash": digest}]}))
            words = root / "words.txt"
            words.write_text("answer\n")
            executable = root / "fake_hashcat"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "out = next(a.split('=', 1)[1] for a in args if a.startswith('--outfile='))\n"
                "hashes = next(pathlib.Path(a) for a in args if a.endswith('targets_sha256.txt'))\n"
                "pathlib.Path(out).write_text(hashes.read_text().strip() + ':answer\\n')\n"
                "sys.stdin.readline()\n"
            )
            executable.chmod(0o755)
            node = root / "state" / "node-01"

            def request_stop():
                deadline = time.monotonic() + 5
                while not list(node.glob("hashlab*.log")) and time.monotonic() < deadline:
                    time.sleep(0.01)
                (node / "stop.flag").write_text("stop")

            stopper = threading.Thread(target=request_stop)
            stopper.start()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run_plan(manifest, 1, 1, executable, [words], [], root / "state"), 2)
            stopper.join()
            state = json.loads((node / "state_hashcat.json").read_text())
            self.assertEqual(state["completed"], [])
            results = json.loads((node / "results.json").read_text())
            self.assertEqual(results["found"][0]["plaintext"], "answer")


if __name__ == "__main__":
    unittest.main()
