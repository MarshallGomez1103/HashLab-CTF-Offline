"""Offline, deterministic Hashcat work sharing for an authorized lab."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path


HEX_64 = re.compile(r"[0-9a-fA-F]{64}\Z")
HEX_OUT = re.compile(rb"\$HEX\[([0-9a-fA-F]+)\]\Z")
DEFAULT_MASKS = (
    "?d?d?d?d?d?d?d?d",
    "?l?l?l?l?d?d?d?d",
    "?l?l?l?l?l?l?l?l",
    "?a?a?a?a?a?a",
    "?l?l?l?l?l?l?l?l?d?d",
    "?u?l?l?l?l?l?l?l?d?d",
)


def validate_assignment(computer: int, total: int) -> None:
    if not 1 <= total <= 20 or not 1 <= computer <= total:
        raise ValueError("Computer must be between 1 and the total, and total must be 1–20.")


def load_targets(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("The target file must contain a nonempty 'targets' list.")
    targets: list[dict[str, str]] = []
    names: set[str] = set()
    hashes: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each target must be an object.")
        name, digest = entry.get("name"), entry.get("hash")
        if not isinstance(name, str) or not name.strip() or "\n" in name or len(name) > 120:
            raise ValueError("Each target needs a short, single-line name.")
        if not isinstance(digest, str) or not HEX_64.fullmatch(digest):
            raise ValueError(f"Target {name!r} is not a 64-character hexadecimal digest.")
        digest = digest.lower()
        if name in names or digest in hashes:
            raise ValueError("Target names and digests must be unique.")
        source = entry.get("source")
        target = {"name": name, "hash": digest}
        if source is not None:
            if not isinstance(source, str) or not source or Path(source).is_absolute() or ".." in Path(source).parts:
                raise ValueError(f"Target {name!r} has an unsafe source path.")
            source_path = path.parent / source
            try:
                actual = source_path.read_text(encoding="ascii").strip().lower()
            except (OSError, UnicodeError) as exc:
                raise ValueError(f"Target {name!r} has an unreadable source file.") from exc
            if actual != digest:
                raise ValueError(f"Target {name!r} differs from its source file.")
            target["source"] = source
        names.add(name)
        hashes.add(digest)
        targets.append(target)
    return targets


def shard_wordlist(source: Path, destination: Path, computer: int, total: int) -> int:
    """Assign each physical line to exactly one 1-based computer."""
    validate_assignment(computer, total)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    count = 0
    with source.open("rb") as incoming, temporary.open("wb") as outgoing:
        for index, line in enumerate(incoming):
            if index % total == computer - 1:
                outgoing.write(line)
                count += 1
    temporary.replace(destination)
    return count


def build_hashcat_command(
    executable: Path,
    hashes_file: Path,
    shard: Path,
    node_dir: Path,
    stage: str,
    rule: Path | None = None,
) -> list[str]:
    command = [
        str(executable), "-m", "1400", "-a", "0", "-w", "1",
        "--hwmon-temp-abort=85", "--status", "--status-timer=30",
        "--restore-timer=60", f"--session={stage}",
        f"--potfile-path={node_dir / 'hashcat.potfile'}",
        f"--outfile={node_dir / (stage + '.out')}",
        "--outfile-format=1,2", str(hashes_file), str(shard),
    ]
    if rule is not None:
        command.extend(("-r", str(rule)))
    return command


def partition_keyspace(keyspace: int, computer: int, total: int) -> tuple[int, int]:
    """Return this computer's disjoint Hashcat --skip/--limit interval."""
    validate_assignment(computer, total)
    if keyspace < 0:
        raise ValueError("Hashcat keyspace must not be negative.")
    size, extra = divmod(keyspace, total)
    index = computer - 1
    return index * size + min(index, extra), size + (1 if index < extra else 0)


def hashcat_keyspace(executable: Path, mask: str) -> int:
    probe = subprocess.run(
        [str(executable), "-m", "1400", "-a", "3", "--keyspace", mask],
        cwd=executable.parent, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, check=False,
    )
    if probe.returncode != 0:
        raise ValueError(f"Hashcat could not calculate keyspace for {mask}.")
    lines = probe.stdout.decode("ascii", errors="replace").strip().splitlines()
    if not lines or not lines[-1].strip().isdigit():
        raise ValueError(f"Hashcat returned an invalid keyspace for {mask}.")
    return int(lines[-1].strip())


def build_mask_command(
    executable: Path, hashes_file: Path, node_dir: Path, stage: str,
    mask: str, skip: int, limit: int,
) -> list[str]:
    if skip < 0 or limit <= 0:
        raise ValueError("Mask partition must contain at least one position.")
    return [
        str(executable), "-m", "1400", "-a", "3", "-w", "1",
        "--hwmon-temp-abort=85", "--status", "--status-timer=30",
        "--restore-timer=60", f"--session={stage}",
        f"--potfile-path={node_dir / 'hashcat.potfile'}",
        f"--outfile={node_dir / (stage + '.out')}",
        "--outfile-format=1,2", f"--skip={skip}", f"--limit={limit}",
        str(hashes_file), mask,
    ]


def parse_recovered(outfile: Path, targets: list[dict[str, str]]) -> list[dict[str, str]]:
    if not outfile.is_file():
        return []
    by_hash = {target["hash"]: target["name"] for target in targets}
    found: dict[str, dict[str, str]] = {}
    for line in outfile.read_bytes().splitlines():
        digest_raw, separator, encoded = line.partition(b":")
        if not separator:
            continue
        try:
            digest = digest_raw.decode("ascii").lower()
        except UnicodeDecodeError:
            continue
        if digest not in by_hash:
            continue
        match = HEX_OUT.fullmatch(encoded)
        if match:
            try:
                plaintext = bytes.fromhex(match.group(1).decode("ascii"))
            except ValueError:
                continue
        else:
            plaintext = encoded
        if hashlib.sha256(plaintext).hexdigest() != digest:
            continue
        found[digest] = _record(by_hash[digest], digest, plaintext)
    return list(found.values())


def _record(name: str, digest: str, plaintext: bytes) -> dict[str, str]:
    record = {
        "name": name, "hash": digest, "plaintext_hex": plaintext.hex(),
        "flag": f"FLAG{{{hashlib.md5(plaintext).hexdigest()}}}",
    }
    try:
        decoded = plaintext.decode("utf-8")
        if decoded.isprintable():
            record["plaintext"] = decoded
    except UnicodeDecodeError:
        pass
    return record


def parse_john_show(output: bytes, targets: list[dict[str, str]]) -> list[dict[str, str]]:
    """Accept John's recovered values only when raw SHA-256 verifies them."""
    found: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        _, separator, candidate = line.partition(b":")
        if not separator:
            continue
        possibilities = [candidate, candidate.partition(b":")[0]]
        for plaintext in possibilities:
            digest = hashlib.sha256(plaintext).hexdigest()
            for target in targets:
                if target["hash"] == digest:
                    found[digest] = _record(target["name"], digest, plaintext)
    return list(found.values())


def _write_json(path: Path, data: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stop_process(process: subprocess.Popen, engine: str) -> None:
    if process.poll() is not None:
        if process.stdin is not None:
            process.stdin.close()
        return
    # Hashcat's interactive checkpoint key saves a restore point before quitting.
    try:
        if engine == "hashcat" and process.stdin is not None:
            process.stdin.write(b"c\n")
            process.stdin.flush()
            process.wait(timeout=20)
        else:
            process.terminate()
            process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    finally:
        if process.stdin is not None:
            process.stdin.close()


def run_plan(
    targets_path: Path, computer: int, total: int, executable: Path | None,
    wordlists: list[Path], rules: list[Path], state_dir: Path,
    engine: str = "hashcat", masks: bool = False,
) -> int:
    validate_assignment(computer, total)
    targets = load_targets(targets_path)
    if engine not in ("hashcat", "john") or executable is None:
        raise ValueError("Choose an available Hashcat or John executable.")
    executable = executable.resolve()
    wordlists = [path.resolve() for path in wordlists]
    rules = [path.resolve() for path in rules]
    if not executable.is_file() or not wordlists or any(not path.is_file() for path in wordlists + rules):
        raise ValueError("Hashcat, every wordlist, and every rule must exist locally.")

    node_dir = state_dir.resolve() / f"node-{computer:02d}"
    node_dir.mkdir(parents=True, exist_ok=True)
    stop_flag = node_dir / "stop.flag"
    log_path = node_dir / "run.log"
    state_path = node_dir / f"state_{engine}.json"
    results_path = node_dir / "results.json"
    if stop_flag.exists():
        raise ValueError("Remove the previous stop.flag before restarting this computer.")

    signature_data = {
        "targets": targets, "computer": computer, "total": total,
        "engine": engine, "executable": _file_hash(executable),
        "wordlists": [(str(path), _file_hash(path)) for path in wordlists],
        "rules": [(str(path), _file_hash(path)) for path in rules],
        "masks": DEFAULT_MASKS if masks and engine == "hashcat" else (),
    }
    signature = hashlib.sha256(json.dumps(signature_data, sort_keys=True).encode()).hexdigest()
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("signature") != signature:
            raise ValueError("This state directory belongs to a different attack plan.")
    else:
        state = {"signature": signature, "completed": []}
        _write_json(state_path, state)

    hashes_file = node_dir / "targets_sha256.txt"
    hashes_file.write_text("\n".join(target["hash"] for target in targets) + "\n", encoding="ascii")
    found: dict[str, dict[str, str]] = {}
    if results_path.exists():
        prior = json.loads(results_path.read_text(encoding="utf-8"))
        for item in prior.get("found", []):
            try:
                digest = item["hash"]
                plaintext = bytes.fromhex(item["plaintext_hex"])
            except (KeyError, TypeError, ValueError):
                continue
            for target in targets:
                if target["hash"] == digest and hashlib.sha256(plaintext).hexdigest() == digest:
                    found[digest] = _record(target["name"], digest, plaintext)

    def log(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as output:
            output.write(message + "\n")
        print(message, flush=True)

    def save_results() -> None:
        _write_json(results_path, {
            "computer": computer, "total": total,
            "found": list(found.values()),
            "unresolved": [t["name"] for t in targets if t["hash"] not in found],
        })

    def collect_existing_outfiles() -> None:
        if engine != "hashcat":
            return
        for outfile in node_dir.glob(f"hashlab_{signature[:8]}_*.out"):
            for record in parse_recovered(outfile, targets):
                found[record["hash"]] = record

    collect_existing_outfiles()
    save_results()
    log(f"Computador {computer}/{total}: {len(targets)} hashes verificados; motor {engine}; modo SHA-256 crudo provisional.")
    if len(found) == len(targets):
        log("Todos los hashes ya estaban verificados; trabajo terminado.")
        return 0
    try:
        for word_index, wordlist in enumerate(wordlists, 1):
            shard = node_dir / f"wordlist_{word_index:02d}.txt"
            if not shard.exists():
                count = shard_wordlist(wordlist, shard, computer, total)
                log(f"Diccionario {word_index}/{len(wordlists)}: {count} líneas asignadas a este computador.")
            stage_rules = [None] + rules if engine == "hashcat" else [None]
            for rule_index, rule in enumerate(stage_rules):
                stage = f"hashlab_{signature[:8]}_{engine}_c{computer:02d}_w{word_index:02d}_r{rule_index:02d}"
                if stage in state["completed"]:
                    log(f"Etapa {stage}: ya terminada; se omite.")
                    continue
                if stop_flag.exists():
                    log("Detención solicitada antes de iniciar la siguiente etapa.")
                    save_results()
                    return 2
                if engine == "hashcat":
                    command = build_hashcat_command(executable, hashes_file, shard, node_dir, stage, rule)
                    restore = executable.parent / f"{stage}.restore"
                    if restore.exists():
                        command = [str(executable), f"--session={stage}", "--restore"]
                else:
                    command = [
                        str(executable), "--format=Raw-SHA256", f"--wordlist={shard}",
                        f"--pot={node_dir / 'john.pot'}", f"--session={stage}", str(hashes_file),
                    ]
                    restore = executable.parent / f"{stage}.rec"
                    if restore.exists():
                        command = [str(executable), f"--restore={stage}"]
                log(f"Etapa {stage}: inicio ({'reglas' if rule else 'directo'}).")
                stage_log = node_dir / f"{stage}.log"
                with stage_log.open("ab") as output:
                    process = subprocess.Popen(
                        command, cwd=executable.parent, stdin=subprocess.PIPE,
                        stdout=output, stderr=subprocess.STDOUT,
                    )
                    while process.poll() is None:
                        if stop_flag.exists():
                            detail = ("guardando punto de control y deteniendo." if engine == "hashcat"
                                      else "deteniendo; esta etapa puede repetirse.")
                            log(f"Etapa {stage}: {detail}")
                            _stop_process(process, engine)
                            collect_existing_outfiles()
                            save_results()
                            return 2
                        time.sleep(0.5)
                    code = process.returncode
                    if process.stdin is not None:
                        process.stdin.close()
                if engine == "hashcat":
                    recovered = parse_recovered(node_dir / f"{stage}.out", targets)
                else:
                    shown = subprocess.run(
                        [str(executable), "--show", "--format=Raw-SHA256",
                         f"--pot={node_dir / 'john.pot'}", str(hashes_file)],
                        cwd=executable.parent, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                        check=False,
                    )
                    if shown.returncode != 0:
                        log(f"Etapa {stage}: John no pudo mostrar los resultados (código {shown.returncode}).")
                        return 1
                    recovered = parse_john_show(shown.stdout, targets)
                for record in recovered:
                    found[record["hash"]] = record
                    log(f"Hash verificado para {record['name']}; flag guardada en results.json.")
                save_results()
                if code not in ((0, 1) if engine == "hashcat" else (0,)):
                    log(f"Etapa {stage}: {engine} terminó con código {code}; revisar su registro.")
                    return 1
                state["completed"].append(stage)
                _write_json(state_path, state)
                log(f"Etapa {stage}: terminada (código {code}).")
                if len(found) == len(targets):
                    log("Todos los hashes fueron verificados; trabajo terminado.")
                    return 0
        if masks and engine == "hashcat":
            for mask_index, mask in enumerate(DEFAULT_MASKS, 1):
                stage = f"hashlab_{signature[:8]}_hashcat_c{computer:02d}_m{mask_index:02d}"
                if stage in state["completed"]:
                    log(f"Etapa {stage}: ya terminada; se omite.")
                    continue
                if stop_flag.exists():
                    log("Detención solicitada antes de la siguiente máscara.")
                    save_results()
                    return 2
                keyspace = hashcat_keyspace(executable, mask)
                skip, limit = partition_keyspace(keyspace, computer, total)
                if limit == 0:
                    state["completed"].append(stage)
                    _write_json(state_path, state)
                    continue
                command = build_mask_command(executable, hashes_file, node_dir, stage, mask, skip, limit)
                restore = executable.parent / f"{stage}.restore"
                if restore.exists():
                    command = [str(executable), f"--session={stage}", "--restore"]
                log(f"Máscara {mask_index}/{len(DEFAULT_MASKS)}: intervalo {skip}..{skip + limit - 1} de {keyspace}.")
                stage_log = node_dir / f"{stage}.log"
                with stage_log.open("ab") as output:
                    process = subprocess.Popen(
                        command, cwd=executable.parent, stdin=subprocess.PIPE,
                        stdout=output, stderr=subprocess.STDOUT,
                    )
                    while process.poll() is None:
                        if stop_flag.exists():
                            log(f"Etapa {stage}: guardando punto de control y deteniendo.")
                            _stop_process(process, engine)
                            collect_existing_outfiles()
                            save_results()
                            return 2
                        time.sleep(0.5)
                    code = process.returncode
                    if process.stdin is not None:
                        process.stdin.close()
                for record in parse_recovered(node_dir / f"{stage}.out", targets):
                    found[record["hash"]] = record
                    log(f"Hash verificado para {record['name']}; flag guardada en results.json.")
                save_results()
                if code not in (0, 1):
                    log(f"Etapa {stage}: Hashcat terminó con código {code}; revisar su registro.")
                    return 1
                state["completed"].append(stage)
                _write_json(state_path, state)
                if len(found) == len(targets):
                    log("Todos los hashes fueron verificados; trabajo terminado.")
                    return 0
    except KeyboardInterrupt:
        if "process" in locals():
            _stop_process(process, engine)
        collect_existing_outfiles()
        log("Interrumpido; la etapa actual queda pendiente para reanudación.")
        save_results()
        return 2
    log("Plan terminado; consultar results.json para los hashes verificados.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline HashLab computer coordinator")
    sub = parser.add_subparsers(dest="action", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--targets", type=Path, required=True)
    run = sub.add_parser("run")
    run.add_argument("--targets", type=Path, required=True)
    run.add_argument("--computer", type=int, required=True)
    run.add_argument("--total", type=int, default=20)
    run.add_argument("--engine", choices=("hashcat", "john"), default="hashcat")
    run.add_argument("--hashcat", type=Path)
    run.add_argument("--john", type=Path)
    run.add_argument("--wordlist", type=Path, action="append", required=True)
    run.add_argument("--rule", type=Path, action="append", default=[])
    run.add_argument("--state-dir", type=Path, required=True)
    run.add_argument("--masks", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "verify":
            targets = load_targets(args.targets)
            print(json.dumps({"count": len(targets), "targets": targets}, ensure_ascii=False))
            return 0
        return run_plan(
            args.targets, args.computer, args.total,
            args.hashcat if args.engine == "hashcat" else args.john,
            args.wordlist, args.rule, args.state_dir, args.engine, args.masks,
        )
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
