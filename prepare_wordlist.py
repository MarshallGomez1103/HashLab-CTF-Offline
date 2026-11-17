"""Reassemble the official compressed CrackStation list from ZIP-safe parts."""

import hashlib
from pathlib import Path


SIZE = 4500756826
SHA256 = "a6dc17d27d0a34f57c989741acdd485b8aee45a6e9796daf8c9435370dc61612"
PART_SIZE = 90 * 1024 * 1024


def prepare_parts(target: Path, size: int, digest: str, part_size: int) -> None:
    if target.is_file() and target.stat().st_size == size:
        return
    count = (size + part_size - 1) // part_size
    parts = [target.with_name(f"{target.name}.part.{index:03d}") for index in range(count)]
    if any(not part.is_file() for part in parts):
        raise ValueError("Missing one or more compressed wordlist parts.")
    temporary = target.with_name(target.name + ".tmp")
    hasher = hashlib.sha256()
    written = 0
    try:
        with temporary.open("wb") as output:
            for index, part in enumerate(parts):
                expected = min(part_size, size - index * part_size)
                if part.stat().st_size != expected:
                    raise ValueError(f"Invalid wordlist part size: {part.name}")
                with part.open("rb") as source:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
                        hasher.update(chunk)
                        written += len(chunk)
        if written != size or hasher.hexdigest() != digest:
            raise ValueError("The compressed wordlist checksum does not match its source.")
        temporary.replace(target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    try:
        prepare_parts(Path(__file__).resolve().parent / "private_data/wordlists/crackstation.txt.gz",
                      SIZE, SHA256, PART_SIZE)
    except (OSError, ValueError) as error:
        print(f"No se pudo preparar CrackStation: {error}")
        raise SystemExit(1) from error
