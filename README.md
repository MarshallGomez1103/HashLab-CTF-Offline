# HashLab

HashLab is a local password recovery lab for hashes that you own or are explicitly authorized to test. The offline coordinator uses `cluster_core.py`, `launcher_gui.py`, and `START.cmd` to divide work across up to 20 Windows computers.

## Offline bundle

Download the complete ZIP from the public repository's **Releases** page. The green **Code → Download ZIP** contains only source code and cannot run offline. The Release ZIP contains:

- `private_data/targets.json`, matching `private_data/hashes/*.txt` files, and screenshots;
- `private_data/wordlists/seeds.txt`, RockYou, and the Xato list;
- portable 64-bit Python, Hashcat, and John the Ripper under `tools/`;
- the application files in this repository.

On each authorized Windows 64-bit computer:

1. Extract the entire ZIP to a writable folder. Running from inside the ZIP will not preserve state.
2. Double-click `START.cmd`. The launcher uses the bundled Python executable and native Windows controls; it needs no installation, account, or PowerShell script policy change.
3. Check the three displayed hashes against the supplied challenge files.
4. Select a distinct computer number from 1 to 20. Every computer uses the same ZIP and the same total of 20, even if fewer computers are available.
5. Select Hashcat (GPU), confirm, and start. John (CPU, dictionaries) is an explicit fallback. It does not run the GPU mask stages.
6. Keep each computer's `state/node-NN/` folder. On restart, choose the same number and engine to resume its completed stages. You can switch to John on the same computer if Hashcat cannot use the GPU; each engine keeps a separate stage record while sharing verified results. The Stop button requests a Hashcat checkpoint; John retains completed stages but may repeat the current one.

The interface shows the current stage and engine output. Each computer writes SHA-256-verified recoveries to `state/node-NN/results.json`. A flag is calculated as `FLAG{MD5(exact_password_bytes)}` only after the recovered bytes reproduce the supplied SHA-256 digest. Platform acceptance is a separate check.

## How work is divided

Each physical line of each wordlist belongs to exactly one numbered computer (`line_index % 20`). Hashcat runs direct dictionary and two rule passes on each computer's assigned lines. Repeated words across lists, or rules producing the same candidate, can still duplicate guesses.

The optional GPU mask stages use Hashcat's `--keyspace`, `--skip`, and `--limit` for disjoint intervals. They include eight digits, four lowercase letters plus four digits, eight lowercase letters, six printable characters, and two eight-letter-plus-two-digit patterns. These are bounded search spaces; they do not cover every possible password. The 64-character target format alone does not prove SHA-256, so the default algorithm remains an explicit assumption.

Hashcat requires a compatible GPU driver and compute runtime. No package can supply or install a missing system driver on a locked lab computer. The Windows GUI, bundled binaries, and NVIDIA hardware need a smoke test on an actual lab computer before a long run.

## Development

Run `python -m unittest discover -s tests -v` to test the coordinator. `python cluster_core.py verify --targets targets.example.json` validates the public example. The public source repository keeps `private_data/`, `tools/`, and `state/` outside Git; the complete Release ZIP includes the first two.

Hashcat is distributed under the MIT license; John the Ripper Jumbo has its own license files; Python includes its license. The offline bundle retains the upstream license and documentation files inside each vendor directory.
