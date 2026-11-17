# HashLab

HashLab is a local password recovery lab for hashes that you own or are explicitly authorized to test. The offline coordinator uses `cluster_core.py`, `launcher_gui.py`, and `START.cmd` to divide work across up to 20 Windows computers.

## Offline bundle

Download the current repository with **Code → Download ZIP**. It includes:

- `private_data/targets.json`, matching `private_data/hashes/*.txt` files, and screenshots;
- `private_data/wordlists/seeds.txt`, RockYou, Xato, and CrackStation's full compressed list;
- portable 64-bit Python, Hashcat, and John the Ripper under `tools/`;
- the application files in this repository.

On each authorized Windows 64-bit computer:

1. Extract the entire ZIP to a writable folder. Running from inside the ZIP will not preserve state.
2. Double-click `START.cmd`. The first launch reconstructs RockYou and the official CrackStation GZIP from included parts. Allow several minutes and at least 6 GB of free space beyond the extracted ZIP. The launcher then uses bundled Python and native Windows controls, with no installation, account, or PowerShell script policy change.
3. Check the three displayed hashes against the supplied challenge files.
4. Select a distinct computer number from 1 to 20. Every computer uses the same ZIP and the same total of 20, even if fewer computers are available.
5. Select Hashcat (GPU), confirm, and start. John (CPU, dictionaries) is an explicit fallback. The GUI prioritizes the four dictionaries and rule passes; short GPU masks can still be enabled from the command line.
6. Keep each computer's `state/node-NN/` folder. On restart, choose the same number and engine to resume its completed stages. You can switch to John on the same computer if Hashcat cannot use the GPU; each engine keeps a separate stage record while sharing verified results. The Stop button requests a Hashcat checkpoint; John retains completed stages but may repeat the current one.

The interface shows the current stage and engine output. Each computer writes SHA-256-verified recoveries to `state/node-NN/results.json`. A flag is calculated as `FLAG{MD5(exact_password_bytes)}` only after the recovered bytes reproduce the supplied SHA-256 digest. Platform acceptance is a separate check.

## How work is divided

Each physical line of each wordlist belongs to exactly one numbered computer (`line_index % 20`). CrackStation's full list has 1,493,677,782 lines, so it contributes about 74.7 million base lines per computer before the two Hashcat rule passes. The initial 487-line message for computer 18 refers only to the small seed list. Repeated words across lists, or rules producing the same candidate, can still duplicate guesses. Sharding the full list can take several minutes per computer and creates an additional file of roughly 750 MB.

The optional GPU mask stages use Hashcat's `--keyspace`, `--skip`, and `--limit` for disjoint intervals. They cover six- to ten-character patterns. Reported but unverified password-length hints are 27 characters for Gorillaz, 26 for Morat, and 29 for Final Copa Sudamericana. The GUI therefore does not run the short masks by default. The 64-character target format alone does not prove SHA-256, so the default algorithm remains an explicit assumption.

Hashcat requires a compatible GPU driver and compute runtime. No package can supply or install a missing system driver on a locked lab computer. The Windows GUI, bundled binaries, and NVIDIA hardware need a smoke test on an actual lab computer before a long run.

## Development

Run `python -m unittest discover -s tests -v` to test the coordinator. `python cluster_core.py verify --targets targets.example.json` validates the public example. The repository includes `private_data/` and `tools/` for an offline Code ZIP; generated `state/` and reconstructed wordlists remain outside Git.

CrackStation's dictionary is [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/), attributed in `private_data/wordlists/SOURCES.txt`. Hashcat is distributed under the MIT license; John the Ripper Jumbo has its own license files; Python includes its license. The offline bundle retains the upstream license and documentation files inside each vendor directory.
