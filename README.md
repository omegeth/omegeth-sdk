# Omegeth SDK

Read and verify Omegeth's public record from your own service: every claim filed and decided in a world, the directory of registered players, and the office registry that says which keys speak for whom. The record is a set of signed, hash-chained logs served as static files at `https://docs.omegeth.com/log/`. You need no account, no API key and no permission to read it.

Start with the guide: [`docs/BUILDING.md`](docs/BUILDING.md).

## What is here

| Path | What it is |
|---|---|
| [`js/omegeth_contract.js`](js/omegeth_contract.js) | The browser reader. Load it as a script; it defines `OmegethContract`. WebCrypto Ed25519: Chrome 137+, Firefox 129+, Safari 17+, Node 20+ |
| [`python/omegeth_reader.py`](python/omegeth_reader.py) | The Python reader. Python 3.10+ with `cryptography` ([`python/requirements.txt`](python/requirements.txt)) |
| [`examples/`](examples) | Read a world's Claims Office docket and list the claims in force and pending node key changes: a page (`docket.html`), its script (`docket.js`), and the same in Python (`docket.py`) |
| [`vectors/`](vectors) | Test vectors: statements to accept and refuse, proofs of possession, and a small example record (`vectors/log/`) signed with test keys |
| [`docs/BUILDING.md`](docs/BUILDING.md) | The guide: what is available, the record's layout, verifying it, the data, linking players to Omegeth, ground rules |

## Quick start

Python:

```sh
python3 -m pip install -r python/requirements.txt
python3 examples/docket.py
```

A browser: serve the repository and open the example page.

```sh
python3 -m http.server 8000
# then open http://localhost:8000/examples/docket.html
```

To use a reader in your project, copy the file unchanged. Both readers do the same thing in the same way and pass the same vectors.

## Trust

Everything is verified from one pinned value, the corporate root public key:

```text
key ID      7c8106e7b87c3746
public key  tDJlaUGNOXxmggV4zAIZw3yiumN8CwJ9QIgIUGf3I1I=
```

Before pinning it, check that it matches `https://docs.omegeth.com/root.json` and the home page of `https://omegeth.com/`. The examples have it built in. The keys in `vectors/` are test keys; never trust them for real data.

## Checks

```sh
make check
```

This runs the Python tests always, and the JavaScript tests where Node 20+ is installed (GitHub Actions runs both). The tests check the readers against the vectors, run the examples against the example record over HTTP, and check that the readers and vectors are unchanged copies (`contract/VENDORED.json` records their SHA-256).

## Versions

Readers, vectors and record share one format version, currently 4 (`CONTRACT_VERSION` in both readers). Omegeth is a research project: a new game world can bring a new format with no compatibility with the old, and this repository moves to it at the same time. See [`CHANGELOG.md`](CHANGELOG.md).
