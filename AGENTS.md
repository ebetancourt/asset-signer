# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository. Read this
before making changes. It is the source of truth for how the project is laid
out, how to build and test it, and the conventions and traps specific to this
codebase.

## What this project is

`asset-signer` (product name **assetsign**) is a proof of concept for
distributing zipped assets that an end user can verify **offline**, with no
network access at verify time.

- **Signer (Python, `signer/`)** — zips assets, builds a SHA-256 manifest, and
  signs the manifest with an Ed25519 key in the [minisign](https://jedisct1.github.io/minisign/)
  format.
- **Verifier (Rust, `verifier/`)** — a small CLI with the **public key compiled
  in**. It verifies the manifest signature, then checks every asset's hash
  against the manifest. Zero network, zero config, single static binary.

The two sides are connected by the minisign wire format, not by shared code.
Signatures produced by the Python signer verify with the reference `minisign`
tool and the Rust `minisign-verify` crate interchangeably. **That
cross-compatibility is the core invariant of this project — do not break it.**

## Repository layout

```
asset-signer/
├── AGENTS.md                 # you are here
├── CLAUDE.md                 # pointer to this file
├── README.md                 # user-facing usage docs
├── signer/                   # Python: build + sign bundles
│   ├── pyproject.toml
│   ├── asset_signer/
│   │   ├── __init__.py
│   │   ├── minisign.py       # native minisign keygen + signing (PyNaCl)
│   │   ├── secretkey.py      # secret-key storage (optionally passphrase-encrypted)
│   │   ├── bundle.py         # zip assets, build manifest, sign it
│   │   └── __main__.py       # CLI: `keygen`, `bundle`
│   └── tests/
│       └── test_pipeline.py
└── verifier/                 # Rust: offline verify
    ├── Cargo.toml
    └── src/
        └── main.rs           # embedded public key, two-layer verification
```

## Environment & setup

- **Python** ≥ 3.10. The only runtime dependency is `pynacl`; `pytest` for dev.
- **Rust** stable (edition 2021). Crates: `minisign-verify`, `sha2`.

```bash
# Python signer
cd signer
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'          # installs pynacl + pytest, exposes `asset-signer`

# Rust verifier
cd ../verifier
cargo build --release
```

## Build / test / run commands

Run these from the directory noted; commands are independent.

```bash
# --- Python signer (from signer/) ---
PYTHONPATH=. python -m pytest tests/ -q     # test suite
python -m asset_signer keygen --pub bundle.pub --secret bundle.key
python -m asset_signer bundle --assets ./assets --out ./dist --secret bundle.key

# --- Rust verifier (from verifier/) ---
cargo build --release
cargo test                                  # includes the sha256 known-vector test
./target/release/asset-verify /path/to/dist # exit 0 = verified
```

End-to-end smoke test (proves the Python→Rust chain):

1. `keygen`, then paste the printed base64 line into `verifier/src/main.rs` as
   the `PUBLIC_KEY` constant.
2. `bundle` a directory of assets into `./dist`.
3. `cargo build --release` and run the verifier against `./dist` — expect
   `OK: bundle verified`.

## How verification works (trust model)

There is **one** signing key; its public half is baked into the Rust binary.
Verification is two layers, both required:

1. `manifest.txt.minisig` is checked against the embedded public key. Forging
   this requires the secret key.
2. Each `sha256  filename` line in the now-trusted manifest is checked against
   the file on disk. This catches tampered or corrupted assets.

What roots the whole chain is the authenticity of the **Rust binary itself**.
If an attacker can replace the binary (and the embedded key), signing buys
nothing. See README "Trust model" for the full discussion.

## Conventions & invariants (don't break these)

- **Minisign wire compatibility is sacred.** `signer/asset_signer/minisign.py`
  implements the minisign format by hand. Any change to signing must keep output
  verifiable by both the reference `minisign` binary and the Rust
  `minisign-verify` crate. The cross-check tests in `test_pipeline.py` guard
  this — keep them passing.
- **Prehashed mode always.** Signing uses BLAKE2b-512 prehash (`ED` sig alg).
  The verifier calls `public_key.verify(.., .., false)` — the `false` forbids
  legacy non-prehashed signatures. Keep signer and verifier in agreement.
- **Manifest is `sha256sum`-compatible.** Lines are exactly `<64-hex><two
  spaces><filename>`, sorted. This lets users cross-check with coreutils
  (`sha256sum -c`). Preserve the exact two-space separator and sorting.
- **Deterministic zips.** `bundle.zip_dir` fixes mtime to 1980-01-01 and mode to
  0644 so bundles are reproducible. Don't reintroduce nondeterminism.
- **Secret key hygiene.** The secret key is stored via `secretkey.py` (plain or
  scrypt+secretbox encrypted JSON) with `0600` perms. Never write the secret key
  next to the assets, never log it, never commit `*.key`.
- **The `PUBLIC_KEY` constant in `main.rs` is a placeholder.** It won't verify
  real bundles until replaced with a freshly generated key. Don't commit a real
  secret; the public line is safe to commit.

## What this PoC deliberately omits

Key rotation, expiry, and revocation are intentionally out of scope. If asked to
add them, see the "Extending beyond the PoC" section of `README.md` for the
intended approach (dual embedded keys, authenticated `expires:` in the trusted
comment, streaming verification).

## Definition of done for a change

- `PYTHONPATH=. python -m pytest tests/ -q` passes from `signer/`.
- `cargo test` and `cargo build --release` pass from `verifier/`.
- If you touched signing/verifying, run the end-to-end smoke test above.
- No secrets (`*.key`, real assets) added to version control.
