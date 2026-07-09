# assetsign — signed, offline-verifiable asset bundles

A proof of concept for distributing zipped assets that an end user can verify
**offline**, with no network access at verify time.

- **Server side (Python):** zips assets, builds a SHA-256 manifest, and signs
  the manifest with an Ed25519 key in the [minisign](https://jedisct1.github.io/minisign/)
  format.
- **Client side (Rust):** a small CLI with the **public key compiled in**. It
  verifies the manifest signature, then checks every asset's hash against the
  manifest. Zero network, zero config, single static binary.

The signature format is real minisign — signatures produced by the Python
signer verify with the reference `minisign` tool and the Rust
`minisign-verify` crate interchangeably.

## Trust model (read this)

There is **one** signing key. Its public half is baked into the Rust binary.

Verification is two layers, and both matter:

1. `manifest.txt.minisig` is checked against the embedded public key. An
   attacker cannot forge this without the secret key.
2. Each `sha256  filename` line in the now-trusted manifest is checked against
   the file on disk. This catches any tampered or corrupted asset.

Tampering with an asset fails layer 2. Tampering with the manifest to cover for
it fails layer 1. Both failure modes are tested.

**What roots the whole chain is the authenticity of the Rust binary itself.**
If an attacker can replace the binary (and the key inside it), signing buys you
nothing. Ship the verifier over a channel you trust: OS package manager, code
signing, or HTTPS you control. Keep the **secret key** off the asset server —
ideally in a secrets manager or an offline signing box.

This is a PoC. It deliberately omits key rotation, expiry, and revocation. See
"Extending" below.

## Layout

```
signer/                 Python: build + sign bundles
  asset_signer/
    minisign.py         native minisign keygen + signing (PyNaCl)
    secretkey.py        secret-key storage (optionally passphrase-encrypted)
    bundle.py           zip assets, build manifest, sign it
    __main__.py         CLI: `keygen`, `bundle`
  tests/
verifier/               Rust: offline verify
  src/main.rs           embedded public key, two-layer verification
  Cargo.toml
```

## Usage

### 1. Generate a keypair (once)

```bash
cd signer
python -m asset_signer keygen --pub bundle.pub --secret bundle.key
# optionally encrypt the secret key at rest:
#   BUNDLE_PW=... python -m asset_signer keygen --secret bundle.key --passphrase-env BUNDLE_PW
```

This prints a base64 line. Paste it into `verifier/src/main.rs` as the
`PUBLIC_KEY` constant.

### 2. Build and sign a bundle

Arrange assets as subdirectories (each becomes one `.zip`), or drop in loose
`.zip` files:

```
assets/
  textures/  ->  textures.zip
  sounds/    ->  sounds.zip
```

```bash
python -m asset_signer bundle --assets ./assets --out ./dist --secret bundle.key
```

`./dist` now contains the zips, `manifest.txt`, and `manifest.txt.minisig`.
Ship that directory to users however you like (CDN, download, USB).

### 3. Verify offline (end user)

```bash
cd verifier
cargo build --release
./target/release/asset-verify /path/to/dist
```

Exit code `0` and `OK: bundle verified` means every asset is authentic. Any
tampering yields a non-zero exit and a specific error.

Because the manifest is `sha256sum`-compatible, a user can also cross-check
independently:

```bash
cd dist && sha256sum -c <(grep -v minisig manifest.txt)   # asset integrity
minisign -Vm manifest.txt -P <your-public-key>            # authenticity
```

## Testing

```bash
cd signer && PYTHONPATH=. python -m pytest tests/ -q
```

The suite cross-checks the native Python signatures against the reference
`minisign` binary when it is installed, which is the guarantee of Rust-side
compatibility.

## Extending beyond the PoC

- **Key rotation:** embed a second ("next") public key and accept either, so
  you can roll to a new key without shipping a new binary on a flag day.
- **Expiry:** put an `expires:` field in the signed trusted comment (it is
  authenticated) and have the verifier reject stale bundles. Note: offline
  expiry can't be enforced against an attacker who controls the machine clock.
- **Streaming:** for very large individual assets, `minisign-verify` supports
  streaming verification so you needn't load a whole file into memory.
- **In-app verification:** drop the CLI and call `minisign-verify` directly
  from your main Rust program with the same embedded-key pattern.
