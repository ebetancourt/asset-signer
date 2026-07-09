"""
Command-line entrypoint for the server-side signer.

Usage:
    python -m asset_signer keygen  --pub bundle.pub --secret bundle.key [--passphrase-env VAR]
    python -m asset_signer bundle  --assets ./assets --out ./dist --secret bundle.key [--passphrase-env VAR]

`keygen` writes a minisign-compatible public key (paste line 2 into the Rust
verifier) and a secret key for signing. `bundle` zips assets, builds the
manifest, and signs it.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .bundle import build_bundle
from .minisign import KeyPair
from .secretkey import load_secret, save_secret


def _passphrase(env_var: str | None) -> str | None:
    if not env_var:
        return None
    val = os.environ.get(env_var)
    if val is None:
        print(f"error: env var {env_var!r} not set", file=sys.stderr)
        sys.exit(2)
    return val


def cmd_keygen(args) -> None:
    kp = KeyPair.generate()
    Path(args.pub).write_text(kp.public_key_file())
    save_secret(kp, Path(args.secret), _passphrase(args.passphrase_env))
    pub_line = kp.public_key_b64()
    print(f"wrote public key -> {args.pub}")
    print(f"wrote secret key -> {args.secret}")
    print()
    print("Embed this line in the Rust verifier (PUBLIC_KEY const):")
    print(f"  {pub_line}")


def cmd_bundle(args) -> None:
    kp = load_secret(Path(args.secret), _passphrase(args.passphrase_env))
    result = build_bundle(Path(args.assets), Path(args.out), kp)
    print(f"bundle written to {args.out}")
    for a in result["assets"]:
        print(f"  asset: {a}")
    print(f"  {result['manifest']}")
    print(f"  {result['signature']}")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="asset_signer")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate a signing keypair")
    g.add_argument("--pub", default="bundle.pub")
    g.add_argument("--secret", default="bundle.key")
    g.add_argument("--passphrase-env", help="env var holding secret-key passphrase")
    g.set_defaults(func=cmd_keygen)

    b = sub.add_parser("bundle", help="build and sign an asset bundle")
    b.add_argument("--assets", required=True, help="directory of assets")
    b.add_argument("--out", required=True, help="output bundle directory")
    b.add_argument("--secret", default="bundle.key")
    b.add_argument("--passphrase-env", help="env var holding secret-key passphrase")
    b.set_defaults(func=cmd_bundle)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
