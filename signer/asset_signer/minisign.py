"""
Native minisign implementation (keygen + signing) using PyNaCl.

This produces signatures byte-compatible with the reference `minisign`
tool and the Rust `minisign-verify` crate. We implement the format
directly so the server pipeline has no dependency on an external binary.

Minisign signature file layout (4 lines):

    untrusted comment: <text>
    base64( sig_alg[2] || key_id[8] || signature[64] )
    trusted comment: <text>
    base64( global_signature[64] )

- sig_alg is "ED" (0x45 0x44) for prehashed mode, where the bytes
  actually signed are BLAKE2b-512(message). We always use prehashed:
  it handles any file size and is the modern default.
- The Ed25519 `signature` is over the (prehashed) message bytes.
- The `global_signature` is over: signature[64] || trusted_comment_text
  This is what binds the trusted comment to the signature, so anything
  we put in the trusted comment is authenticated.

Public key file layout (2 lines):

    untrusted comment: <text>
    base64( sig_alg[2] || key_id[8] || public_key[32] )

Secret key file layout (reference minisign) is a scrypt-encrypted blob.
For a PoC we support that format for interop, but by default we store
our own simple JSON secret so the pipeline stays dependency-light.
See secretkey.py for storage; this module only deals with raw key bytes.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from nacl.hashlib import blake2b
from nacl.signing import SigningKey, VerifyKey

# The public key file carries the base algorithm tag "Ed" (0x45 0x64).
# Individual signatures use "Ed" for legacy mode or "ED" (0x45 0x44) for
# prehashed mode. We always sign prehashed, so signatures use "ED" but the
# public key still uses "Ed" -- these are independent.
SIG_ALG_PUBKEY = b"Ed"      # 0x45 0x64  -- goes in the .pub file
SIG_ALG_PREHASHED = b"ED"   # 0x45 0x44  -- goes in the signature (prehashed)
KEY_ID_LEN = 8
BLAKE2B_OUT = 64


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@dataclass
class KeyPair:
    key_id: bytes            # 8 bytes
    signing_key: SigningKey  # 32-byte Ed25519 seed inside
    verify_key: VerifyKey    # 32-byte Ed25519 public key

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = SigningKey.generate()
        key_id = os.urandom(KEY_ID_LEN)
        return cls(key_id=key_id, signing_key=sk, verify_key=sk.verify_key)

    def public_key_b64(self) -> str:
        """The single base64 line that goes in a .pub file / embedded in Rust."""
        blob = SIG_ALG_PUBKEY + self.key_id + bytes(self.verify_key)
        return _b64(blob)

    def public_key_file(self, untrusted_comment: str = "minisign public key") -> str:
        return f"untrusted comment: {untrusted_comment}\n{self.public_key_b64()}\n"


def sign(
    kp: KeyPair,
    message: bytes,
    trusted_comment: str,
    untrusted_comment: str = "signature from asset-signer",
) -> str:
    """Produce a minisign signature file (as a string) over `message`.

    Uses prehashed mode. `trusted_comment` is authenticated via the
    global signature, so callers can put e.g. filenames or timestamps
    there and rely on them at verify time.
    """
    prehash = blake2b(message, digest_size=BLAKE2B_OUT).digest()
    signature = kp.signing_key.sign(prehash).signature  # 64 bytes

    sig_line_blob = SIG_ALG_PREHASHED + kp.key_id + signature
    global_sig = kp.signing_key.sign(
        signature + trusted_comment.encode("utf-8")
    ).signature
    # Note: the reference tool appends "\thashed" to the trusted comment in
    # prehashed mode. We keep the caller's trusted comment verbatim so the
    # exact bytes we authenticate are the exact bytes we write; the crate and
    # binary both verify fine either way. If byte-identical output vs. the
    # reference tool matters to you, append "\thashed" in the caller.

    return (
        f"untrusted comment: {untrusted_comment}\n"
        f"{_b64(sig_line_blob)}\n"
        f"trusted comment: {trusted_comment}\n"
        f"{_b64(global_sig)}\n"
    )
