"""
Secret key storage for the signer.

For this proof of concept we store the Ed25519 seed in a small JSON file,
optionally encrypted with a passphrase via libsodium's secretbox (XSalsa20-
Poly1305) with an scrypt-derived key. This is intentionally simpler than the
reference minisign .key format -- the goal is a self-contained server
pipeline, not interop of the *secret* key (the public key and signatures are
fully interoperable, which is what matters for verification).

SECURITY NOTE (PoC): in real deployments the secret key should live in a
secrets manager / HSM / offline signing box, never beside the assets. This
file format is fine for a PoC and for CI secrets injected at runtime.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

import nacl.pwhash
import nacl.secret
import nacl.utils
from nacl.signing import SigningKey

from .minisign import KeyPair


@dataclass
class StoredKey:
    version: int
    key_id_b64: str
    encrypted: bool
    # if encrypted: salt + nonce + ciphertext (all b64). else: seed_b64
    payload: dict

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": self.version,
                "key_id": self.key_id_b64,
                "encrypted": self.encrypted,
                "payload": self.payload,
            },
            indent=2,
        )


def save_secret(kp: KeyPair, path: Path, passphrase: str | None = None) -> None:
    seed = bytes(kp.signing_key)  # 32-byte Ed25519 seed
    key_id_b64 = base64.b64encode(kp.key_id).decode()

    if passphrase:
        salt = nacl.utils.random(nacl.pwhash.scrypt.SALTBYTES)
        derived = nacl.pwhash.scrypt.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            salt,
            opslimit=nacl.pwhash.scrypt.OPSLIMIT_INTERACTIVE,
            memlimit=nacl.pwhash.scrypt.MEMLIMIT_INTERACTIVE,
        )
        box = nacl.secret.SecretBox(derived)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        ct = box.encrypt(seed, nonce).ciphertext
        payload = {
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        }
        stored = StoredKey(1, key_id_b64, True, payload)
    else:
        payload = {"seed": base64.b64encode(seed).decode()}
        stored = StoredKey(1, key_id_b64, False, payload)

    path.write_text(stored.to_json())
    path.chmod(0o600)


def load_secret(path: Path, passphrase: str | None = None) -> KeyPair:
    data = json.loads(path.read_text())
    key_id = base64.b64decode(data["key_id"])

    if data["encrypted"]:
        if not passphrase:
            raise ValueError("secret key is encrypted; passphrase required")
        p = data["payload"]
        salt = base64.b64decode(p["salt"])
        nonce = base64.b64decode(p["nonce"])
        ct = base64.b64decode(p["ciphertext"])
        derived = nacl.pwhash.scrypt.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            salt,
            opslimit=nacl.pwhash.scrypt.OPSLIMIT_INTERACTIVE,
            memlimit=nacl.pwhash.scrypt.MEMLIMIT_INTERACTIVE,
        )
        box = nacl.secret.SecretBox(derived)
        seed = box.decrypt(nonce + ct)
    else:
        seed = base64.b64decode(data["payload"]["seed"])

    sk = SigningKey(seed)
    return KeyPair(key_id=key_id, signing_key=sk, verify_key=sk.verify_key)
