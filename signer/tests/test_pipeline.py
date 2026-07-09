"""
Tests for the signer pipeline.

The most important test cross-checks our native Python signature against the
reference `minisign` binary when it is available on PATH -- this is what
guarantees the Rust `minisign-verify` crate will accept our output. When the
binary is absent, that test is skipped (the format round-trip within our own
code is still exercised).
"""

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from asset_signer.bundle import build_bundle
from asset_signer.minisign import KeyPair, sign
from asset_signer.secretkey import load_secret, save_secret

HAVE_MINISIGN = shutil.which("minisign") is not None


def test_public_key_line_shape():
    kp = KeyPair.generate()
    line = kp.public_key_b64()
    # base64 of 2 + 8 + 32 = 42 bytes -> 56 base64 chars
    import base64

    raw = base64.b64decode(line)
    assert len(raw) == 42
    assert raw[0:2] == b"Ed"  # pubkey algorithm tag


def test_secret_roundtrip_plain(tmp_path):
    kp = KeyPair.generate()
    p = tmp_path / "k.key"
    save_secret(kp, p)
    kp2 = load_secret(p)
    assert bytes(kp2.signing_key) == bytes(kp.signing_key)
    assert kp2.key_id == kp.key_id


def test_secret_roundtrip_encrypted(tmp_path):
    kp = KeyPair.generate()
    p = tmp_path / "k.key"
    save_secret(kp, p, passphrase="hunter2")
    with pytest.raises(Exception):
        load_secret(p)  # missing passphrase
    kp2 = load_secret(p, passphrase="hunter2")
    assert bytes(kp2.signing_key) == bytes(kp.signing_key)


@pytest.mark.skipif(not HAVE_MINISIGN, reason="reference minisign not installed")
def test_signature_verifies_with_reference_minisign(tmp_path):
    kp = KeyPair.generate()
    (tmp_path / "k.pub").write_text(kp.public_key_file())
    data = b"the payload that will be signed\n"
    (tmp_path / "data.bin").write_bytes(data)
    sig = sign(kp, data, trusted_comment="timestamp:0\tfile:data.bin")
    (tmp_path / "data.bin.minisig").write_text(sig)

    r = subprocess.run(
        ["minisign", "-V", "-p", str(tmp_path / "k.pub"), "-m", str(tmp_path / "data.bin")],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr


def _make_assets(root: Path):
    (root / "textures").mkdir(parents=True)
    (root / "sounds").mkdir(parents=True)
    (root / "textures" / "a.png").write_text("alpha")
    (root / "sounds" / "b.wav").write_text("beep")


def test_build_bundle_and_manifest(tmp_path):
    assets = tmp_path / "assets"
    _make_assets(assets)
    out = tmp_path / "dist"
    kp = KeyPair.generate()
    result = build_bundle(assets, out, kp)

    assert (out / "manifest.txt").exists()
    assert (out / "manifest.txt.minisig").exists()
    assert "textures.zip" in result["assets"]
    assert "sounds.zip" in result["assets"]

    # Manifest hashes match the actual zips.
    for line in (out / "manifest.txt").read_text().splitlines():
        expected, name = line.split("  ", 1)
        got = hashlib.sha256((out / name).read_bytes()).hexdigest()
        assert got == expected


@pytest.mark.skipif(not HAVE_MINISIGN, reason="reference minisign not installed")
def test_tampered_manifest_fails_reference(tmp_path):
    assets = tmp_path / "assets"
    _make_assets(assets)
    out = tmp_path / "dist"
    kp = KeyPair.generate()
    build_bundle(assets, out, kp)
    (tmp_path / "k.pub").write_text(kp.public_key_file())

    # Flip a byte in the manifest.
    m = out / "manifest.txt"
    text = m.read_text()
    m.write_text(text.replace(text[0], "0" if text[0] != "0" else "1", 1))

    r = subprocess.run(
        ["minisign", "-V", "-p", str(tmp_path / "k.pub"), "-m", str(m)],
        capture_output=True,
        text=True,
    )
    assert r.returncode != 0
