"""
Bundle pipeline: turn a directory of assets into a signed, verifiable bundle.

Output layout (everything the client needs):

    <out>/
      <asset1>.zip
      <asset2>.zip
      ...
      manifest.txt          # "sha256  filename" lines, sorted
      manifest.txt.minisig  # minisign signature over manifest.txt

The client verifies manifest.txt.minisig against the embedded public key,
then checks each asset's SHA-256 against manifest.txt. The manifest format
is deliberately `sha256sum`-compatible so users can cross-check with
coreutils independently of our tool.
"""

from __future__ import annotations

import hashlib
import time
import zipfile
from pathlib import Path

from .minisign import KeyPair, sign

MANIFEST_NAME = "manifest.txt"
SIG_NAME = "manifest.txt.minisig"


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def zip_dir(src_dir: Path, dest_zip: Path) -> None:
    """Zip a directory's contents deterministically (sorted, fixed mtime)."""
    files = sorted(p for p in src_dir.rglob("*") if p.is_file())
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in files:
            arcname = p.relative_to(src_dir).as_posix()
            zi = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, p.read_bytes())


def build_manifest(bundle_dir: Path) -> str:
    lines = []
    for p in sorted(bundle_dir.glob("*.zip")):
        lines.append(f"{sha256_file(p)}  {p.name}")
    return "\n".join(lines) + "\n"


def build_bundle(
    asset_dir: Path,
    out_dir: Path,
    kp: KeyPair,
    zip_each_subdir: bool = True,
) -> dict:
    """Build a signed bundle from `asset_dir` into `out_dir`.

    If `zip_each_subdir`, each immediate subdirectory of asset_dir becomes one
    <name>.zip. Any loose .zip files already in asset_dir are copied through.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Produce the zips.
    if zip_each_subdir:
        for sub in sorted(p for p in asset_dir.iterdir() if p.is_dir()):
            zip_dir(sub, out_dir / f"{sub.name}.zip")
    for existing in sorted(asset_dir.glob("*.zip")):
        (out_dir / existing.name).write_bytes(existing.read_bytes())

    # 2. Manifest.
    manifest = build_manifest(out_dir)
    (out_dir / MANIFEST_NAME).write_text(manifest)

    # 3. Sign the manifest. Trusted comment carries a timestamp + filename,
    #    matching reference minisign convention.
    trusted = f"timestamp:{int(time.time())}\tfile:{MANIFEST_NAME}"
    sig = sign(kp, manifest.encode("utf-8"), trusted_comment=trusted)
    (out_dir / SIG_NAME).write_text(sig)

    zips = sorted(str(p.name) for p in out_dir.glob("*.zip"))
    return {"assets": zips, "manifest": MANIFEST_NAME, "signature": SIG_NAME}
