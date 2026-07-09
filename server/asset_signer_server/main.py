"""
Web frontend + API for the signer pipeline.

Serves a static upload page at `/` and a single endpoint, `POST /api/bundle`,
that accepts a set of files, runs them through the existing
`asset_signer.bundle.build_bundle` pipeline, and streams back a zip
containing `manifest.txt`, `manifest.txt.minisig`, and the asset zip(s) --
exactly what `python -m asset_signer bundle` would produce on disk.

The secret key is loaded once at startup from ASSET_SIGNER_SECRET_KEY (default:
../signer/bundle.key). This is a PoC: fine for local/dev use, but see
signer/asset_signer/secretkey.py's security note before deploying anywhere
the key's host isn't fully trusted.

Run:
    ASSET_SIGNER_SECRET_KEY=../signer/bundle.key uvicorn asset_signer_server.main:app --reload
"""

from __future__ import annotations

import io
import os
import tempfile
import zipfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from asset_signer.bundle import build_bundle
from asset_signer.minisign import KeyPair
from asset_signer.secretkey import load_secret

SECRET_KEY_PATH = Path(
    os.environ.get("ASSET_SIGNER_SECRET_KEY", "../signer/bundle.key")
).resolve()
_passphrase_env = os.environ.get("ASSET_SIGNER_PASSPHRASE_ENV")
SECRET_KEY_PASSPHRASE = os.environ.get(_passphrase_env) if _passphrase_env else None

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="asset-signer bundle server")

_keypair: KeyPair | None = None


def get_keypair() -> KeyPair:
    global _keypair
    if _keypair is None:
        if not SECRET_KEY_PATH.exists():
            raise HTTPException(
                500,
                f"secret key not found at {SECRET_KEY_PATH}; "
                "set ASSET_SIGNER_SECRET_KEY to a valid `asset_signer keygen` output",
            )
        _keypair = load_secret(SECRET_KEY_PATH, SECRET_KEY_PASSPHRASE)
    return _keypair


@app.post("/api/bundle")
async def create_bundle(files: list[UploadFile] = File(...)) -> StreamingResponse:
    if not files:
        raise HTTPException(400, "no files uploaded")

    kp = get_keypair()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        asset_root = tmp_path / "assets"
        upload_dir = asset_root / "upload"
        upload_dir.mkdir(parents=True)
        out_dir = tmp_path / "out"

        for f in files:
            name = Path(f.filename or "").name
            if not name:
                continue
            data = await f.read()
            (upload_dir / name).write_bytes(data)

        if not any(upload_dir.iterdir()):
            raise HTTPException(400, "no valid filenames in upload")

        result = build_bundle(asset_root, out_dir, kp)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in [result["manifest"], result["signature"], *result["assets"]]:
                zf.write(out_dir / name, arcname=name)
        buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=signed-bundle.zip"},
    )


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
