"""
src/signing.py
==============
Ed25519 signing of ``models/manifest.json``.

The SHA-256 manifest stops accidental corruption, but anyone who can write the models directory can
rewrite the manifest too. Signing closes that gap: keep the **private key offline** (build machine or
HSM), ship only the **public key**, and set ``IDS_MANIFEST_PUBKEY`` on the servers. A tampered model now
also needs the private key to be accepted.

    python src/signing.py keygen keys/          # once; store keys/manifest_private.pem offline
    python src/signing.py sign   keys/manifest_private.pem
    python src/signing.py verify keys/manifest_public.pem
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

try:
    from config import MANIFEST_PATH
except ImportError:  # imported as part of the ``src`` package
    from src.config import MANIFEST_PATH


class SignatureError(Exception):
    """Manifest signature is missing, malformed, or does not verify."""


def sig_path(manifest_path: Path) -> Path:
    return manifest_path.with_suffix(manifest_path.suffix + ".sig")


def generate_keypair(out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    priv, pub = out_dir / "manifest_private.pem", out_dir / "manifest_public.pem"
    priv.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    priv.chmod(0o600)
    pub.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


def sign_manifest(private_key_path: Path, manifest_path: Path = MANIFEST_PATH) -> Path:
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError("Private key is not an Ed25519 key.")
    out = sig_path(manifest_path)
    out.write_bytes(key.sign(manifest_path.read_bytes()))
    return out


def verify_manifest_signature(public_key_path: Path, manifest_path: Path = MANIFEST_PATH) -> None:
    sp = sig_path(manifest_path)
    if not sp.exists():
        raise SignatureError(f"Signature file missing: {sp}")
    try:
        pub = serialization.load_pem_public_key(public_key_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise SignatureError(f"Cannot read public key {public_key_path}: {exc}") from exc
    if not isinstance(pub, Ed25519PublicKey):
        raise SignatureError("Public key is not an Ed25519 key.")
    try:
        pub.verify(sp.read_bytes(), manifest_path.read_bytes())
    except InvalidSignature as exc:
        raise SignatureError("Manifest signature does not match: the manifest was modified or signed by another key.") from exc


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "keygen":
        priv, pub = generate_keypair(Path(argv[1]))
        print(f"Private key (keep offline): {priv}\nPublic key (deploy):       {pub}")
        return 0
    if len(argv) >= 2 and argv[0] == "sign":
        print(f"Signed -> {sign_manifest(Path(argv[1]))}")
        return 0
    if len(argv) >= 2 and argv[0] == "verify":
        verify_manifest_signature(Path(argv[1]))
        print("Manifest signature OK")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except SignatureError as exc:
        print(f"SIGNATURE CHECK FAILED: {exc}")
        sys.exit(1)
