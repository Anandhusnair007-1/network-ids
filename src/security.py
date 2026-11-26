"""
src/security.py
===============
Cryptographic artifact integrity verification and safe deserialization utilities.
Ensures model and artifact tampering is detected BEFORE any deserialization occurs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from config import MANIFEST_PATH, MANIFEST_PUBKEY, VERIFY_INTEGRITY
except ImportError:
    from src.config import MANIFEST_PATH, MANIFEST_PUBKEY, VERIFY_INTEGRITY

log = logging.getLogger(__name__)


class SecurityError(Exception):
    """Base class for all security-related exceptions."""


class ArtifactIntegrityError(SecurityError):
    """Raised when an artifact's cryptographic hash does not match expected manifest."""


class ArtifactNotFoundError(SecurityError):
    """Raised when a required artifact is missing on disk."""


class ManifestError(SecurityError):
    """Raised when the artifact integrity manifest is missing or malformed."""


def compute_file_sha256(file_path: Path, chunk_size: int = 65536) -> str:
    """
    Compute SHA-256 digest of a file using buffered chunk reads to handle large files.
    """
    if not file_path.exists():
        raise ArtifactNotFoundError(f"Artifact not found at: {file_path}")

    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_manifest(manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    """
    Load and parse the cryptographic artifact manifest.
    """
    if not manifest_path.exists():
        raise ManifestError(f"Integrity manifest not found at: {manifest_path}")

    if MANIFEST_PUBKEY:  # signed-manifest mode: refuse an unsigned or re-signed manifest
        try:
            from signing import SignatureError, verify_manifest_signature
        except ImportError:
            from src.signing import SignatureError, verify_manifest_signature
        try:
            verify_manifest_signature(Path(MANIFEST_PUBKEY), manifest_path)
        except SignatureError as exc:
            raise ManifestError(f"Manifest signature check failed: {exc}") from exc

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        raise ManifestError(f"Failed to parse manifest JSON at {manifest_path}: {e}") from e

    if "artifacts" not in manifest or not isinstance(manifest["artifacts"], dict):
        raise ManifestError(f"Malformed manifest: missing 'artifacts' mapping in {manifest_path}")

    return manifest


def verify_artifact_integrity(
    file_path: Path,
    expected_sha256: str | None = None,
    manifest_path: Path = MANIFEST_PATH,
) -> None:
    """
    Verify the cryptographic SHA-256 integrity of an artifact.
    Compares the calculated hash with the manifest or an explicit expected hash.
    Uses hmac.compare_digest for constant-time comparison.
    """
    if not file_path.exists():
        raise ArtifactNotFoundError(f"Artifact does not exist: {file_path}")

    if expected_sha256 is None:
        manifest = load_manifest(manifest_path)
        name = file_path.name
        if name not in manifest["artifacts"]:
            raise ArtifactIntegrityError(
                f"Artifact '{name}' is not registered in integrity manifest {manifest_path}"
            )
        expected_sha256 = manifest["artifacts"][name]["sha256"]

    computed_sha256 = compute_file_sha256(file_path)

    # Constant-time comparison to prevent timing leakages
    if not hmac.compare_digest(computed_sha256.lower(), expected_sha256.lower()):
        log.critical(
            "SECURITY ALERT: Hash mismatch for artifact '%s'! Computed: %s, Expected: %s",
            file_path.name,
            computed_sha256,
            expected_sha256,
        )
        raise ArtifactIntegrityError(
            f"Cryptographic integrity verification FAILED for '{file_path.name}'. "
            f"File may be corrupted or tampered with! "
            f"(Computed: {computed_sha256[:16]}..., Expected: {expected_sha256[:16]}...)"
        )

    log.debug("Artifact integrity verified: %s (SHA-256: %s...)", file_path.name, computed_sha256[:12])


def safe_load_pickle(
    file_path: Path,
    manifest_path: Path = MANIFEST_PATH,
    verify_integrity: bool = VERIFY_INTEGRITY,
) -> Any:
    """
    Securely deserializes a pickle artifact.
    CRITICAL: Hash verification occurs BEFORE pickle.load is invoked.
    If integrity verification fails, the file is never deserialized.
    """
    if not file_path.exists():
        raise ArtifactNotFoundError(f"Artifact not found: {file_path}")

    if verify_integrity:
        verify_artifact_integrity(file_path, manifest_path=manifest_path)

    with open(file_path, "rb") as f:
        return pickle.load(f)  # nosec B301 - hash (and optional signature) verified above


def verify_all_artifacts(
    manifest_path: Path = MANIFEST_PATH,
    base_dir: Path | None = None,
) -> dict[str, str]:
    """
    Verify all artifacts registered in the manifest against disk contents.
    Returns mapping of artifact_name -> verified sha256 hex digest.
    Raises ArtifactIntegrityError or ArtifactNotFoundError on mismatch or missing file.
    """
    manifest = load_manifest(manifest_path)
    if base_dir is None:
        base_dir = manifest_path.parent

    verified = {}
    for name, meta in manifest["artifacts"].items():
        file_path = base_dir / name
        verify_artifact_integrity(file_path, expected_sha256=meta["sha256"], manifest_path=manifest_path)
        verified[name] = meta["sha256"]
    return verified


_ARTIFACT_TYPES = {
    "rf_model.pkl": "RandomForestClassifier",
    "rf_scaler.pkl": "StandardScaler",
    "iforest_model.pkl": "IsolationForest",
    "iforest_threshold.json": "ThresholdConfig",
}


def write_manifest(
    manifest_path: Path = MANIFEST_PATH,
    base_dir: Path | None = None,
    artifact_types: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    (Re)generate the SHA-256 manifest from the artifacts currently on disk.

    Run this deliberately, once, right after training. It records whatever is on disk as
    trusted, so it must never be wired into application start-up.
    """
    base_dir = base_dir or manifest_path.parent
    types = artifact_types or _ARTIFACT_TYPES
    artifacts: dict[str, Any] = {}
    for name, kind in types.items():
        path = base_dir / name
        if not path.exists():
            raise ArtifactNotFoundError(f"Cannot register missing artifact: {path}")
        artifacts[name] = {
            "sha256": compute_file_sha256(path),
            "size_bytes": path.stat().st_size,
            "type": kind,
        }
    manifest = {
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "description": "Cryptographic SHA-256 integrity manifest for Network IDS model artifacts",
        "artifacts": artifacts,
    }
    tmp = manifest_path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    tmp.replace(manifest_path)
    return manifest


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    if "--update" in sys.argv[1:]:
        m = write_manifest()
        print(f"Manifest regenerated at {MANIFEST_PATH} for {len(m['artifacts'])} artifacts "
              f"({m['generated_at']}).")
        sys.exit(0)
    print(f"Checking artifact integrity against manifest: {MANIFEST_PATH}")
    try:
        results = verify_all_artifacts()
        for art_name, sha in results.items():
            print(f"  OK  {art_name:<24} SHA-256: {sha[:16]}... (VERIFIED)")
        print(f"\nAll {len(results)} artifacts passed cryptographic integrity verification.")
    except Exception as exc:
        print(f"\nINTEGRITY CHECK FAILED: {exc}")
        sys.exit(1)
