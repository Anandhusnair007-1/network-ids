"""
tests/test_security_and_validation.py
======================================
Automated security and validation test suite for Network IDS platform.
Verifies artifact integrity, tamper prevention, schema enforcement,
malicious input rejection, and DoS input size limits.
"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

# Ensure src/ is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ManifestError,
    compute_file_sha256,
    safe_load_pickle,
    verify_artifact_integrity,
)
from validator import (
    InputValidator,
    InvalidDataTypeError,
    MissingFeatureError,
    OversizedInputError,
    ValidationError,
)
from hybrid import HybridDetector


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def canonical_features() -> list[str]:
    return [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
    ]


@pytest.fixture()
def sample_valid_df(canonical_features) -> pd.DataFrame:
    np.random.seed(42)
    data = np.random.rand(10, len(canonical_features)).astype(np.float32)
    return pd.DataFrame(data, columns=canonical_features)


# ── Security & Integrity Verification Tests ───────────────────────────────────

class TestArtifactIntegrity:

    def test_compute_file_sha256_deterministic(self, tmp_path):
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"NetworkIDS-Integrity-Payload")
        # Precomputed sha256 of "NetworkIDS-Integrity-Payload"
        digest1 = compute_file_sha256(test_file)
        digest2 = compute_file_sha256(test_file)
        assert digest1 == digest2
        assert len(digest1) == 64

    def test_tampered_artifact_raises_integrity_error(self, tmp_path):
        artifact = tmp_path / "model.pkl"
        payload = {"model_name": "genuine_rf"}
        artifact.write_bytes(pickle.dumps(payload))
        genuine_hash = compute_file_sha256(artifact)

        # Tamper with 1 byte of the file
        tampered_bytes = bytearray(artifact.read_bytes())
        tampered_bytes[0] ^= 0xFF
        artifact.write_bytes(tampered_bytes)

        with pytest.raises(ArtifactIntegrityError) as exc_info:
            verify_artifact_integrity(artifact, expected_sha256=genuine_hash)
        assert "Cryptographic integrity verification FAILED" in str(exc_info.value)

    def test_safe_load_pickle_blocks_deserialization_on_tamper(self, tmp_path):
        """Verify that tampered artifacts are NEVER unpickled."""
        artifact = tmp_path / "model.pkl"
        artifact.write_bytes(pickle.dumps({"status": "authentic"}))
        genuine_hash = compute_file_sha256(artifact)

        # Create manifest
        manifest_path = tmp_path / "manifest.json"
        manifest_data = {
            "version": "1.0.0",
            "artifacts": {
                "model.pkl": {"sha256": genuine_hash, "size_bytes": len(artifact.read_bytes())}
            }
        }
        manifest_path.write_text(json.dumps(manifest_data))

        # Tamper with file
        artifact.write_bytes(b"malicious_tampered_pickle_data")

        with pytest.raises(ArtifactIntegrityError):
            safe_load_pickle(artifact, manifest_path=manifest_path, verify_integrity=True)

    def test_safe_load_pickle_success_on_authentic(self, tmp_path):
        artifact = tmp_path / "authentic_model.pkl"
        expected_obj = {"accuracy": 0.99, "version": "1.0"}
        artifact.write_bytes(pickle.dumps(expected_obj))
        genuine_hash = compute_file_sha256(artifact)

        manifest_path = tmp_path / "manifest.json"
        manifest_data = {
            "version": "1.0.0",
            "artifacts": {
                "authentic_model.pkl": {"sha256": genuine_hash}
            }
        }
        manifest_path.write_text(json.dumps(manifest_data))

        loaded = safe_load_pickle(artifact, manifest_path=manifest_path, verify_integrity=True)
        assert loaded == expected_obj

    def test_unregistered_artifact_raises_error(self, tmp_path):
        artifact = tmp_path / "unknown.pkl"
        artifact.write_bytes(b"data")
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps({"version": "1.0", "artifacts": {}}))

        with pytest.raises(ArtifactIntegrityError) as exc_info:
            verify_artifact_integrity(artifact, manifest_path=manifest_path)
        assert "is not registered in integrity manifest" in str(exc_info.value)

    def test_missing_artifact_raises_not_found(self, tmp_path):
        missing = tmp_path / "does_not_exist.pkl"
        with pytest.raises(ArtifactNotFoundError):
            compute_file_sha256(missing)

    def test_malformed_manifest_raises_manifest_error(self, tmp_path):
        bad_manifest = tmp_path / "bad_manifest.json"
        bad_manifest.write_text("{invalid_json:")
        dummy_file = tmp_path / "dummy.pkl"
        dummy_file.write_bytes(b"dummy")

        with pytest.raises(ManifestError):
            verify_artifact_integrity(dummy_file, manifest_path=bad_manifest)


# ── Input Validation & DoS Protection Tests ───────────────────────────────────

class TestInputValidation:

    def test_valid_dataframe_passes(self, canonical_features, sample_valid_df):
        validator = InputValidator(canonical_features, max_rows=100)
        clean_df = validator.validate_df(sample_valid_df)

        assert clean_df.shape == (10, len(canonical_features))
        assert list(clean_df.columns) == canonical_features
        assert clean_df.dtypes.iloc[0] == np.float32

    def test_missing_features_raises_error(self, canonical_features, sample_valid_df):
        validator = InputValidator(canonical_features)
        # Drop one required column
        incomplete_df = sample_valid_df.drop(columns=[canonical_features[0]])

        with pytest.raises(MissingFeatureError) as exc_info:
            validator.validate_df(incomplete_df)
        assert canonical_features[0] in str(exc_info.value)

    def test_fill_missing_imputes_zeros(self, canonical_features, sample_valid_df):
        validator = InputValidator(canonical_features, fill_missing=True)
        incomplete_df = sample_valid_df.drop(columns=[canonical_features[0]])

        clean_df = validator.validate_df(incomplete_df)
        assert canonical_features[0] in clean_df.columns
        assert (clean_df[canonical_features[0]] == 0.0).all()

    def test_extra_features_handled_safely(self, canonical_features, sample_valid_df):
        validator = InputValidator(canonical_features, allow_extra_columns=True)
        extended_df = sample_valid_df.copy()
        extended_df["Timestamp"] = "2026-10-20 12:00:00"
        extended_df["Source IP"] = "192.168.1.100"
        extended_df["Label"] = "BENIGN"

        clean_df = validator.validate_df(extended_df)
        # Verify only canonical features remain in clean output
        assert list(clean_df.columns) == canonical_features

    def test_disallowed_extra_features_raises_error(self, canonical_features, sample_valid_df):
        validator = InputValidator(canonical_features, allow_extra_columns=False)
        extended_df = sample_valid_df.copy()
        extended_df["Unexpected_Col"] = 999

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_df(extended_df)
        assert "Disallowed extra columns" in str(exc_info.value)

    def test_nan_and_inf_sanitization(self, canonical_features, sample_valid_df):
        validator = InputValidator(canonical_features)
        corrupted_df = sample_valid_df.copy()
        corrupted_df.loc[0, canonical_features[0]] = np.inf
        corrupted_df.loc[1, canonical_features[1]] = -np.inf
        corrupted_df.loc[2, canonical_features[2]] = np.nan

        clean_df = validator.validate_df(corrupted_df)
        assert not np.isnan(clean_df.to_numpy()).any()
        assert not np.isinf(clean_df.to_numpy()).any()
        assert clean_df.loc[0, canonical_features[0]] == 0.0
        assert clean_df.loc[1, canonical_features[1]] == 0.0
        assert clean_df.loc[2, canonical_features[2]] == 0.0

    def test_invalid_datatype_raises_error(self, canonical_features, sample_valid_df):
        validator = InputValidator(canonical_features)
        corrupted_df = sample_valid_df.copy()
        # Insert illegal non-convertible text
        corrupted_df[canonical_features[0]] = ["malicious_string_not_numeric"] * len(sample_valid_df)

        clean_df = validator.validate_df(corrupted_df)
        # Non-coercible text is cleanly converted to NaN and sanitized to 0.0 without crash
        assert clean_df.dtypes.iloc[0] == np.float32

    def test_oversized_input_raises_error(self, canonical_features):
        validator = InputValidator(canonical_features, max_rows=5)
        oversized_df = pd.DataFrame(
            np.zeros((10, len(canonical_features))),
            columns=canonical_features,
        )

        with pytest.raises(OversizedInputError) as exc_info:
            validator.validate_df(oversized_df)
        assert "exceeds safety threshold" in str(exc_info.value)

    def test_empty_dataframe_returns_clean_schema(self, canonical_features):
        validator = InputValidator(canonical_features)
        empty_df = pd.DataFrame()
        clean_df = validator.validate_df(empty_df)
        assert clean_df.empty
        assert list(clean_df.columns) == canonical_features

    def test_non_dataframe_raises_validation_error(self, canonical_features):
        validator = InputValidator(canonical_features)
        with pytest.raises(ValidationError):
            validator.validate_df({"not": "a dataframe"})

    def test_validate_array(self, canonical_features):
        validator = InputValidator(canonical_features, max_rows=50)
        X_raw = np.array([
            [1.0, 2.0, np.nan, 4.0, np.inf],
            [5.0, -np.inf, 7.0, 8.0, 9.0],
        ])
        X_clean = validator.validate_array(X_raw)
        assert X_clean.shape == (2, len(canonical_features))
        assert not np.isnan(X_clean).any()
        assert not np.isinf(X_clean).any()
        assert X_clean.dtype == np.float32


# ── Hybrid Integration with Validation ────────────────────────────────────────

class TestHybridIntegrationValidation:

    def test_predict_df_rejects_missing_features_by_default(self, canonical_features):
        detector = HybridDetector(
            rf_model=None,
            iforest_model=None,
            scaler=None,
            label_map={0: "BENIGN"},
            threshold=0.0,
        )
        incomplete_df = pd.DataFrame({"Destination Port": [80, 443]})

        with pytest.raises(MissingFeatureError):
            detector.predict_df(incomplete_df, feature_cols=canonical_features, validate=True)
