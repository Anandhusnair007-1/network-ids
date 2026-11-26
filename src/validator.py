"""
src/validator.py
================
Strict input validation, schema enforcement, and sanitization for Network IDS telemetry.
Guards against malicious payloads, unexpected schemas, missing columns, and DoS input sizes.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import numpy as np
import pandas as pd

try:
    from config import MAX_UPLOAD_ROWS
except ImportError:  # imported as part of the ``src`` package
    from src.config import MAX_UPLOAD_ROWS

log = logging.getLogger(__name__)


class ValidationError(ValueError):
    """Base exception for input telemetry validation failures."""


class MissingFeatureError(ValidationError):
    """Raised when input lacks required feature columns."""


class InvalidDataTypeError(ValidationError):
    """Raised when feature columns contain non-numeric or non-coercible data."""


class OversizedInputError(ValidationError):
    """Raised when input volume exceeds resource exhaustion safety limits."""


class InputValidator:
    """
    Validates and sanitizes network flow telemetry against the canonical feature schema.

    Parameters
    ----------
    feature_cols : Sequence[str]
        The exact ordered list of expected numerical features.
    max_rows : int
        Maximum permissible rows in a single batch (guards against DoS).
    allow_extra_columns : bool
        If True, silently ignores or separates extra metadata columns (e.g. 'Label', 'Timestamp').
        If False, rejects dataframes with unexpected extraneous columns.
    fill_missing : bool
        If True, missing features are imputed with 0.0.
        If False, missing features trigger a MissingFeatureError.
    """

    def __init__(
        self,
        feature_cols: Sequence[str],
        max_rows: int = MAX_UPLOAD_ROWS,
        allow_extra_columns: bool = True,
        fill_missing: bool = False,
    ) -> None:
        if not feature_cols:
            raise ValueError("Validator must be initialized with at least one expected feature column.")
        self.feature_cols = list(feature_cols)
        self.expected_set = set(self.feature_cols)
        self.max_rows = max_rows
        self.allow_extra_columns = allow_extra_columns
        self.fill_missing = fill_missing

    def validate_df(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Validate and sanitize a telemetry DataFrame.

        Returns
        -------
        pd.DataFrame
            Sanitized DataFrame containing all canonical features in exact order,
            with non-numeric, infinite, and NaN values appropriately sanitized.
        """
        if not isinstance(df, pd.DataFrame):
            raise ValidationError(f"Expected pandas DataFrame, received {type(df).__name__}")

        # Check maximum row limits to protect against memory exhaustion DoS
        if len(df) > self.max_rows:
            raise OversizedInputError(
                f"Input batch size of {len(df):,} flows exceeds safety threshold of {self.max_rows:,} rows."
            )

        if df.empty:
            # Return empty frame with canonical schema
            return pd.DataFrame(columns=self.feature_cols, dtype=np.float32)

        # Normalize column header whitespace
        df_clean = df.copy()
        df_clean.columns = df_clean.columns.astype(str).str.strip()
        present_set = set(df_clean.columns)

        # Check missing features
        missing = [c for c in self.feature_cols if c not in present_set]
        if missing:
            if not self.fill_missing:
                preview = missing[:5]
                suffix = "..." if len(missing) > 5 else ""
                raise MissingFeatureError(
                    f"Input telemetry missing {len(missing)} required features: {preview}{suffix}"
                )
            log.warning("Imputing %d missing feature columns with 0.0", len(missing))
            for col in missing:
                df_clean[col] = 0.0

        # Check extra columns if disallowed
        if not self.allow_extra_columns:
            extra = present_set - self.expected_set
            if extra:
                raise ValidationError(f"Disallowed extra columns in input telemetry: {sorted(extra)[:5]}")

        # Extract only canonical feature columns in exact order
        features_df = df_clean[self.feature_cols].copy()

        # Enforce numeric conversion and check for illegal non-numeric types
        for col in self.feature_cols:
            if not pd.api.types.is_numeric_dtype(features_df[col]):
                try:
                    features_df[col] = pd.to_numeric(features_df[col], errors="coerce")
                except Exception as e:
                    raise InvalidDataTypeError(f"Failed to coerce column '{col}' to numeric: {e}") from e

        # Handle Infinities and NaNs
        # Replace inf and -inf with NaN, then impute NaNs with 0.0
        features_df = features_df.replace([np.inf, -np.inf], np.nan)
        nan_count = int(features_df.isna().sum().sum())
        if nan_count > 0:
            log.debug("Sanitizing %d NaN/Infinite cells in telemetry input to 0.0", nan_count)
            features_df = features_df.fillna(0.0)

        # Cast to float32
        features_df = features_df.astype(np.float32)

        return features_df

    def validate_array(self, X: np.ndarray) -> np.ndarray:
        """
        Validate and sanitize a raw 2D numpy array.
        """
        if not isinstance(X, np.ndarray):
            raise ValidationError(f"Expected numpy ndarray, received {type(X).__name__}")

        if X.ndim != 2:
            raise ValidationError(f"Expected 2D array of shape (samples, features), received shape {X.shape}")

        if X.shape[0] > self.max_rows:
            raise OversizedInputError(
                f"Input batch size of {X.shape[0]:,} flows exceeds safety threshold of {self.max_rows:,} rows."
            )

        if X.shape[1] != len(self.feature_cols):
            raise MissingFeatureError(
                f"Feature dimension mismatch: expected {len(self.feature_cols)} features, received {X.shape[1]}"
            )

        # Check for infinities/NaNs
        if not np.issubdtype(X.dtype, np.number):
            raise InvalidDataTypeError(f"Array dtype must be numeric, received {X.dtype}")

        X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
        return X_clean
