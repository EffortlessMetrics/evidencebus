//! Digest computation and verification for evidencebus.
//!
//! This crate provides functions for computing SHA-256 digests and verifying
//! that data matches expected digests. All digest operations are deterministic
//! per ADR-0005.

use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

/// Error type for digest operations.
#[derive(Debug, Error, PartialEq)]
pub enum DigestError {
    #[error("digest verification failed: expected {expected}, got {actual}")]
    VerificationFailed { expected: String, actual: String },
    #[error("invalid digest format: {0}")]
    InvalidFormat(String),
}

/// Computes the SHA-256 digest of the given data.
///
/// # Arguments
/// * `data` - The byte slice to compute the digest for
///
/// # Returns
/// A 64-character hex string representing the SHA-256 digest
///
/// # Examples
/// ```
/// use evidencebus_digest::compute_sha256;
///
/// let digest = compute_sha256(b"hello world");
/// assert_eq!(digest.len(), 64);
/// ```
pub fn compute_sha256(data: &[u8]) -> String {
    let hasher = Sha256::new().chain_update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Verifies that data matches the expected digest.
///
/// # Arguments
/// * `data` - The byte slice to verify
/// * `expected` - The expected 64-character hex digest string
///
/// # Errors
/// Returns a `DigestError` if verification fails or if the expected digest
/// format is invalid.
///
/// # Examples
/// ```
/// use evidencebus_digest::{compute_sha256, verify_digest};
///
/// let data = b"hello world";
/// let expected = compute_sha256(data);
/// assert!(verify_digest(data, &expected).is_ok());
///
/// let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
/// assert!(verify_digest(data, wrong).is_err());
/// ```
pub fn verify_digest(data: &[u8], expected: &str) -> Result<(), DigestError> {
    // Validate expected digest format
    if expected.len() != 64 {
        return Err(DigestError::InvalidFormat(format!(
            "digest must be 64 characters, got {}",
            expected.len()
        )));
    }
    if !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(DigestError::InvalidFormat(
            "digest contains invalid hex characters".to_string(),
        ));
    }

    let computed = compute_sha256(data);
    if computed == expected {
        Ok(())
    } else {
        Err(DigestError::VerificationFailed {
            expected: expected.to_string(),
            actual: computed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256_known_value() {
        // SHA-256 of "hello world" is a known value
        let digest = compute_sha256(b"hello world");
        assert_eq!(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_sha256_empty_data() {
        // SHA-256 of empty input is a known value
        let digest = compute_sha256(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_compute_sha256_deterministic() {
        // Same input should produce same digest
        let data = b"deterministic test data";
        let digest1 = compute_sha256(data);
        let digest2 = compute_sha256(data);
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_compute_sha256_different_inputs() {
        // Different inputs should produce different digests
        let digest1 = compute_sha256(b"input one");
        let digest2 = compute_sha256(b"input two");
        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_verify_digest_correct() {
        let data = b"test data";
        let expected = compute_sha256(data);
        assert!(verify_digest(data, &expected).is_ok());
    }

    #[test]
    fn test_verify_digest_incorrect() {
        let data = b"test data";
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = verify_digest(data, wrong);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(DigestError::VerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_digest_invalid_length() {
        let data = b"test data";
        let short = "abc123";
        let result = verify_digest(data, short);
        assert!(matches!(result, Err(DigestError::InvalidFormat(_))));
    }

    #[test]
    fn test_verify_digest_invalid_hex() {
        let data = b"test data";
        let invalid = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        let result = verify_digest(data, invalid);
        assert!(matches!(result, Err(DigestError::InvalidFormat(_))));
    }

    #[test]
    fn test_verify_digest_empty_data() {
        let data = b"";
        let expected = compute_sha256(data);
        assert!(verify_digest(data, &expected).is_ok());
    }
}
