//! BDD-style tests for the evidencebus-digest crate.
//!
//! These tests follow the Given-When-Then structure to describe behavior
//! in a clear, readable format.

use evidencebus_digest::{compute_sha256, verify_digest, DigestError};

mod digest_computation {
    use super::*;

    #[test]
    fn scenario_compute_digest_of_valid_data() {
        // Given: Valid data to compute digest for
        let data = b"hello world";

        // When: Computing the SHA-256 digest
        let digest = compute_sha256(data);

        // Then: The digest should be a 64-character hex string
        assert_eq!(digest.len(), 64);

        // And: The digest should match the known SHA-256 value
        assert_eq!(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        // And: The digest should contain only hex characters
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn scenario_compute_digest_of_empty_data() {
        // Given: Empty data
        let data = b"";

        // When: Computing the SHA-256 digest
        let digest = compute_sha256(data);

        // Then: The digest should be a 64-character hex string
        assert_eq!(digest.len(), 64);

        // And: The digest should match the known SHA-256 value for empty input
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn scenario_compute_digest_of_binary_data() {
        // Given: Binary data with various byte values
        let data: &[u8] = &[0x00, 0xFF, 0x42, 0x13, 0xAB, 0xCD];

        // When: Computing the SHA-256 digest
        let digest = compute_sha256(data);

        // Then: The digest should be a 64-character hex string
        assert_eq!(digest.len(), 64);

        // And: The digest should be deterministic (same for same input)
        let digest2 = compute_sha256(data);
        assert_eq!(digest, digest2);
    }

    #[test]
    fn scenario_compute_digest_of_large_data() {
        // Given: Large data (1KB)
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();

        // When: Computing the SHA-256 digest
        let digest = compute_sha256(&data);

        // Then: The digest should be a 64-character hex string
        assert_eq!(digest.len(), 64);

        // And: The digest should be deterministic
        let digest2 = compute_sha256(&data);
        assert_eq!(digest, digest2);
    }
}

mod digest_verification {
    use super::*;

    #[test]
    fn scenario_verify_correct_digest() {
        // Given: Data and its correct digest
        let data = b"test data for verification";
        let expected = compute_sha256(data);

        // When: Verifying the digest
        let result = verify_digest(data, &expected);

        // Then: Verification should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn scenario_verify_incorrect_digest() {
        // Given: Data and an incorrect digest
        let data = b"test data for verification";
        let wrong_digest = "0000000000000000000000000000000000000000000000000000000000000000";

        // When: Verifying the digest
        let result = verify_digest(data, wrong_digest);

        // Then: Verification should fail
        assert!(result.is_err());

        // And: The error should be VerificationFailed
        match result {
            Err(DigestError::VerificationFailed { expected, actual }) => {
                assert_eq!(expected, wrong_digest);
                assert_ne!(actual, wrong_digest);
            }
            _ => panic!("Expected VerificationFailed error"),
        }
    }

    #[test]
    fn scenario_verify_digest_with_invalid_length() {
        // Given: Data and a digest with invalid length
        let data = b"test data";
        let short_digest = "abc123";

        // When: Verifying the digest
        let result = verify_digest(data, short_digest);

        // Then: Verification should fail
        assert!(result.is_err());

        // And: The error should be InvalidFormat
        match result {
            Err(DigestError::InvalidFormat(msg)) => {
                assert!(msg.contains("64 characters"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn scenario_verify_digest_with_invalid_hex_characters() {
        // Given: Data and a digest with invalid hex characters
        let data = b"test data";
        let invalid_digest = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";

        // When: Verifying the digest
        let result = verify_digest(data, invalid_digest);

        // Then: Verification should fail
        assert!(result.is_err());

        // And: The error should be InvalidFormat
        match result {
            Err(DigestError::InvalidFormat(msg)) => {
                assert!(msg.contains("invalid hex"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn scenario_verify_digest_of_empty_data() {
        // Given: Empty data and its correct digest
        let data = b"";
        let expected = compute_sha256(data);

        // When: Verifying the digest
        let result = verify_digest(data, &expected);

        // Then: Verification should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn scenario_verify_digest_with_mixed_case() {
        // Given: Data and a digest with mixed case (should still work)
        let data = b"test data";
        let expected = compute_sha256(data);
        let mixed_case = expected.to_uppercase();

        // When: Verifying the digest with mixed case
        let result = verify_digest(data, &mixed_case);

        // Then: Verification should fail (hex is case-sensitive)
        assert!(result.is_err());
    }
}

mod determinism {
    use super::*;

    #[test]
    fn scenario_same_input_produces_same_digest_multiple_times() {
        // Given: The same data
        let data = b"determinism test data";

        // When: Computing the digest multiple times
        let digest1 = compute_sha256(data);
        let digest2 = compute_sha256(data);
        let digest3 = compute_sha256(data);

        // Then: All digests should be identical
        assert_eq!(digest1, digest2);
        assert_eq!(digest2, digest3);
    }

    #[test]
    fn scenario_different_inputs_produce_different_digests() {
        // Given: Different data that are similar
        let data1 = b"test data one";
        let data2 = b"test data two";
        let data3 = b"test data one "; // Note trailing space

        // When: Computing digests for each
        let digest1 = compute_sha256(data1);
        let digest2 = compute_sha256(data2);
        let digest3 = compute_sha256(data3);

        // Then: All digests should be different
        assert_ne!(digest1, digest2);
        assert_ne!(digest1, digest3);
        assert_ne!(digest2, digest3);
    }

    #[test]
    fn scenario_single_byte_difference_changes_digest() {
        // Given: Two data sets differing by a single byte
        let data1 = b"hello world";
        let data2 = b"hello worlx"; // Only last byte differs

        // When: Computing digests for each
        let digest1 = compute_sha256(data1);
        let digest2 = compute_sha256(data2);

        // Then: The digests should be completely different (avalanche effect)
        assert_ne!(digest1, digest2);
    }

    #[test]
    fn scenario_digest_is_consistent_across_verification() {
        // Given: Data and its computed digest
        let data = b"consistency test";
        let digest = compute_sha256(data);

        // When: Verifying the digest multiple times
        let result1 = verify_digest(data, &digest);
        let result2 = verify_digest(data, &digest);
        let result3 = verify_digest(data, &digest);

        // Then: All verifications should succeed
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert!(result3.is_ok());
    }
}

mod edge_cases {
    use super::*;

    #[test]
    fn scenario_compute_digest_of_null_bytes() {
        // Given: Data containing null bytes
        let data = b"test\x00data\x00with\x00nulls";

        // When: Computing the digest
        let digest = compute_sha256(data);

        // Then: The digest should be a valid 64-character hex string
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn scenario_compute_digest_of_unicode_data() {
        // Given: Data containing Unicode characters
        let data = "Hello 世界 🌍".as_bytes();

        // When: Computing the digest
        let digest = compute_sha256(data);

        // Then: The digest should be a valid 64-character hex string
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn scenario_verify_digest_with_whitespace_in_digest() {
        // Given: Data and a digest with whitespace
        let data = b"test data";
        let digest_with_space = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 ";

        // When: Verifying the digest with trailing space
        let result = verify_digest(data, digest_with_space);

        // Then: Verification should fail due to invalid format
        assert!(result.is_err());
        match result {
            Err(DigestError::InvalidFormat(_)) => {}
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn scenario_verify_digest_with_very_long_input() {
        // Given: Very large data (10KB)
        let data: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();
        let expected = compute_sha256(&data);

        // When: Verifying the digest
        let result = verify_digest(&data, &expected);

        // Then: Verification should succeed
        assert!(result.is_ok());
    }
}
