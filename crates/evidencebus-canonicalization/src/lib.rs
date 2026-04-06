//! Deterministic JSON canonicalization for evidencebus.
//!
//! This crate provides functions for canonicalizing JSON values to ensure
//! deterministic serialization. Canonicalization ensures that semantically
//! equivalent JSON values always produce the same byte representation,
//! regardless of original key ordering or whitespace.
//!
//! Per ADR-0005, canonicalization is essential for reproducible digest computation
//! and consistent evidence validation.

use serde::Serialize;
use thiserror::Error;

/// Error type for canonicalization operations.
#[derive(Debug, Error, PartialEq)]
pub enum CanonicalizationError {
    #[error("JSON serialization failed: {0}")]
    SerializationFailed(String),
}

/// Canonicalizes a value to deterministic JSON.
///
/// This function ensures that:
/// - Object keys are sorted in lexicographic order
/// - No extraneous whitespace is included
/// - The output is compact (no pretty-printing)
///
/// # Arguments
/// * `value` - A reference to a value that can be serialized
///
/// # Returns
/// A canonical JSON string representation
///
/// # Errors
/// Returns a `CanonicalizationError` if serialization fails.
///
/// # Examples
/// ```
/// use evidencebus_canonicalization::canonicalize_json;
/// use serde_json::json;
///
/// let data = json!({
///     "z": 1,
///     "a": 2,
///     "m": 3
/// });
///
/// let result = canonicalize_json(&data).unwrap();
/// // Keys should be sorted: "a", "m", "z"
/// assert_eq!(result, r#"{"a":2,"m":3,"z":1}"#);
/// ```
pub fn canonicalize_json<T: Serialize>(value: &T) -> Result<String, CanonicalizationError> {
    let mut json_value = serde_json::to_value(value).map_err(|e| {
        CanonicalizationError::SerializationFailed(format!("failed to serialize to JSON: {}", e))
    })?;

    // Sort object keys deterministically
    sort_json_keys(&mut json_value);

    serde_json::to_string(&json_value).map_err(|e| {
        CanonicalizationError::SerializationFailed(format!(
            "failed to serialize canonical JSON: {}",
            e
        ))
    })
}

/// Recursively sorts keys in JSON objects.
///
/// This function traverses the JSON value and sorts all object keys
/// in lexicographic order, both at the top level and in nested structures.
/// Arrays are traversed recursively to sort any objects they contain.
///
/// # Arguments
/// * `value` - A mutable reference to a JSON value
fn sort_json_keys(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = value {
        // Collect keys, sort them, and rebuild the map
        let mut sorted_keys: Vec<_> = map.keys().cloned().collect();
        sorted_keys.sort();

        let mut sorted_map = serde_json::Map::new();
        for key in sorted_keys {
            if let Some(mut val) = map.remove(&key) {
                sort_json_keys(&mut val);
                sorted_map.insert(key, val);
            }
        }

        *value = serde_json::Value::Object(sorted_map);
    } else if let serde_json::Value::Array(arr) = value {
        for item in arr {
            sort_json_keys(item);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::approx_constant)]
mod tests {
    use super::*;
    use serde_json::json;

    // BDD-style tests for canonicalization

    mod simple_object_canonicalization {
        use super::*;

        #[test]
        fn given_simple_object_with_unsorted_keys_when_canonicalized_then_keys_are_sorted() {
            // Given: A simple object with unsorted keys
            let data = json!({
                "zebra": 1,
                "apple": 2,
                "middle": 3
            });

            // When: The object is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Keys should be sorted in lexicographic order
            assert_eq!(result, r#"{"apple":2,"middle":3,"zebra":1}"#);
        }

        #[test]
        fn given_simple_object_with_sorted_keys_when_canonicalized_then_output_is_compact() {
            // Given: A simple object with already sorted keys
            let data = json!({
                "a": 1,
                "b": 2,
                "c": 3
            });

            // When: The object is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Output should be compact with no whitespace
            assert_eq!(result, r#"{"a":1,"b":2,"c":3}"#);
        }

        #[test]
        fn given_empty_object_when_canonicalized_then_output_is_empty_object() {
            // Given: An empty object
            let data = json!({});

            // When: The object is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Output should be an empty object
            assert_eq!(result, r#"{}"#);
        }
    }

    mod nested_object_canonicalization {
        use super::*;

        #[test]
        fn given_nested_objects_with_unsorted_keys_when_canonicalized_then_all_keys_are_sorted() {
            // Given: Nested objects with unsorted keys at multiple levels
            let data = json!({
                "outer_z": {
                    "inner_z": 1,
                    "inner_a": 2
                },
                "outer_a": {
                    "inner_z": 3,
                    "inner_a": 4
                }
            });

            // When: The nested object is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: All keys at all levels should be sorted
            assert_eq!(
                result,
                r#"{"outer_a":{"inner_a":4,"inner_z":3},"outer_z":{"inner_a":2,"inner_z":1}}"#
            );
        }

        #[test]
        fn given_deeply_nested_object_when_canonicalized_then_all_levels_are_sorted() {
            // Given: A deeply nested object
            let data = json!({
                "level1_c": {
                    "level2_b": {
                        "level3_z": 1,
                        "level3_a": 2
                    },
                    "level2_a": {
                        "level3_z": 3,
                        "level3_a": 4
                    }
                },
                "level1_a": {}
            });

            // When: The deeply nested object is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: All keys at all levels should be sorted
            assert_eq!(
                result,
                r#"{"level1_a":{},"level1_c":{"level2_a":{"level3_a":4,"level3_z":3},"level2_b":{"level3_a":2,"level3_z":1}}}"#
            );
        }

        #[test]
        fn given_nested_empty_objects_when_canonicalized_then_empty_objects_preserved() {
            // Given: Nested empty objects
            let data = json!({
                "outer": {
                    "inner": {}
                }
            });

            // When: The nested object is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Empty objects should be preserved
            assert_eq!(result, r#"{"outer":{"inner":{}}}"#);
        }
    }

    mod array_canonicalization {
        use super::*;

        #[test]
        fn given_simple_array_when_canonicalized_then_order_is_preserved() {
            // Given: A simple array
            let data = json!([3, 1, 2]);

            // When: The array is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Array order should be preserved (not sorted)
            assert_eq!(result, r#"[3,1,2]"#);
        }

        #[test]
        fn given_array_of_objects_when_canonicalized_then_each_object_keys_are_sorted() {
            // Given: An array of objects with unsorted keys
            let data = json!([
                {"z": 1, "a": 2},
                {"m": 3, "b": 4}
            ]);

            // When: The array is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Each object's keys should be sorted, but array order preserved
            assert_eq!(result, r#"[{"a":2,"z":1},{"b":4,"m":3}]"#);
        }

        #[test]
        fn given_nested_arrays_when_canonicalized_then_all_nested_objects_are_sorted() {
            // Given: Nested arrays containing objects
            let data = json!([
                [
                    {"z": 1, "a": 2}
                ],
                [
                    {"m": 3, "b": 4}
                ]
            ]);

            // When: The nested array is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: All nested objects should have sorted keys
            assert_eq!(result, r#"[[{"a":2,"z":1}],[{"b":4,"m":3}]]"#);
        }

        #[test]
        fn given_empty_array_when_canonicalized_then_output_is_empty_array() {
            // Given: An empty array
            let data = json!([]);

            // When: The array is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Output should be an empty array
            assert_eq!(result, r#"[]"#);
        }

        #[test]
        fn given_array_with_mixed_types_when_canonicalized_then_all_objects_sorted() {
            // Given: An array with mixed types including objects
            let data = json!([
                "string",
                123,
                {"z": 1, "a": 2},
                null,
                true
            ]);

            // When: The array is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Object keys should be sorted
            assert_eq!(result, r#"["string",123,{"a":2,"z":1},null,true]"#);
        }
    }

    mod key_order_independence {
        use super::*;

        #[test]
        fn given_objects_with_different_key_orders_when_canonicalized_then_outputs_are_identical() {
            // Given: Two semantically equivalent objects with different key orders
            let data1 = json!({
                "z": 1,
                "a": 2,
                "m": 3
            });
            let data2 = json!({
                "a": 2,
                "m": 3,
                "z": 1
            });

            // When: Both objects are canonicalized
            let result1 = canonicalize_json(&data1).unwrap();
            let result2 = canonicalize_json(&data2).unwrap();

            // Then: The outputs should be identical
            assert_eq!(result1, result2);
        }

        #[test]
        fn given_nested_objects_with_different_key_orders_when_canonicalized_then_outputs_are_identical(
        ) {
            // Given: Two semantically equivalent nested objects with different key orders
            let data1 = json!({
                "outer_z": {
                    "inner_z": 1,
                    "inner_a": 2
                },
                "outer_a": {
                    "inner_z": 3,
                    "inner_a": 4
                }
            });
            let data2 = json!({
                "outer_a": {
                    "inner_a": 4,
                    "inner_z": 3
                },
                "outer_z": {
                    "inner_a": 2,
                    "inner_z": 1
                }
            });

            // When: Both nested objects are canonicalized
            let result1 = canonicalize_json(&data1).unwrap();
            let result2 = canonicalize_json(&data2).unwrap();

            // Then: The outputs should be identical
            assert_eq!(result1, result2);
        }

        #[test]
        fn given_arrays_of_objects_with_different_key_orders_when_canonicalized_then_outputs_are_identical(
        ) {
            // Given: Two arrays of objects with different key orders
            let data1 = json!([
                {"z": 1, "a": 2},
                {"m": 3, "b": 4}
            ]);
            let data2 = json!([
                {"a": 2, "z": 1},
                {"b": 4, "m": 3}
            ]);

            // When: Both arrays are canonicalized
            let result1 = canonicalize_json(&data1).unwrap();
            let result2 = canonicalize_json(&data2).unwrap();

            // Then: The outputs should be identical
            assert_eq!(result1, result2);
        }
    }

    mod determinism {
        use super::*;

        #[test]
        fn given_same_input_when_canonicalized_multiple_times_then_outputs_are_identical() {
            // Given: The same JSON value
            let data = json!({
                "z": 1,
                "a": 2,
                "m": 3
            });

            // When: The value is canonicalized multiple times
            let result1 = canonicalize_json(&data).unwrap();
            let result2 = canonicalize_json(&data).unwrap();
            let result3 = canonicalize_json(&data).unwrap();

            // Then: All outputs should be identical
            assert_eq!(result1, result2);
            assert_eq!(result2, result3);
        }

        #[test]
        fn given_complex_nested_structure_when_canonicalized_multiple_times_then_outputs_are_identical(
        ) {
            // Given: A complex nested structure
            let data = json!({
                "level1": {
                    "array": [
                        {"z": 1, "a": 2},
                        {"m": 3, "b": 4}
                    ],
                    "object": {
                        "nested": {
                            "deep": {
                                "value": "test"
                            }
                        }
                    }
                }
            });

            // When: The value is canonicalized multiple times
            let result1 = canonicalize_json(&data).unwrap();
            let result2 = canonicalize_json(&data).unwrap();

            // Then: All outputs should be identical
            assert_eq!(result1, result2);
        }

        #[test]
        fn given_large_object_when_canonicalized_multiple_times_then_outputs_are_identical() {
            // Given: A large object with many keys
            let mut data = serde_json::Map::new();
            for i in (0..100).rev() {
                data.insert(format!("key_{}", i), json!(i));
            }
            let data = serde_json::Value::Object(data);

            // When: The value is canonicalized multiple times
            let result1 = canonicalize_json(&data).unwrap();
            let result2 = canonicalize_json(&data).unwrap();

            // Then: All outputs should be identical
            assert_eq!(result1, result2);
        }
    }

    mod error_handling {
        use super::*;

        #[test]
        fn given_non_serializable_value_when_canonicalized_then_returns_error() {
            // Given: A value that cannot be serialized (e.g., a function)
            // This is a bit tricky to test with serde_json, so we'll use
            // a custom type that fails serialization

            struct FailSerialize;

            impl serde::Serialize for FailSerialize {
                fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    use serde::ser::Error;
                    Err(S::Error::custom("always fails"))
                }
            }

            let data = FailSerialize;

            // When: The value is canonicalized
            let result = canonicalize_json(&data);

            // Then: An error should be returned
            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(CanonicalizationError::SerializationFailed(_))
            ));
        }
    }

    mod special_values {
        use super::*;

        #[test]
        fn given_null_value_when_canonicalized_then_output_is_null() {
            // Given: A null value
            let data: serde_json::Value = json!(null);

            // When: The value is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Output should be null
            assert_eq!(result, r#"null"#);
        }

        #[test]
        fn given_boolean_true_when_canonicalized_then_output_is_true() {
            // Given: A boolean true value
            let data = json!(true);

            // When: The value is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Output should be true
            assert_eq!(result, r#"true"#);
        }

        #[test]
        fn given_boolean_false_when_canonicalized_then_output_is_false() {
            // Given: A boolean false value
            let data = json!(false);

            // When: The value is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Output should be false
            assert_eq!(result, r#"false"#);
        }

        #[test]
        fn given_string_value_when_canonicalized_then_output_is_quoted_string() {
            // Given: A string value
            let data = json!("hello world");

            // When: The value is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Output should be a quoted string
            assert_eq!(result, r#""hello world""#);
        }

        #[test]
        fn given_number_value_when_canonicalized_then_output_is_number() {
            // Given: A number value
            let data = json!(42);

            // When: The value is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Output should be the number
            assert_eq!(result, r#"42"#);
        }

        #[test]
        fn given_negative_number_when_canonicalized_then_output_is_negative_number() {
            // Given: A negative number
            let data = json!(-42);

            // When: The value is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Output should be the negative number
            assert_eq!(result, r#"-42"#);
        }

        #[test]
        fn given_float_number_when_canonicalized_then_output_is_float() {
            // Given: A float number
            let data = json!(3.14);

            // When: The value is canonicalized
            let result = canonicalize_json(&data).unwrap();

            // Then: Output should be the float
            assert_eq!(result, r#"3.14"#);
        }
    }
}
