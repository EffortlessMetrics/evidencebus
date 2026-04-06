# evidencebus-path

Path validation and sanitization for evidencebus.

## Purpose

This crate provides functions for validating and sanitizing paths to prevent path traversal attacks and ensure safe path handling. It focuses purely on path operations without any I/O, making it suitable for validation before file operations.

## Key Functions

### `contains_traversal`

Checks if a path contains traversal components (`..`).

```rust
use evidencebus_path::contains_traversal;

assert!(contains_traversal("../safe"));
assert!(contains_traversal("safe/../unsafe"));
assert!(!contains_traversal("safe/relative/path"));
```

### `contains_null_byte`

Checks if a path contains null bytes.

```rust
use evidencebus_path::contains_null_byte;

assert!(contains_null_byte("safe\0path"));
assert!(!contains_null_byte("safe/path"));
```

### `is_absolute_path`

Checks if a path is absolute.

```rust
use evidencebus_path::is_absolute_path;
use std::path::Path;

assert!(is_absolute_path(Path::new("/absolute/path")));
assert!(!is_absolute_path(Path::new("relative/path")));
```

### `validate_path`

Validates that a path is safe (no traversal, no absolute paths, no null bytes).

```rust
use evidencebus_path::validate_path;
use std::path::Path;

assert!(validate_path(Path::new("safe/relative/path")).is_ok());
assert!(validate_path(Path::new("/absolute/path")).is_err());
assert!(validate_path(Path::new("safe/../unsafe")).is_err());
```

### `sanitize_path`

Sanitizes a path string by removing unsafe components.

```rust
use evidencebus_path::sanitize_path;

let safe = sanitize_path("safe/../unsafe/./file.txt");
assert_eq!(safe, "unsafe/file.txt");
```

## Error Types

### `PathError`

- `PathTraversal` - Path contains `..` components
- `AbsolutePath` - Path is absolute (not allowed)
- `InvalidPathComponent` - Path component is invalid
- `OutsideBundle` - Path would escape bundle directory

## Usage Examples

### Validating Packet Paths

```rust
use evidencebus_path::validate_path;
use std::path::Path;

let artifact_path = Path::new("packets/pkt-tool1/artifacts/output.txt");

match validate_path(artifact_path) {
    Ok(_) => println!("Path is safe"),
    Err(e) => println!("Unsafe path: {}", e),
}
```

### Checking for Path Traversal

```rust
use evidencebus_path::contains_traversal;
use std::path::Path;

let user_input = Path::new("../../../etc/passwd");

if contains_traversal(user_input) {
    return Err("Path traversal detected");
}
```

### Sanitizing User Input

```rust
use evidencebus_path::sanitize_path;

let user_path = "safe/../unsafe/./file.txt";
let safe_path = sanitize_path(user_path);
println!("Sanitized: {}", safe_path);
```

### Validating Multiple Paths

```rust
use evidencebus_path::validate_path;
use std::path::Path;

let paths = vec![
    Path::new("artifacts/output.txt"),
    Path::new("logs/stderr.log"),
    Path::new("report.html"),
];

for path in paths {
    validate_path(path)?;
}
```

## Design Principles

- **Security-First** - Prevents path traversal attacks
- **No I/O** - Pure validation, no filesystem operations
- **Explicit** - Clear error messages for validation failures
- **Cross-Platform** - Works consistently across Windows, Linux, macOS

## Path Validation Rules

evidencebus enforces these path rules:

1. **No Traversal** - Paths cannot contain `..` components
2. **Relative Only** - Absolute paths are rejected
3. **No Null Bytes** - Null bytes are rejected
4. **Forward Slashes** - Paths must use forward slashes (even on Windows)
5. **No Leading Slash** - Paths cannot start with `/`

## Security Considerations

This crate helps prevent:

- **Path Traversal Attacks** - Accessing files outside intended directory
- **Directory Escape** - Escaping bundle or packet directories
- **Null Byte Injection** - Bypassing path validation
- **Absolute Path Abuse** - Accessing system files

## Dependencies

- `thiserror` - Error handling

## Testing

The crate includes comprehensive BDD-style tests for:

- Path traversal detection
- Null byte detection
- Absolute path detection
- Path sanitization
- Edge cases and security scenarios

Run tests with:

```bash
cargo test -p evidencebus-path
```

## Related Documentation

- [Architecture Guide](../../docs/architecture.md)
- [API Reference](../../docs/api-reference.md)
- [FAQ - Path Handling](../../docs/faq.md#path-handling)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
