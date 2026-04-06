# Contributing to evidencebus

Thank you for your interest in contributing to evidencebus! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please:

- Be respectful and considerate
- Use inclusive language
- Focus on constructive feedback
- Assume good intentions
- Help others learn and grow

If you experience or witness inappropriate behavior, please contact the maintainers.

## Getting Started

### Prerequisites

- **Rust 1.78 or later** - Install from [rustup.rs](https://rustup.rs/)
- **Git** - For version control
- **Just** - For running commands (optional, but recommended)

### Setting Up the Development Environment

1. Fork the repository on GitHub

2. Clone your fork:

```bash
git clone https://github.com/YOUR_USERNAME/evidencebus.git
cd evidencebus
```

3. Add the upstream repository:

```bash
git remote add upstream https://github.com/EffortlessMetrics/evidencebus.git
```

4. Install development dependencies:

```bash
cargo install cargo-edit
cargo install cargo-watch
```

5. Verify your setup:

```bash
cargo test --workspace --all-targets
cargo run -p evidencebus-cli -- --help
```

### Building the Project

Build all crates:

```bash
cargo build --workspace
```

Build with optimizations:

```bash
cargo build --workspace --release
```

Build a specific crate:

```bash
cargo build -p evidencebus-core
```

### Running Tests

Run all tests:

```bash
cargo test --workspace --all-targets
```

Run tests with output:

```bash
cargo test --workspace --all-targets -- --nocapture
```

Run tests for a specific crate:

```bash
cargo test -p evidencebus-core
```

Run tests with filtering:

```bash
cargo test --workspace test_name
```

## Development Workflow

### 1. Create a Branch

Create a new branch for your work:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions or improvements

### 2. Make Your Changes

Follow the [Coding Standards](#coding-standards) and ensure your code is well-tested.

### 3. Test Your Changes

Run the full test suite:

```bash
cargo test --workspace --all-targets
```

Run clippy for linting:

```bash
cargo clippy --workspace -- -D warnings
```

Format your code:

```bash
cargo fmt --all
```

### 4. Commit Your Changes

Write clear, descriptive commit messages:

```
feat: add support for custom export formats

Add a new export format trait that allows users to implement
custom export formats beyond Markdown and SARIF.

- Add ExportFormat trait
- Implement for Markdown and SARIF
- Add tests for custom format support
```

Commit message format:
- Use a type prefix: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Keep the first line under 72 characters
- Use imperative mood ("add" not "added")
- Add a blank line before the body
- Explain **why** and **what**, not just **how**

### 5. Push Your Changes

Push to your fork:

```bash
git push origin feature/your-feature-name
```

### 6. Create a Pull Request

1. Go to the repository on GitHub
2. Click "New Pull Request"
3. Select your branch
4. Fill in the PR template
5. Submit the PR

## Coding Standards

### Rust Guidelines

#### Use `thiserror` for Error Types

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Validation failed: {0}")]
    Validation(String),
}
```

#### Prefer `Result` over `panic!`

```rust
// Good
fn parse_packet(data: &str) -> Result<Packet, ParseError> {
    // ...
}

// Avoid
fn parse_packet(data: &str) -> Packet {
    // ...
    panic!("Invalid packet"); // Don't do this
}
```

#### Use `unwrap` and `expect` Sparingly

```rust
// Good
let value = some_operation()?;

// Acceptable in tests
let value = some_operation().expect("This should never fail");

// Avoid in production code
let value = some_operation().unwrap();
```

#### Use Descriptive Names

```rust
// Good
fn compute_packet_digest(packet: &Packet) -> Result<Digest, DigestError> {
    // ...
}

// Avoid
fn calc(p: &Packet) -> Result<Digest, DigestError> {
    // ...
}
```

#### Document Public APIs

```rust
/// Computes the SHA-256 digest of a file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or does not exist.
///
/// # Examples
///
/// ```rust
/// use evidencebus_digest::compute_digest;
///
/// let digest = compute_digest("path/to/file")?;
/// println!("Digest: {}", digest);
/// ```
pub fn compute_digest(path: impl AsRef<Path>) -> Result<String, DigestError> {
    // ...
}
```

### Workspace Guidelines

#### Keep Crates Focused

Each crate should have a single, well-defined responsibility:

- **evidencebus-codes** - Shared enums and codes only
- **evidencebus-types** - Data structures only
- **evidencebus-digest** - Digest computation only
- **evidencebus-validation** - Validation logic only

#### Minimize Dependencies

Prefer minimal dependencies. When adding a dependency:

1. Check if it's already in the workspace
2. Use workspace dependencies in `Cargo.toml`
3. Prefer well-maintained crates
4. Avoid large, feature-heavy dependencies

#### Use Workspace Dependencies

```toml
[workspace.dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
```

### Lint Rules

The project enforces these lint rules:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
dbg_macro = "deny"
todo = "deny"
```

## Testing

### BDD-Style Tests

We use BDD (Behavior-Driven Development) style tests for observable behaviors:

```rust
#[cfg(test)]
mod bdd_tests {
    use super::*;

    #[test]
    fn given_valid_packet_when_validated_then_succeeds() {
        // Given
        let packet = create_valid_packet();

        // When
        let result = validate_packet(&packet);

        // Then
        assert!(result.is_ok());
    }
}
```

### Test Organization

- Unit tests go in the same file as the code
- Integration tests go in `tests/` directory
- BDD tests use descriptive test names
- Use fixtures for test data

### Running Tests

Run all tests:

```bash
cargo test --workspace --all-targets
```

Run BDD tests only:

```bash
cargo test --workspace bdd
```

Run tests with coverage:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --out Html
```

### Writing Good Tests

1. **Test Behavior, Not Implementation**

```rust
// Good - tests behavior
#[test]
fn test_packet_validation_rejects_invalid_digest() {
    let packet = create_packet_with_invalid_digest();
    assert!(validate_packet(&packet).is_err());
}

// Avoid - tests implementation details
#[test]
fn test_packet_validation_calls_digest_function() {
    // This tests how, not what
}
```

2. **Use Descriptive Test Names**

```rust
// Good
#[test]
fn given_packet_with_missing_field_when_validated_then_returns_error() {
    // ...
}

// Avoid
#[test]
fn test_validation() {
    // ...
}
```

3. **Test Edge Cases**

```rust
#[test]
fn test_empty_packet_id_is_rejected() {
    let result = PacketId::new("");
    assert!(matches!(result, Err(PacketIdError::Empty)));
}

#[test]
fn test_packet_id_with_path_traversal_is_rejected() {
    let result = PacketId::new("../malicious");
    assert!(matches!(result, Err(PacketIdError::InvalidChars)));
}
```

## Documentation

### Code Documentation

- Document all public APIs
- Include examples for complex functions
- Use `///` for documentation comments
- Keep documentation up to date with code changes

### Schema Documentation

When updating schemas:

1. Update the JSON schema files in `schemas/`
2. Update the `docs/schema.md` documentation
3. Add migration notes to `docs/migration-guide.md`
4. Update example packets and bundles

### README Files

Each crate should have a `README.md` explaining:

- Purpose and scope
- Key types and functions
- Usage examples
- Dependencies

### Changelog

Document all changes in `CHANGELOG.md`:

```markdown
## [0.2.0] - 2024-01-15

### Added
- Custom export format support
- New validation rules for packet IDs

### Changed
- Improved error messages for validation failures
- Updated digest computation to use SHA-256

### Fixed
- Fixed path traversal vulnerability in artifact loading
- Fixed digest mismatch in bundle validation
```

## Pull Request Process

### Before Submitting

1. **Ensure tests pass**

```bash
cargo test --workspace --all-targets
```

2. **Run linters**

```bash
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

3. **Update documentation**

- Update relevant documentation files
- Add examples for new features
- Update CHANGELOG.md

4. **Check for breaking changes**

- If you're changing the schema, update `schemas/*.json`
- Document breaking changes in migration guide
- Consider version bumping

### PR Description Template

```markdown
## Description
Brief description of the changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe how you tested your changes.

## Checklist
- [ ] Tests pass
- [ ] Linting passes
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No breaking changes (or documented)
```

### Review Process

1. **Automated Checks**

   - CI/CD runs tests
   - Linting checks pass
   - Formatting checks pass

2. **Code Review**

   - At least one maintainer approval required
   - Address all review comments
   - Keep PRs focused and small

3. **Merge**

   - Squash and merge for clean history
   - Maintainer merges after approval
   - Delete branch after merge

### Getting Feedback

- Be responsive to review comments
- Ask questions if something is unclear
- Suggest improvements
- Learn from the process

## Getting Help

- **Documentation**: Check the [docs/](docs/) directory
- **Issues**: Search existing issues or create a new one
- **Discussions**: Join GitHub Discussions for questions
- **Maintainers**: Contact maintainers for urgent issues

## Recognition

Contributors are recognized in the project's contributor list. Thank you for your contributions!

## License

By contributing to evidencebus, you agree that your contributions will be licensed under the MIT License.
