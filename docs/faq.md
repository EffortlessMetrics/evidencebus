# Frequently Asked Questions

## General Questions

### What is evidencebus?

evidencebus is a schema-first evidence backplane for repository operations. It takes outputs from tools like `faultline`, `proofrun`, `repropack`, `stackcut`, `perfgate`, and similar tools and transforms them into validated packets, deterministic bundles, and portable artifact inventories.

### What is evidencebus NOT?

evidencebus is deliberately **not** a merge cockpit. It moves evidence; downstream tools like `cockpitctl` decide what that evidence means for merge decisions. It does not implement merge policy, required/optional gate semantics, or review workflow logic.

### Why was evidencebus created?

evidencebus was created to provide a neutral, schema-first way to transport and validate evidence across different tools and workflows. It addresses the need for:

- Standardized evidence formats
- Deterministic, reproducible bundles
- Integrity verification through digests
- Neutral exports for different consumers

### What programming language is evidencebus written in?

evidencebus is written in Rust. This provides memory safety, performance, and strong type guarantees.

## Installation and Setup

### How do I install evidencebus?

You can install evidencebus by building from source:

```bash
git clone https://github.com/EffortlessMetrics/evidencebus.git
cd evidencebus
cargo build --release
```

The binary will be at `target/release/evidencebus`.

### What are the system requirements?

- **Rust 1.78 or later** - Required for building
- **Git** - For cloning the repository
- **~50MB disk space** - For the compiled binary and dependencies

### Can I install evidencebus via cargo?

Once published to crates.io, you'll be able to install directly:

```bash
cargo install evidencebus-cli
```

### Is evidencebus available as a Docker image?

Docker images are planned for future releases. For now, build from source or use the binary.

## Usage

### How do I create a packet?

You can create a packet either programmatically using the `evidencebus-types` crate or by writing a JSON file that conforms to the schema. See [Creating Your First Packet](tutorials/creating-your-first-packet.md) for a detailed tutorial.

### How do I create a bundle?

Use the CLI to combine multiple packets:

```bash
evidencebus bundle packet1.eb.json packet2.eb.json --out ./my-bundle
```

See [Building a Bundle](tutorials/building-a-bundle.md) for more details.

### How do I export to different formats?

evidencebus supports Markdown and SARIF exports:

```bash
# Markdown
evidencebus emit markdown ./bundle --out ./summary.md

# SARIF
evidencebus emit sarif ./bundle --out ./results.sarif
```

See [Exporting to Different Formats](tutorials/exporting-formats.md) for more information.

### How do I validate packets and bundles?

Use the validate command:

```bash
# Validate a packet
evidencebus validate packet.eb.json

# Validate a bundle
evidencebus validate ./bundle

# Schema-only validation (no file checks)
evidencebus validate packet.eb.json --schema-only
```

See [Validating Packets and Bundles](tutorials/validating-packets-bundles.md) for details.

## Architecture

### What are microcrates?

evidencebus is organized as a workspace of focused microcrates, each with a single, well-defined responsibility. This modular architecture improves maintainability, testability, and reusability.

### How do the microcrates relate to each other?

The microcrates form a dependency hierarchy:

```
evidencebus-codes (leaf)
    ↑
evidencebus-types
    ↑
┌─────────────────────────────────────┐
│ evidencebus-digest                  │
│ evidencebus-canonicalization        │
│ evidencebus-path                   │
└─────────────────────────────────────┘
    ↑
evidencebus-validation
    ↑
evidencebus-core
    ↑
evidencebus-fs
    ↑
┌─────────────────────────────────────┐
│ evidencebus-export-markdown         │
│ evidencebus-export-sarif            │
└─────────────────────────────────────┘
    ↑
┌─────────────────────────────────────┐
│ evidencebus-export (facade)         │
│ evidencebus-fixtures               │
└─────────────────────────────────────┘
    ↑
evidencebus-cli
```

### What is the canonical bundle layout?

```
evidence-bundle/
  bundle.eb.json
  packets/
    <packet-id>/
      packet.eb.json
      artifacts/
```

See the [Architecture Guide](architecture.md) for more details.

## Schema and Validation

### Where are the schemas defined?

Schemas are defined in the `schemas/` directory:
- `packet.schema.json` - Packet schema
- `bundle.schema.json` - Bundle schema

You can view them using the CLI:

```bash
evidencebus schema packet --format pretty
evidencebus schema bundle --format pretty
```

### What validation does evidencebus perform?

evidencebus validates:

1. **Schema compliance** - Structure matches JSON Schema
2. **Digest integrity** - SHA-256 digests match file content
3. **Path safety** - No path traversal or unsafe paths
4. **Required fields** - All required fields present
5. **Enum values** - Status and severity values are valid
6. **Conflict detection** - No duplicate packet IDs with different content

### What happens if validation fails?

Validation failures produce clear error messages indicating:
- What failed (schema, digest, path, etc.)
- Where it failed (field, file, etc.)
- Why it failed (specific error details)

### Can I customize validation rules?

Yes, you can add custom validation logic by implementing your own validators using the `evidencebus-validation` crate. See the [API Reference](api-reference.md) for details.

## Digests and Integrity

### What digest algorithm does evidencebus use?

evidencebus uses SHA-256 for all digest computations.

### How are digests computed?

Digests are computed over the canonical JSON representation of packets and the raw bytes of artifact files.

### Why do I get "digest mismatch" errors?

This error occurs when the SHA-256 digest in the packet doesn't match the actual file content. Common causes:

1. File was modified after packet creation
2. Digest was computed incorrectly
3. Wrong file is referenced

**Solution**: Recompute the digest or restore the original file content.

### Can I disable digest checking?

You can use `--schema-only` to skip file existence and digest checks, but this is not recommended for production use.

## Path Handling

### Why does evidencebus reject paths with `..`?

evidencebus prevents path traversal attacks for security. Paths containing `..` could be used to access files outside the intended directory.

### What path format should I use?

Use relative paths with forward slashes, even on Windows:

```json
{
  "relative_path": "artifacts/output.txt"
}
```

### Can I use absolute paths?

No, evidencebus only accepts relative paths to ensure portability and security.

### What about Windows paths?

Use forward slashes even on Windows. Backslashes are rejected for consistency and security.

## Bundles and Packets

### What's the difference between a packet and a bundle?

- **Packet**: A single evidence file from one tool
- **Bundle**: A collection of packets with a manifest and deterministic layout

### Can I have multiple packets with the same ID?

No, packets must have unique IDs within a bundle. If you try to bundle packets with duplicate IDs:

- Identical packets: Automatically deduplicated
- Different packets: Error raised

### How do I handle packet ID conflicts?

You have three options:

1. **Rename** one of the packets
2. **Merge** content into a single packet
3. **Use separate bundles** for different contexts

### Can I modify a bundle after creation?

You can modify files, but this will cause digest validation to fail. To make changes:

1. Modify the packet files
2. Recompute digests
3. Re-create the bundle

## Export Formats

### What export formats are supported?

evidencebus supports:

- **Markdown** - Human-readable reports
- **SARIF** - Static Analysis Results Interchange Format for tool integration

### Why are exports "lossy"?

Some formats (like SARIF) cannot express the full evidencebus model. Exports are explicitly marked as lossy where information cannot be preserved. The canonical truth remains in the JSON + artifacts.

### Can I create custom export formats?

Yes, you can implement custom export formats using the `evidencebus-export` crate. See the [API Reference](api-reference.md) for details.

### How do I integrate SARIF with GitHub?

See the [Exporting to Different Formats](tutorials/exporting-formats.md) tutorial for GitHub Actions integration examples.

## Development

### How do I contribute to evidencebus?

See the [Contributing Guide](../CONTRIBUTING.md) for detailed information on:

- Setting up the development environment
- Coding standards
- Testing guidelines
- Pull request process

### What are the coding standards?

Key standards include:

- Use `thiserror` for error types
- Prefer `Result` over `panic!`
- Document all public APIs
- Follow Rust naming conventions
- Keep crates focused and minimal

See the [Contributing Guide](../CONTRIBUTING.md) for full details.

### How do I run tests?

```bash
# Run all tests
cargo test --workspace --all-targets

# Run tests for a specific crate
cargo test -p evidencebus-core

# Run BDD tests
cargo test --workspace bdd
```

### What testing approach does evidencebus use?

evidencebus uses BDD (Behavior-Driven Development) style tests with descriptive test names:

```rust
#[test]
fn given_valid_packet_when_validated_then_succeeds() {
    // Given
    let packet = create_valid_packet();

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(result.is_ok());
}
```

## Troubleshooting

### "Validation failed" error

**Cause**: Packet or bundle doesn't pass validation.

**Solution**:
1. Check the error message for specific details
2. Verify all required fields are present
3. Ensure digests match file content
4. Check paths are valid and relative

### "Digest mismatch" error

**Cause**: File content doesn't match the digest.

**Solution**:
1. Verify files haven't been modified
2. Recompute digests if files were legitimately updated
3. Check that the correct files are referenced

### "Path traversal detected" error

**Cause**: Packet contains unsafe paths.

**Solution**:
1. Use only relative paths
2. Remove `..` sequences from paths
3. Use forward slashes (even on Windows)

### "Duplicate packet ID" error

**Cause**: Multiple packets have the same ID.

**Solution**:
1. Rename one of the packets
2. Merge content if appropriate
3. Use separate bundles if needed

### "Missing artifact" error

**Cause**: Referenced artifact file doesn't exist.

**Solution**:
1. Ensure all artifacts exist in the correct location
2. Verify paths in the packet are correct
3. Check file permissions

## Integration

### Can I use evidencebus in CI/CD?

Yes, evidencebus is designed for CI/CD integration. See the tutorials for examples with:

- GitHub Actions
- GitLab CI
- Jenkins

### How do I integrate with existing tools?

You can integrate existing tools by:

1. Creating packets that match your tool's output
2. Using the `evidencebus-types` crate to build packets
3. Validating against the schema

See the [Producer Guide](producer-guide.md) for details.

### Can evidencebus work with non-Git VCS?

Yes, evidencebus supports any VCS through the `vcs_kind` field in the subject:

```json
{
  "subject": {
    "vcs_kind": "hg",  // or "svn", "fossil", etc.
    "repo_identifier": "my-repo",
    "commit": "abc123"
  }
}
```

## Performance

### Is evidencebus fast?

Yes, evidencebus is built with Rust for performance. Typical operations:

- Validate packet: < 10ms
- Create bundle: < 100ms (depends on packet count)
- Export to Markdown: < 50ms
- Export to SARIF: < 50ms

### Can evidencebus handle large bundles?

evidencebus can handle bundles with hundreds of packets. Performance scales linearly with packet count.

### What about memory usage?

Memory usage is proportional to bundle size. Typical memory usage is under 50MB for most use cases.

## Security

### Is evidencebus secure?

evidencebus includes several security features:

- Path traversal prevention
- Digest verification
- Schema validation
- Safe path handling

### Does evidencebus handle sensitive data?

evidencebus does not encrypt data. If you need to handle sensitive information:

1. Encrypt artifacts before adding to packets
2. Use secure storage for bundles
3. Consider access controls on bundle directories

### Can evidencebus be used in security-sensitive environments?

Yes, evidencebus is designed for security-sensitive environments. However, you should:

- Validate all inputs
- Use secure transport for bundles
- Implement appropriate access controls

## Licensing

### What license does evidencebus use?

evidencebus is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

### Can I use evidencebus in commercial projects?

Yes, the MIT License allows commercial use.

### Can I contribute to evidencebus?

Yes, contributions are welcome! See the [Contributing Guide](../CONTRIBUTING.md) for details.

## Getting Help

### Where can I get help?

- **Documentation**: Check the [docs/](.) directory
- **Issues**: Search or create issues on GitHub
- **Discussions**: Join GitHub Discussions
- **Maintainers**: Contact maintainers for urgent issues

### How do I report a bug?

Report bugs on GitHub Issues with:

- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Rust version)

### How do I request a feature?

Request features on GitHub Issues with:

- Clear description of the feature
- Use case and motivation
- Proposed implementation (if known)

## Future Plans

### What's planned for future releases?

Future plans include:

- Additional export formats
- Performance improvements
- Enhanced validation rules
- Better error messages
- Docker images
- Pre-built binaries

### How can I influence the roadmap?

Join discussions on GitHub to share your use cases and priorities. We value community feedback.

## Still Have Questions?

If your question isn't answered here, please:

1. Check the [documentation](.)
2. Search [GitHub Issues](https://github.com/EffortlessMetrics/evidencebus/issues)
3. Join [GitHub Discussions](https://github.com/EffortlessMetrics/evidencebus/discussions)
4. Create a new issue with your question
