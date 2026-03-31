# ADR-0004: lossy export policy

Canonical truth lives in packet JSON, bundle JSON, and attached artifacts.

Markdown and SARIF are derived views and may be lossy. That lossiness should
be explicit in documentation and, where useful, in the emitted export metadata.
