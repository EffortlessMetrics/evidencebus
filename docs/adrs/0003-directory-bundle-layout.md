# ADR-0003: directory bundle layout

v0.1 uses a directory bundle representation instead of an opaque archive.

Reasons:

- easier local inspection
- easier diffing
- easier validation
- zip packaging can be added later without changing the canonical model
