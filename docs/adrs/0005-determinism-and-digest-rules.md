# ADR-0005: determinism and digest rules

evidencebus requires stable ordering and stable digests across runs for the
same inputs.

The implementation therefore sorts packet content canonically and computes
digests from canonical JSON bytes and copied artifact files.
