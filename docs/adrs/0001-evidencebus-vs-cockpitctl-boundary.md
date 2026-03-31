# ADR-0001: evidencebus vs cockpitctl boundary

evidencebus owns evidence transport, validation, bundling, and export.

`cockpitctl` owns policy, merge readiness, required vs optional semantics, and
operator decision surfaces.

This boundary prevents evidencebus from turning into cockpit software sideways.
