# Schema overview

evidencebus exposes two canonical JSON schema surfaces:

- `packet.schema.json`
- `bundle.schema.json`

## Packet

A packet represents one tool invocation and contains:

- header and identity
- producer metadata
- subject metadata
- summary
- projections
- provenance

## Bundle

A bundle represents a deterministic directory that contains:

- manifest metadata
- packet inventory
- artifact inventory
- summary counts

## Compatibility

Schema version changes should be deliberate and documented. Producers should
attach richer native payloads rather than forcing every field into the common
projection layer.
