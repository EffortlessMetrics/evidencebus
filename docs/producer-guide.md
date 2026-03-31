# Producer guide

## Goal

Emit one packet JSON file plus any attached artifacts.

## Packet guidance

- use a stable `packet_id`
- keep `producer.tool` and `producer.version` accurate
- keep the summary short and neutral
- put richer data into typed attachments
- use `role = "native_payload"` with a `schema_id` for tool-native JSON

## Attachment guidance

- attachments are referenced by relative path
- include `sha256` and `size_bytes` when possible
- use stable roles:
  - `native_payload`
  - `report_html`
  - `stderr_log`
  - `stdout_log`
  - `report_json`

## Example

See `fixtures/packets/perfgate` and `fixtures/packets/faultline`.
