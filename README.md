# evidencebus

**Schema-first evidence backplane for repo operations.**

evidencebus takes outputs from tools like `faultline`, `proofrun`, `repropack`,
`stackcut`, `perfgate`, and similar repos and turns them into:

- validated packets
- deterministic bundles
- portable artifact inventories
- neutral exports such as Markdown and SARIF

It is deliberately **not** the merge cockpit. evidencebus moves evidence.
`cockpitctl` should decide what that evidence means for merge.

## Core commands

```bash
evidencebus validate fixtures/packets/perfgate/pkt-perfgate.eb.json
evidencebus bundle \
  fixtures/packets/perfgate/pkt-perfgate.eb.json \
  fixtures/packets/faultline/pkt-faultline.eb.json \
  --out ./out/evidence-bundle

evidencebus inspect ./out/evidence-bundle
evidencebus emit markdown ./out/evidence-bundle --out ./out/SUMMARY.md
evidencebus emit sarif ./out/evidence-bundle --out ./out/results.sarif
evidencebus schema packet
```

## Workspace doctrine

- **artifact-first** — packets and bundles are the product
- **schema-first** — checked-in JSON Schemas define the public contract
- **deterministic** — stable ordering, stable digests, stable manifests
- **local-first** — no daemon, service, or network requirement
- **neutral** — evidence transport and validation only, never merge policy

## Canonical layout

evidencebus writes directory bundles in this shape:

```text
evidence-bundle/
  bundle.eb.json
  packets/
    pkt-faultline/
      packet.eb.json
      artifacts/
        faultline/analysis.json
        faultline/index.html
        logs/stderr.log
    pkt-perfgate/
      packet.eb.json
      artifacts/
        report.json
```

## Documents

- `requirements.md`
- `design.md`
- `tasks.md`
- `docs/architecture.md`
- `docs/producer-guide.md`
- `docs/consumer-guide.md`
