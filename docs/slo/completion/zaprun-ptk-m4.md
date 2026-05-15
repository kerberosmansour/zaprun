# zaprun-ptk M4 Completion

Date: 2026-05-15

Completed end-to-end release readiness:

- Updated README, crate README, CLI docs, architecture notes, changelog, and workflow smoke coverage.
- Built `zaprun:ptk-local` and published it through a local registry as `localhost:5001/zaprun@sha256:9521117fa4a0f487e8165e4af7ebb5037bf2b5048a5de5d18d3e9564c9ac58ef`.
- Ran PTK against NodeGoat; the scan completed and produced all expected artifacts under `output/zaprun-ptk-nodegoat-20260515225040/`.
- Recorded upstream ZAP Network add-on Netty CVE tracking in issue #3 and kept Trivy gates green with dated, narrow ignores.
