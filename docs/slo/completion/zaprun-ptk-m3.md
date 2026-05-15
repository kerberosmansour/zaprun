# zaprun-ptk M3 Completion

Date: 2026-05-15

Completed the public PTK CLI lane:

- Added `zaprun ptk <url>` with digest-pinned image support, dry-run mode, browser count bounds, duration parsing, and HTTP(S)-only target validation.
- Generated PTK Phase 1 plans through the typed plan API.
- Normalized artifacts into `summary.json`, `coverage.json`, and `zap.sarif` alongside the ZAP reports.
- Verified YAML-only E2E tests and command help.
