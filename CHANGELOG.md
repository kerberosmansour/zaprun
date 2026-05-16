# Changelog

## v0.3.1 - 2026-05-16

- Fixed a high-severity `zaprun observe` SSRF guard bypass where manual target parsing disagreed with `reqwest` replay URL parsing.
- Reused SunLit `secure_boundary::SafeUrl` for the default no-internal-target SSRF blocklist and kept zaprun's stricter always-blocked IMDS/link-local policy.
- Added regression coverage for userinfo authority bypasses, bracketed IPv6 literals, IPv4-mapped IPv6 literals, and observe replay rejection before any protected socket connection is opened.

## v0.3.0 - 2026-05-15

- Baked ZAP Client Side Integration `client` 0.24.0 and OWASP PTK `ptk` 0.4.0 add-ons into the hardened image with SHA-256 verified downloads.
- Added typed Automation Framework support for `env.configs` PTK Phase 1 settings and the `spiderClient` job.
- Added `zaprun ptk <url>` for OWASP PTK Phase 1 scans with deterministic plan/run artifacts and normalised summary, coverage, and SARIF output.
- Removed the GUI-only ZAP Quick Start add-on from the hardened headless image after PTK config smokes exposed a ZAP 2.17.0 headless startup failure.
- Added release smoke coverage for PTK add-on presence, PTK config startup, the `zaprun ptk` CLI surface, and extracted `.zap` add-on vulnerability scanning.

## v0.2.0

- Moved `init`, `rederive`, `triage-sarif`, SARIF parsing, manifest handling, baseline schema handling, path-safe writes, and CWE rule mappings into `crates/zaprun` so the published crate is self-contained.
- Removed the `dast-spike` dependency from `zaprun`.
- Updated the image smoke tests to verify the baked CLI version and the full current subcommand surface.
- Renamed image-owned entrypoint, environment, and policy labels from their old project names to `zaprun`.
- Updated the root docs and crate README for the v0.2.0 release.

## v0.1.0

- First public release of the digest-pinned `zaprun` CLI and hardened OWASP ZAP image.
