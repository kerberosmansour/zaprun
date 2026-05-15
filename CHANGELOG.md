# Changelog

## v0.2.0

- Moved `init`, `rederive`, `triage-sarif`, SARIF parsing, manifest handling, baseline schema handling, path-safe writes, and CWE rule mappings into `crates/zaprun` so the published crate is self-contained.
- Removed the `dast-spike` dependency from `zaprun`.
- Updated the image smoke tests to verify the baked CLI version and the full current subcommand surface.
- Renamed image-owned entrypoint, environment, and policy labels from their old project names to `zaprun`.
- Updated the root docs and crate README for the v0.2.0 release.

## v0.1.0

- First public release of the digest-pinned `zaprun` CLI and hardened OWASP ZAP image.
