# `zaprun` — CLI manual

The canonical CLI manual lives next to the crate so that crates.io renders it as the package's landing page:

→ **[`crates/zaprun/README.md`](../crates/zaprun/README.md)** *(in this repo)*
→ **[`zaprun` on crates.io](https://crates.io/crates/zaprun)** *(published copy)*

The crate README contains:

- Install methods (`cargo install zaprun`, `docker pull`, or build from source).
- Platform-support matrix (Linux / macOS / Windows; image is `linux/amd64`).
- Artifact contract and exit codes.
- Per-subcommand reference for `doctor`, `plan`, `scan`, `api`, `ptk`, `observe`, `calibrate`, `explain`.
- Image entrypoint dispatch (the literal-string-equality security rule).
- End-to-end examples (NodeGoat dogfood, OpenAPI scan, observe-mode replay, CI exit-code gate).
- Troubleshooting table.

This file is kept as a redirect so the link in the root [`README.md`](../README.md) and in older docs continues to resolve.
