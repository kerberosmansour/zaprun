# zaprun

Reproducible DAST scans with a deterministic CLI and a hardened OWASP ZAP image.

This is the public home of the `zaprun` Rust CLI and the `ghcr.io/kerberosmansour/zaprun` container image. Both are pinned by digest, the image is built from a Wolfi base with the ZAP release tarball and add-ons checksum-pinned at build time, and the entrypoint dispatches its argv via literal-string-equality (no shell evaluation of attacker-controlled input).

The repository is in early-stage public release. A first signed and attested image tag is forthcoming.

## Layout

- `crates/zaprun/` — the CLI.
- `crates/dast-spike/` — orchestrator that wraps `zaprun` plus Nuclei and Wapiti.
- `crates/dast-spike-rules/` — typed schemas for the artifact contract.
- `docker/zap/Dockerfile` — the hardened image.
- `.github/workflows/build-zap-image.yml` — publish workflow.
- `.github/workflows/ci.yml` — `cargo fmt`, `clippy`, workspace tests on every push.
- `templates/dast-workflow.yml` — workflow skeleton emitted into a target repo by `dast-spike init`.
- `references/*.toml` — pinned digests for upstream artefacts.
- `schema/` — JSON schemas for the artifact contract.

See [ARCHITECTURE.md](ARCHITECTURE.md) for components, data flow, and trust boundaries. See [SECURITY.md](SECURITY.md) for the supply-chain controls and vulnerability disclosure.

## License

MIT — see [LICENSE](LICENSE).
