# zaprun

Reproducible DAST scans with a deterministic CLI and a hardened OWASP ZAP image.

`zaprun` is a small Rust CLI that drives OWASP ZAP through Automation Framework plans, plus a Wolfi-based ZAP container image that bakes the CLI in. It targets a few hard requirements:

- **Digest-pinned scans.** Both the ZAP image and any helper scripts are content-addressed; the CLI refuses non-digest references.
- **Stable artifact contract.** Every run writes the same files (`plan.yaml`, `run.json`, `summary.json`, `coverage.json`, `capabilities.json`, `observations.json`, plus ZAP's JSON/HTML reports) so CI gates and humans can reason about results the same way.
- **No reliance on live add-on installs at scan time.** The image bundles the add-ons it needs at build time, so a scan can run on a sealed network.
- **Reasonable defaults for CI.** The image uses a non-root UID, no extra capabilities, and a literal-string-equality entrypoint dispatch that does not eval its arguments.

## Quick start

```bash
docker run --rm \
  -v "$PWD/output:/zap/wrk/output" \
  ghcr.io/kerberosmansour/zaprun:<version> \
  zaprun scan http://host.docker.internal:4000 --active --profile spa-pr
```

The image's entrypoint dispatches on the first argument: `zaprun` hands off to the baked-in CLI; anything else falls through to a legacy entrypoint that accepts `--target` / `--output-dir` / `--policy` flags for backwards compatibility.

Full subcommand reference, exit codes, and the artifact-contract schemas are in [docs/zaprun-cli.md](docs/zaprun-cli.md).

## What's in this repo

| Path | Purpose |
|---|---|
| `crates/zaprun/` | The CLI (Rust). Subcommands: `scan`, `triage`, `api`, `doctor`, `plan`, `observe`, `calibrate`, `explain`. |
| `crates/dast-spike/` | A higher-level orchestrator that wraps `zaprun` plus other scanners (Nuclei, Wapiti). |
| `crates/dast-spike-rules/` | Curated CWE → ZAP/Nuclei rule mapping used by the orchestrator. |
| `docker/zap/Dockerfile` | The hardened ZAP image. Wolfi base, ZAP from official tarball with checksum pin, add-ons bundled at build time, Trivy-scanned in CI. |
| `.github/workflows/build-zap-image.yml` | Builds + scans + (eventually) signs and publishes the image to GHCR. |
| `.github/workflows/ci.yml` | Cargo fmt / clippy / test on every push and PR. |
| `references/*.toml` | Pinned digests for upstream artefacts (the ZAP image, Nuclei templates, GHA action SHAs). |
| `schema/` | JSON schemas for the artifact contract. |
| `templates/dast-workflow.yml` | A GitHub Actions workflow template the `dast-spike init` subcommand emits into a target repo. |

## Verifying a published image

(Reserved — once the v0.1.0 release lands the image will be cosign-signed with keyless GitHub OIDC. The verification command will live here:)

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/kerberosmansour/zaprun/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/kerberosmansour/zaprun@sha256:<digest>
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system diagram, component responsibilities, and the threat model summary.

## Security

See [SECURITY.md](SECURITY.md) for the supported version policy, supply-chain controls, and reporting instructions.

## License

MIT — see [LICENSE](LICENSE).

## Status

`v0.1.0` is the first published release. This repo will follow the conventional `v<major>.<minor>.<patch>` tag pattern. There is no `:latest` image tag — consumers are expected to pin by digest.
