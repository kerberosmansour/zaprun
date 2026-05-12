# zaprun

Reproducible DAST scans with a deterministic CLI and a hardened OWASP ZAP image.

[![crates.io](https://img.shields.io/crates/v/zaprun.svg)](https://crates.io/crates/zaprun)
[![v0.1.0](https://img.shields.io/badge/release-v0.1.0-blue)](https://github.com/kerberosmansour/zaprun/releases/tag/v0.1.0)
[![image](https://img.shields.io/badge/ghcr.io-zaprun-blue?logo=docker)](https://github.com/kerberosmansour/zaprun/pkgs/container/zaprun)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

`zaprun` is a small Rust CLI that drives OWASP ZAP through Automation Framework plans, plus a Wolfi-based ZAP container image that bakes the CLI in. It targets a few hard requirements:

- **Digest-pinned scans.** The CLI's `--image` flag refuses non-digest references, and the image's Dockerfile checksum-pins its ZAP release tarball + every helper script + the bundled add-ons.
- **Stable artifact contract.** Every run writes the same files (`plan.yaml`, `run.json`, `summary.json`, `coverage.json`, `capabilities.json`, `observations.json`, plus ZAP's JSON/HTML/SARIF reports) so CI gates and humans can reason about results the same way.
- **No reliance on live add-on installs at scan time.** The image bundles the add-ons it needs at build time, so a scan can run on a sealed network.
- **Reasonable defaults for CI.** The image uses a non-root UID, no extra capabilities, and a literal-string-equality entrypoint dispatch that does not eval its arguments.

## Install

Three options, depending on your host:

```bash
# 1. CLI from crates.io (cross-platform: Linux / macOS / Windows).
cargo install zaprun

# 2. Prebuilt container image (linux/amd64; runs via emulation on macOS arm64).
docker pull ghcr.io/kerberosmansour/zaprun:v0.1.0

# 3. From source.
git clone https://github.com/kerberosmansour/zaprun
cargo build --release -p zaprun
```

At runtime the CLI drives Docker, so a working Docker daemon is required on the host regardless of how the CLI was installed.

## Quick start

```bash
# Pull + run the image (no Rust toolchain needed):
docker run --rm \
  -v "$PWD/output:/zap/wrk/output" \
  ghcr.io/kerberosmansour/zaprun:v0.1.0 \
  zaprun scan http://host.docker.internal:4000 --active --profile spa-pr

# Or use the cargo-installed binary against a digest-pinned image:
zaprun scan http://host.docker.internal:4000 --active --profile spa-pr
```

The image's entrypoint dispatches on the first argument: `zaprun` hands off to the baked-in CLI; anything else falls through to a legacy entrypoint that accepts `--target` / `--output-dir` / `--policy` flags for backwards compatibility with existing ZAP harnesses.

Full subcommand reference, exit codes, the artifact-contract schemas, end-to-end examples, and a per-platform support matrix are in the **[CLI manual](crates/zaprun/README.md)** (also published as the crate's landing page on [crates.io/crates/zaprun](https://crates.io/crates/zaprun)).

## Verifying a release

Every published image digest is signed (cosign keyless via Sigstore Fulcio + Rekor) and carries three attestations — SLSA Build Provenance v1, an SPDX-JSON SBOM, and a CycloneDX-JSON SBOM. The signing happens in an isolated reusable workflow that holds `id-token: write` (the build job does not), per SLSA Build L3 guidance.

```bash
# Anyone can pull — the GHCR package is public.
docker pull ghcr.io/kerberosmansour/zaprun:v0.1.0

# Verify SLSA Build Provenance + SBOMs.
gh attestation verify \
  oci://ghcr.io/kerberosmansour/zaprun@sha256:1caa4c454beac1a5ca67bb06484282b94e43a5cd01ba772ec1a2b78a6ed4c649 \
  --repo kerberosmansour/zaprun

# Verify the cosign keyless signature.
cosign verify \
  --certificate-identity-regexp '^https://github.com/kerberosmansour/zaprun/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/kerberosmansour/zaprun@sha256:1caa4c454beac1a5ca67bb06484282b94e43a5cd01ba772ec1a2b78a6ed4c649
```

## Image tags

| Tag | Source | Stability |
|---|---|---|
| `@sha256:<64-hex>` | every push to main; every release | immutable — pin here in production |
| `:<full-git-sha>` | every push to main | immutable |
| `:edge` | every push to main | floating — re-points to the most recent main commit |
| `:v0.1.0` | release tag | immutable per release |
| `:v0.1`, `:v0` | release tag (skipped for pre-releases) | floating — re-points to the latest patch / minor |
| `:latest` | **NEVER PUBLISHED** | n/a |

[SECURITY.md](SECURITY.md) has the full tagging-convention rationale and verification snippets.

## Repository layout

| Path | Purpose |
|---|---|
| [`crates/zaprun/`](crates/zaprun/) | The CLI. Subcommands: `scan`, `api`, `doctor`, `plan`, `observe`, `calibrate`, `explain` (see [docs/zaprun-cli.md](docs/zaprun-cli.md)). |
| [`crates/dast-spike/`](crates/dast-spike/) | A higher-level orchestrator that wraps `zaprun` plus Nuclei and Wapiti. |
| [`crates/dast-spike-rules/`](crates/dast-spike-rules/) | Typed schemas + a curated CWE → scanner-rule mapping. |
| [`docker/zap/Dockerfile`](docker/zap/Dockerfile) | The hardened image. Wolfi base, ZAP from official tarball with SHA-256 pin, add-ons bundled at build time, Trivy-scanned in CI. |
| [`.github/workflows/build-zap-image.yml`](.github/workflows/build-zap-image.yml) | Build + scan + push (and tag `:edge` on main). |
| [`.github/workflows/sign-and-attest.yml`](.github/workflows/sign-and-attest.yml) | Reusable workflow that signs the image and attests the build provenance + both SBOMs. Holds `id-token: write` (the build job does not — SLSA L3 isolation). |
| [`.github/workflows/release.yml`](.github/workflows/release.yml) | Triggered on tag push (`v*`). Adds semver tags via `crane tag` so the digest (and therefore signatures + attestations) is preserved. |
| [`.github/workflows/scheduled-image-rebuild.yml`](.github/workflows/scheduled-image-rebuild.yml) | Weekly (Mondays 06:00 UTC). Rebuilds + re-scans the image so newly-disclosed CVEs in the bundled deps surface promptly. Also audits `.trivyignore` entries against their tracking-issue age. |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | `cargo fmt --check`, `clippy -D warnings`, full workspace tests on every push and PR. |
| [`.github/renovate.json`](.github/renovate.json) | Renovate config — Cargo workspace, SHA-pinned GHA actions, Dockerfile, with grouping for tokio / serde / sigstore / SunLit-security crates. |
| [`templates/dast-workflow.yml`](templates/dast-workflow.yml) | Workflow skeleton emitted into a target repo by `dast-spike init`. |
| [`references/*.toml`](references/) | Pinned digests for upstream artefacts (Wolfi base / ZAP image / Nuclei templates / GHA action SHAs). |
| [`schema/`](schema/) | JSON schemas for the artifact contract. |
| [`.trivyignore`](.trivyignore) | Explicit CVE suppressions with rationale + tracking-issue references; reviewed weekly by `scheduled-image-rebuild.yml`. |

## Status

`v0.1.0` is the first public release. Image is signed + attested, package is public, verification snippets above work today.

The repo follows `v<major>.<minor>.<patch>` tagging via [release.yml](.github/workflows/release.yml). There is no `:latest` image tag — consumers are expected to pin by digest.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — components, data flow, and trust boundaries.
- [SECURITY.md](SECURITY.md) — supply-chain controls and vulnerability disclosure.
- [`docs/zaprun-cli.md`](docs/zaprun-cli.md) — full CLI manual.

## License

MIT — see [LICENSE](LICENSE).
