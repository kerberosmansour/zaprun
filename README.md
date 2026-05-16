# zaprun

Reproducible DAST scans with a deterministic CLI and a hardened OWASP ZAP image.

[![crates.io](https://img.shields.io/crates/v/zaprun.svg)](https://crates.io/crates/zaprun)
[![v0.3.0](https://img.shields.io/badge/release-v0.3.0-blue)](https://github.com/kerberosmansour/zaprun/releases/tag/v0.3.0)
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
docker pull ghcr.io/kerberosmansour/zaprun:v0.3.0

# 3. From source.
git clone https://github.com/kerberosmansour/zaprun
cargo build --release -p zaprun
```

At runtime the CLI drives Docker, so a working Docker daemon is required on the host regardless of how the CLI was installed.

## Quick start

```bash
# Pull + run the image (no Rust toolchain needed; pin by digest):
docker run --rm \
  -v "$PWD/output:/zap/wrk/output" \
  ghcr.io/kerberosmansour/zaprun@sha256:<digest> \
  zaprun scan http://host.docker.internal:4000 --active --profile spa-pr

# Or use the cargo-installed binary against a digest-pinned image:
zaprun scan http://host.docker.internal:4000 --active --profile spa-pr

# Browser-backed OWASP PTK Phase 1 lane:
zaprun ptk http://host.docker.internal:4000 --output output/zaprun-ptk
```

The image's entrypoint dispatches on the first argument: `zaprun` hands off to the baked-in CLI; anything else falls through to a compatibility scan harness that accepts `--target` / `--output-dir` / `--policy` flags for existing ZAP jobs.

Full subcommand reference, exit codes, the artifact-contract schemas, end-to-end examples, and a per-platform support matrix are in the **[CLI manual](crates/zaprun/README.md)** (also published as the crate's landing page on [crates.io/crates/zaprun](https://crates.io/crates/zaprun)).

## Initialize DAST in a target repo

`zaprun init` bootstraps a consumer repository with target-owned DAST config:

```bash
# From this repo while iterating locally:
cargo run -p zaprun -- init --target-dir /path/to/webapp \
  --deployment-target https://staging.example.test

# Later, re-check drift after threat-model or image-pin changes:
cargo run -p zaprun -- rederive --target-dir /path/to/webapp
```

The emitted workflow calls the latest approved digest-pinned zaprun image with first arg `zaprun`:

```bash
docker run --rm --user 1000:1000 \
  --add-host=host.docker.internal:host-gateway \
  -v "$PWD:/work:ro" \
  -v "$PWD/output:/zap/wrk/output:rw" \
  ghcr.io/kerberosmansour/zaprun@sha256:<digest> \
  zaprun scan https://staging.example.test --active --profile web-pr --output /zap/wrk/output
```

When `openapi.yaml`, `openapi.yml`, or `openapi.json` exists at the target repo root, `init` emits `zaprun api /work/<spec> --target <url> --active` instead. The generated workflow preserves the safety contract: SHA-pinned actions, no `pull_request_target`, top-level `permissions: {}`, no secrets, no `zaproxy/action-*`, and no legacy `zap-api-scan.py` / `zap-baseline.py` / `zap-full-scan.py` helpers.

## Verifying a release

Every published image digest is signed (cosign keyless via Sigstore Fulcio + Rekor) and carries three attestations — SLSA Build Provenance v1, an SPDX-JSON SBOM, and a CycloneDX-JSON SBOM. The signing happens in an isolated reusable workflow that holds `id-token: write` (the build job does not), per SLSA Build L3 guidance.

```bash
# Pull the exact digest you'll run.
docker pull ghcr.io/kerberosmansour/zaprun@sha256:<digest>

# Verify SLSA Build Provenance + SBOMs.
gh attestation verify \
  oci://ghcr.io/kerberosmansour/zaprun@sha256:<digest> \
  --repo kerberosmansour/zaprun

# Verify the cosign keyless signature.
cosign verify \
  --certificate-identity-regexp '^https://github.com/kerberosmansour/zaprun/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/kerberosmansour/zaprun@sha256:<digest>
```

## Image tags

| Tag | Source | Stability |
|---|---|---|
| `@sha256:<64-hex>` | every push to main; every release | immutable — pin here in production |
| `:<full-git-sha>` | every push to main | immutable |
| `:edge` | every push to main | floating — re-points to the most recent main commit |
| `:v0.3.0` | release tag | convenience alias (do not use in consumer runs; pin `@sha256` instead) |
| `:v0.3`, `:v0` | release tag (skipped for pre-releases) | floating — re-points to the latest patch / minor |
| `:latest` | **NEVER PUBLISHED** | n/a |

[SECURITY.md](SECURITY.md) has the full tagging-convention rationale and verification snippets.

## Repository layout

| Path | Purpose |
|---|---|
| [`crates/zaprun/`](crates/zaprun/) | The public, self-contained CLI. Subcommands: `scan`, `api`, `ptk`, `doctor`, `plan`, `observe`, `calibrate`, `init`, `rederive`, `triage-sarif`, and `explain` (see [docs/zaprun-cli.md](docs/zaprun-cli.md)). |
| [`crates/zaprun/src/tuner/`](crates/zaprun/src/tuner/) | The schema, SARIF, baseline, path-safety, and CWE-rule mapping code used by `zaprun init`, `rederive`, and `triage-sarif`. `zaprun` does not depend on `dast-spike`. |
| [`crates/dast-spike/`](crates/dast-spike/) | Legacy scanner-runner experiments kept in the workspace for compatibility tests; not a dependency of `zaprun`. |
| [`docker/zap/Dockerfile`](docker/zap/Dockerfile) | The hardened image. Wolfi base, ZAP from official tarball with SHA-256 pin, add-ons bundled at build time, Trivy-scanned in CI. |
| [`xtasks/dast-verify/`](xtasks/dast-verify/) | Standalone rule-promotion gate for generic DAST rules and target-owned custom rules. |
| [`.github/workflows/build-zap-image.yml`](.github/workflows/build-zap-image.yml) | Build + scan + push (and tag `:edge` on main). |
| [`.github/workflows/sign-and-attest.yml`](.github/workflows/sign-and-attest.yml) | Reusable workflow that signs the image and attests the build provenance + both SBOMs. Holds `id-token: write` (the build job does not — SLSA L3 isolation). |
| [`.github/workflows/release.yml`](.github/workflows/release.yml) | Triggered on tag push (`v*`). Adds semver tags via `crane tag` so the digest (and therefore signatures + attestations) is preserved. |
| [`.github/workflows/scheduled-image-rebuild.yml`](.github/workflows/scheduled-image-rebuild.yml) | Weekly (Mondays 06:00 UTC). Rebuilds + re-scans the image so newly-disclosed CVEs in the bundled deps surface promptly. Also audits `.trivyignore` entries against their tracking-issue age. |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | `cargo fmt --check`, `clippy -D warnings`, full workspace tests on every push and PR. |
| [`.github/renovate.json`](.github/renovate.json) | Renovate config — Cargo workspace, SHA-pinned GHA actions, Dockerfile, with grouping for tokio / serde / sigstore / SunLit-security crates. |
| [`templates/dast-workflow.yml`](templates/dast-workflow.yml) | Workflow skeleton emitted into a target repo by `zaprun init`. |
| [`references/*.toml`](references/) | Pinned digests for upstream artefacts (Wolfi base / ZAP image / Nuclei templates / GHA action SHAs). |
| [`schema/`](schema/) | JSON schemas for the artifact contract. |
| [`.trivyignore`](.trivyignore) | Explicit CVE suppressions with rationale + tracking-issue references; reviewed weekly by `scheduled-image-rebuild.yml`. |

## DAST tuning loop

`/slo-dast-tuner` stays thin and drives the public `zaprun` commands:

1. `zaprun init` writes target-owned `.zaprun/` config and a digest-pinned workflow.
2. `zaprun rederive` checks threat-model/image drift and rewrites at most one reviewable diff.
3. `zaprun triage-sarif` reads SARIF 2.1.0, route/OpenAPI context, and `.zaprun/manifest.json`, then writes `triage-report.json`, `guided-scan-map.json`, and `filtered.sarif`.
4. `zaprun observe` replays a concrete raw HTTP request and writes `observations.json` with response evidence, while preserving the SSRF/IMDS guard.
5. `xtasks/dast-verify` gates candidate JavaScript DAST rules. Generic candidates must pass metadata, safety lint, vulnerable/patched synthetic fixtures, and anti-overfitting checks. App-specific rules can be accepted only as target-owned output under the target repo, such as `.zaprun/scripts/`.

SARIF is evidence, not authority: a result becomes `dast-detectable` only when there is route/request evidence. Authenticated findings remain `needs-human-input` until auth configuration and logged-in reachability are explicit.

## Status

`v0.3.0` adds `zaprun ptk`, an OWASP PTK Phase 1 lane that uses ZAP's Client Spider and the image-baked Client Side Integration + PTK add-ons. The legacy workspace crates `dast-spike` and `dast-spike-rules` are not publishable crates; release the public CLI with:

```bash
cargo publish -p zaprun
```

Do not use `cargo publish --workspace` for this repo.

The image release flow is:

1. Merge this PR to `main`; `.github/workflows/build-zap-image.yml` builds, scans, signs, attests, and pushes `ghcr.io/kerberosmansour/zaprun:<git-sha>`.
2. Tag the merged commit with `v0.3.0` and push the tag; `.github/workflows/release.yml` retags the existing signed digest as `:v0.3.0`, `:v0.3`, and `:v0` without rebuilding.
3. Use the release workflow's digest output for downstream pin bumps and verification.

The previous `v0.2.0` image and crate are signed + attested and public; `v0.3.0` publishes the PTK Phase 1 CLI and hardened image update.

The repo follows `v<major>.<minor>.<patch>` tagging via [release.yml](.github/workflows/release.yml). There is no `:latest` image tag — consumers are expected to pin by digest.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — components, data flow, and trust boundaries.
- [CHANGELOG.md](CHANGELOG.md) — release notes.
- [SECURITY.md](SECURITY.md) — supply-chain controls and vulnerability disclosure.
- [`docs/zaprun-cli.md`](docs/zaprun-cli.md) — full CLI manual.

## License

MIT — see [LICENSE](LICENSE).
