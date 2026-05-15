# `zaprun` — CLI manual

`zaprun` is a point-and-shoot ZAP driver: it builds an OWASP ZAP Automation Framework plan, runs ZAP via a digest-pinned container, and writes a stable set of artifacts so CI gates and humans can reason about results the same way.

This manual is the canonical reference for v0.2.0. It describes the self-contained `zaprun` crate and the CLI baked into [`ghcr.io/kerberosmansour/zaprun:v0.2.0`](https://github.com/kerberosmansour/zaprun/pkgs/container/zaprun).

## Install

Pick one of the three install methods, depending on your host:

```bash
# 1. From crates.io — builds the CLI from source. Cross-platform.
cargo install zaprun

# 2. From the prebuilt image — no Rust toolchain needed. Linux-amd64-native;
#    on macOS arm64 the image runs via Rosetta / QEMU emulation.
docker pull ghcr.io/kerberosmansour/zaprun:v0.2.0

# 3. From source.
git clone https://github.com/kerberosmansour/zaprun
cd zaprun
cargo build --release -p zaprun
./target/release/zaprun --help
```

At runtime `zaprun` drives Docker, so a working Docker daemon is required on the host regardless of how the CLI was installed.

## Platform support

| Platform | CLI binary | Container image | Notes |
|---|---|---|---|
| Linux x86_64 | ✅ `cargo install` / prebuilt | ✅ native `linux/amd64` | First-class target. |
| Linux aarch64 | ✅ `cargo install` from source | ⚠ image is `linux/amd64` only; pull works but runs via QEMU | Multi-arch image build is a planned enhancement. |
| macOS Apple Silicon (aarch64) | ✅ `cargo install` from source | ⚠ Docker Desktop / OrbStack / Colima run the amd64 image via Rosetta; benign `requested image's platform` warning prints | Works; slightly slower than native. |
| macOS Intel (x86_64) | ✅ `cargo install` from source | ✅ runs natively under Docker Desktop. | |
| Windows x86_64 | ✅ `cargo install` from source | ✅ runs under Docker Desktop's WSL2 backend | Volume-mount paths follow Docker Desktop's Windows-to-Linux translation. |

The Rust code is pure portable Rust (`rustls-tls`, no `native-tls`; `getrandom` for the CSPRNG; `which` for binary lookup). Cross-compilation should work out of the box for any target the Rust toolchain supports.

## Table of contents

- [Where the CLI lives](#where-the-cli-lives)
- [Invocation patterns](#invocation-patterns)
- [Artifact contract](#artifact-contract)
- [Exit codes](#exit-codes)
- [Subcommands](#subcommands)
  - [`doctor`](#doctor)
  - [`plan`](#plan)
  - [`scan`](#scan)
  - [`api`](#api)
  - [`observe`](#observe)
  - [`init`](#init)
  - [`rederive`](#rederive)
  - [`triage-sarif`](#triage-sarif)
  - [`calibrate`](#calibrate)
  - [`explain`](#explain)
- [Image entrypoint dispatch](#image-entrypoint-dispatch)
- [Reaching the target from inside the scanner](#reaching-the-target-from-inside-the-scanner)
- [End-to-end examples](#end-to-end-examples)
- [Troubleshooting](#troubleshooting)

## Where the CLI lives

Two distribution surfaces:

1. **Baked into the image** at `/usr/local/bin/zaprun`. Pull the digest-pinned image and invoke `zaprun` as the first argument. This is the canonical way to run scans — no host Rust toolchain required.
2. **Built from source** by cloning the repo and running `cargo build --release -p zaprun`. The resulting binary lives at `target/release/zaprun`. Useful for development; for scans it's still better to use the image because the image bundles the matching ZAP runtime + add-ons + helper scripts.

The CLI's `--image` flag enforces digest pinning. Tag references (`:v0.2.0`, `:edge`) are NOT accepted; only `<repo>@sha256:<64-hex>` is. This is by design — every published digest carries a cosign signature and three attestations (SLSA Build Provenance, SPDX SBOM, CycloneDX SBOM) and tag-by-tag resolution loses the binding.

`zaprun` does not depend on `dast-spike`; the `init`, `rederive`, `triage-sarif`, schema, SARIF, and path-safety code used by the public CLI lives inside this crate.

## Invocation patterns

### From the image (recommended)

```bash
docker run --rm \
  -v "$PWD/output:/zap/wrk/output" \
  ghcr.io/kerberosmansour/zaprun@sha256:<digest> \
  zaprun scan http://host.docker.internal:4000 --active --profile spa-pr
```

The first positional argument after the image ref selects the inner CLI: the entrypoint dispatches `zaprun` -> the baked binary; anything else falls through to the image's compatibility scan harness, which accepts `--target` / `--output-dir` / `--policy` for existing ZAP jobs (see [image entrypoint dispatch](#image-entrypoint-dispatch) for the literal-equality rule).

### From a local build

```bash
cargo build --release -p zaprun
./target/release/zaprun scan http://localhost:4000 --active
```

The CLI itself talks to a Docker daemon to run ZAP; you still need a working Docker on the host.

## Artifact contract

Every successful run writes the following files under `--output` (default `./output/zaprun`):

| File | Schema | Contents |
|---|---|---|
| `plan.yaml` | ZAP Automation Framework | The exact plan that was executed. |
| `run.json` | v1.0 | Run metadata: image digest, per-run 32-byte API-key envelope, target URL, exit code, timings. |
| `summary.json` | v1.0 | Normalised finding summary — severity counts + sample alerts per rule. |
| `coverage.json` | v1.0 | Coverage ledger — URLs discovered vs URLs scanned. |
| `capabilities.json` | v1.0 | `doctor` pre-flight result: backend, image digest, browser support. |
| `observations.json` | v1.0 | `observe`-mode replay record. Only written when `observe` runs. |
| `zap-report.json` | ZAP traditional JSON | Raw ZAP report, preserved verbatim alongside the normalised summary. |
| `zap-report.html` | ZAP HTML | Raw ZAP HTML report. |
| `zap.sarif` | SARIF 2.1.0 | For GitHub Code Scanning and other SARIF consumers. |

Not every subcommand writes every file — see the per-subcommand sections below. `summary.json` plus `zap-report.json` are the most consumed pair; `plan.yaml` is the deterministic-replay anchor.

## Exit codes

`zaprun` exits with one of six well-defined codes — useful in CI gating logic.

| Code | Meaning |
|---|---|
| `0` | scan completed and policy gate passed |
| `1` | scan completed and policy gate failed |
| `2` | tool or environment error (bad args, missing docker, unsafe path) |
| `3` | target unavailable or scan could not start |
| `4` | timeout or resource budget exceeded |
| `5` | coverage contract failed |

The mapping is exhaustive: every Rust-side error category lands on exactly one exit code. This is asserted by `crates/zaprun/tests/unit_exit_code_mapping_is_total.rs`.

## Subcommands

### `doctor`

Pre-flight check (M1). Confirms the backend is reachable, the image digest is well-formed and pullable, and (optionally) the target URL responds.

```text
Usage: zaprun doctor [OPTIONS]

Options:
      --backend <BACKEND>            Backend to probe. `docker` (default) or `local-zap` (stubbed) [default: docker]
      --image <IMAGE>                Optional image reference. When provided, must be `<repo>@sha256:<64-hex>`
      --probe-target <PROBE_TARGET>  Optional target URL to probe for reachability
      --output <OUTPUT>              Output directory for `capabilities.json` [default: ./output/zaprun]
  -h, --help                         Print help
```

**Examples**

```bash
# Default: probe docker + the pinned image
zaprun doctor

# Probe a target URL for reachability before scanning
zaprun doctor --probe-target http://localhost:3001

# Validate a specific image digest is well-formed and pullable
zaprun doctor --image ghcr.io/kerberosmansour/zaprun@sha256:<digest>
```

Writes: `capabilities.json`.

### `plan`

Build a ZAP Automation Framework plan for a target without running it (M2). Useful for inspecting the plan before kicking off a scan, or for emitting the plan into a target repo for archival.

```text
Usage: zaprun plan [OPTIONS] <TARGET>

Arguments:
  <TARGET>  Target URL the plan should describe

Options:
      --dry-run          Materialise the plan but do not run the scanner (only mode in MVP1)
      --output <OUTPUT>  Output directory for plan.yaml and run.json [default: ./output/zaprun]
  -h, --help             Print help
```

**Examples**

```bash
# Materialise a plan for inspection (no scan)
zaprun plan https://example.test --dry-run

# Plan into a custom directory
zaprun plan http://localhost:3001 --dry-run --output output/zaprun-plan
```

Writes: `plan.yaml`, `run.json`.

Note: in v0.2.0, `plan` only supports `--dry-run`. Running the plan from `plan` directly is reserved for MVP2.

### `scan`

Run an active web URL scan (M3). The default profile is `web-pr` (traditional spider + active scan); `spa-pr` adds the Ajax spider + DOM-XSS active rules via Firefox-backed Selenium.

```text
Usage: zaprun scan [OPTIONS] <URL>

Arguments:
  <URL>  Target URL to scan (http or https)

Options:
      --active                       Run the active scanner (in addition to spidering and passive rules)
      --passive                      Run only passive rules (mutually exclusive with --active in practice)
      --profile <PROFILE>            Scan profile: `web-pr` (default, traditional) or `spa-pr` (Ajax + DOM XSS) [default: web-pr]
      --browser-id <BROWSER_ID>      Selenium browser ID for browser-backed rules (e.g. DOM XSS) [default: firefox-headless]
      --output <OUTPUT>              Output directory for plan.yaml/run.json/summary.json/zap-report.* [default: ./output/zaprun]
      --image <IMAGE>                Optional image reference (`<repo>@sha256:<64-hex>`); defaults to the pinned digest
      --scan-timeout <SCAN_TIMEOUT>  Scan timeout (e.g. `8m`, `30m`) [default: 8m]
  -h, --help                         Print help
```

**Examples**

```bash
# Default profile (web-pr): traditional spider + active scan
zaprun scan https://example.test --active

# SPA-aware profile (spa-pr): Ajax spider + DOM XSS rules
zaprun scan http://host.docker.internal:4000 --active --profile spa-pr

# Longer scan budget for a larger target
zaprun scan http://localhost:4000 --active --scan-timeout 30m

# Passive-only sweep (no active probes — useful in shared envs)
zaprun scan https://example.test --passive

# Pin a specific image digest (CI lane that wants reproducibility-by-digest)
zaprun scan http://localhost:4000 --active \
  --image ghcr.io/kerberosmansour/zaprun@sha256:<digest>

# Direct output to a per-CI-job dir
zaprun scan http://localhost:4000 --active --output output/zaprun-pr-1234
```

Writes: `plan.yaml`, `run.json`, `summary.json`, `coverage.json`, `capabilities.json`, `zap-report.json`, `zap-report.html`, `zap.sarif`.

`--scan-timeout` defaults to `8m`. For active scans against larger or interactive targets, bump to `15m`–`30m`. The scanner's internal timeout is independent of any CI job timeout — set both.

### `api`

Run an OpenAPI active scan (M4). Loads the spec, rewrites the host so the scanner container can reach the host gateway, builds an Automation Framework plan with an **inlined** active-scan policy (no dependency on `~/.ZAP/policies/*.policy` at scan time), and runs it.

```text
Usage: zaprun api [OPTIONS] --target <TARGET> <SPEC>

Arguments:
  <SPEC>  Path to the OpenAPI spec (YAML or JSON)

Options:
      --target <TARGET>              Target base URL the spec describes (http or https)
      --active                       Run the active scanner (passive-only is the default)
      --output <OUTPUT>              Output directory for plan.yaml/run.json/summary.json/zap-report.* [default: ./output/zaprun]
      --image <IMAGE>                Optional image reference (`<repo>@sha256:<64-hex>`); defaults to the pinned digest
      --scan-timeout <SCAN_TIMEOUT>  Scan timeout (e.g. `8m`, `30m`) [default: 8m]
  -h, --help                         Print help
```

**Examples**

```bash
# Active scan a local API behind a generated OpenAPI doc
zaprun api ./openapi.yaml --target http://localhost:3001 --active

# Pin output dir for a smoke service run
zaprun api ./crates/secure_smoke_service/openapi.yaml \
  --target http://localhost:3001 --active \
  --output output/zaprun-smoke

# Passive-only sweep against a production-shaped spec
zaprun api ./openapi.yaml --target https://api.example.test

# Custom scan timeout for a deep API
zaprun api ./openapi.yaml --target http://localhost:3001 --active --scan-timeout 20m
```

Writes: same set as `scan`, plus the inlined API-Minimal active policy is captured in `plan.yaml` so a reader can reproduce the run from the plan alone.

The inlined policy's SHA-256 is pinned as `API_MINIMAL_POLICY_INLINE_HASH` in `crates/zaprun/src/scan_api.rs`; drift is detected by `crates/zaprun/tests/unit_api_inline_policy.rs`. Changing the policy requires a deliberate, reviewed bump of the pinned hash.

### `observe`

Send a candidate raw HTTP request and record replay evidence. Useful for incident-response and SAST-guided DAST flows: take a request that reaches a finding, replay it against a staging target, and capture whether the target responded before deciding how to tune scanner coverage.

```text
Usage: zaprun observe [OPTIONS] --target <TARGET>

Options:
      --request <REQUEST>      Path to a candidate raw HTTP request to replay
      --finding <FINDING>      Path to a candidate finding JSON to replay
      --target <TARGET>        Target URL the request should be sent to
      --output <OUTPUT>        Output directory for observations.json [default: ./output/zaprun]
      --allow-internal-target  Opt out of the SSRF guard for RFC1918 + loopback targets.
                               Link-local / IMDS (169.254/16) is ALWAYS refused regardless of this flag
  -h, --help                   Print help
```

**Examples**

```bash
# Replay a request file against an internal target
zaprun observe \
  --request ./req.http \
  --target http://localhost:3001 \
  --allow-internal-target

# Replay a finding fixture and write observations.json
zaprun observe \
  --finding ./finding.json \
  --target https://example.test
```

Writes: `observations.json` with request/response evidence such as `request_sent`, `response_observed`, `request_path`, `http_status`, and `response_body_hash`. ZAP alert correlation can be layered on top of this evidence path; the replay artifact is already useful for proving that a SARIF finding has an HTTP-reachable request.

**SSRF guard** — `observe`'s `--target` is the only `zaprun` flag with a network-trust-boundary check. Link-local addresses (169.254.0.0/16, the IMDS range) are unconditionally refused. RFC1918 (10/8, 172.16/12, 192.168/16) and loopback (127/8) require the explicit `--allow-internal-target` opt-in. The rationale is in `crates/zaprun/tests/unit_observe_ssrf_guard.rs`. The `scan` subcommand uses scheme-only validation because loopback is the headline scan target in CI.

### `init`

Bootstrap target-owned DAST configuration and a GitHub Actions workflow.

```text
Usage: zaprun init [OPTIONS]

Options:
      --target-dir <TARGET_DIR>              Target repository to receive .zaprun/ config and .github/workflows/dast.yml [default: .]
      --deployment-target <DEPLOYMENT_TARGET> Runtime base URL the workflow should scan
      --image <IMAGE>                        Optional image reference (`<repo>@sha256:<64-hex>`); defaults to the pinned digest
  -h, --help                                 Print help
```

Writes `.zaprun/policy-pr.yml`, `.zaprun/policy-nightly.yml`, `.zaprun/baseline.json`, `.zaprun/rules.tsv`, `.zaprun/manifest.json`, and `.github/workflows/dast.yml`.

### `rederive`

Recompute target-owned DAST configuration when the threat model or approved image digest drifts from `.zaprun/manifest.json`.

```text
Usage: zaprun rederive [OPTIONS]

Options:
      --target-dir <TARGET_DIR>  Target repository containing .zaprun/manifest.json [default: .]
  -h, --help                     Print help
```

When drift exists, `rederive` rewrites the generated files and opens one review PR with `gh pr create` from the target repository.

### `triage-sarif`

Classify SAST SARIF into endpoint x CWE guided DAST inputs.

```text
Usage: zaprun triage-sarif [OPTIONS] --sarif <SARIF>

Options:
      --target-dir <TARGET_DIR>  Target repository containing route/OpenAPI context [default: .]
      --sarif <SARIF>            SARIF file to classify
      --output <OUTPUT>          Output directory for triage-report.json/guided-scan-map.json/filtered.sarif [default: ./output/zaprun-triage-sarif]
  -h, --help                     Print help
```

Writes `triage-report.json`, `guided-scan-map.json`, and `filtered.sarif`. SARIF remains evidence, not authority: authenticated findings stay `needs-human-input` until logged-in reachability is configured.

### `calibrate`

Class-based calibration against expected plugin IDs (M5). Reads a calibration profile TOML that declares which ZAP plugin IDs are expected to fire on a target, and reports observed-vs-expected. Useful for regression-testing scanner coverage when you ship a new version of a vulnerable-app fixture.

```text
Usage: zaprun calibrate [OPTIONS] <PROFILE>

Arguments:
  <PROFILE>  Calibration profile TOML describing expected plugin classes

Options:
      --output <OUTPUT>  Output directory for calibration evaluation results [default: ./output/zaprun]
  -h, --help             Print help
```

**Examples**

```bash
# Evaluate a calibration profile against NodeGoat
zaprun calibrate ./calibration/nodegoat.toml \
  --output output/zaprun-calibrate
```

Writes: calibration-results JSON in the output directory.

In v0.2.0 the calibration evaluator reads the profile and produces a placeholder result; full scan-orchestration is tracked as a zaprun follow-up. The flag surface is stable.

### `explain`

Explain a previous run directory (placeholder in v0.2.0).

```text
Usage: zaprun explain <RUN_DIR>

Arguments:
  <RUN_DIR>  Path to a previous zaprun output directory

Options:
  -h, --help  Print help
```

Reserved for MVP2. The CLI accepts the argument shape so future invocations don't need to change, but the implementation prints an MVP2-pending banner.

## Image entrypoint dispatch

The hardened ZAP image's `ENTRYPOINT` is a shell script that does **literal-string-equality** dispatch on `$1`:

```bash
if [ "${1:-}" = "zaprun" ]; then
  shift
  exec /usr/local/bin/zaprun "$@"
fi
# Otherwise: fall through to the compatibility --target/--output-dir/--policy scan harness.
```

The literal check (no regex, no case-fold, no `eval`) is a deliberate security property: shell metacharacters in `$1` are NEVER expanded. An invocation like `docker run … "zaprun; echo PWNED"` does NOT match `"zaprun"` and falls through to the compatibility scan harness, which rejects with `unknown argument: zaprun; echo PWNED`. The argv-injection abuse case is exercised in `.github/workflows/build-zap-image.yml`'s `Smoke test final image` step.

## Reaching the target from inside the scanner

The scanner container runs with `--add-host=host.docker.internal:host-gateway`, so a target listening on the host's `127.0.0.1:<port>` is reachable from inside the scanner as `http://host.docker.internal:<port>`.

For the `api` subcommand, `zaprun` rewrites `http://127.0.0.1:<port>` references in the OpenAPI spec's `servers` block to `http://host.docker.internal:<port>` automatically (see `crates/zaprun/src/scan.rs::rewrite_openapi_host`). For the `scan` subcommand, you pass the right URL directly; if the target is on the host, use `http://host.docker.internal:<port>`.

## End-to-end examples

### Example 1: NodeGoat in CI (the publish-runbook dogfood lane)

```bash
# 1. Start the target. NodeGoat exposes the app on port 4000.
docker run -d --name nodegoat -p 4000:4000 \
  nirocr/nodegoat@sha256:1384d404f1eb89ba218a5988cccde902bb6b606e3ec70f60b185183f9639c392

# 2. Wait for the target to become healthy.
for i in $(seq 1 60); do
  curl -fsS --max-time 2 http://127.0.0.1:4000/ >/dev/null && break
  sleep 1
done

# 3. Active scan with the SPA-aware profile + a generous timeout.
mkdir -p output && chmod 0777 output
docker run --rm \
  -v "$PWD/output:/zap/wrk/output" \
  --add-host=host.docker.internal:host-gateway \
  ghcr.io/kerberosmansour/zaprun:v0.2.0 \
  zaprun scan http://host.docker.internal:4000 \
    --active --profile spa-pr --scan-timeout 30m

# 4. Tear down.
docker rm -f nodegoat
```

The scan writes `output/plan.yaml`, `output/zap-report.json`, `output/summary.json`, `output/zap.sarif`, and the rest of the artifact contract.

### Example 2: scan a generated OpenAPI doc

```bash
# Target: a Rust service that emits its own openapi.yaml.
cargo build --release -p secure_smoke_service
./target/release/secure_smoke_service &
SVC_PID=$!

curl -fsS http://localhost:3001/openapi.yaml -o /tmp/openapi.yaml

docker run --rm \
  -v "$PWD/output:/zap/wrk/output" \
  -v /tmp/openapi.yaml:/spec/openapi.yaml:ro \
  --add-host=host.docker.internal:host-gateway \
  ghcr.io/kerberosmansour/zaprun:v0.2.0 \
  zaprun api /spec/openapi.yaml \
    --target http://host.docker.internal:3001 \
    --active

kill "$SVC_PID"
```

The `api` subcommand inlines its active-scan policy into `plan.yaml` so the result is reproducible from the plan alone.

### Example 3: replay a bug-bounty finding via observe

```bash
# Suppose req.http is the request the reporter included, against a staging URL.
cat > req.http <<'REQ'
POST /api/checkout HTTP/1.1
Host: staging.example.test
Content-Type: application/json

{"coupon": "<script>alert(1)</script>"}
REQ

docker run --rm \
  -v "$PWD/output:/zap/wrk/output" \
  -v "$PWD/req.http:/in/req.http:ro" \
  ghcr.io/kerberosmansour/zaprun:v0.2.0 \
  zaprun observe \
    --request /in/req.http \
    --target https://staging.example.test
```

`output/observations.json` carries replay evidence for the request and response. Use that evidence with `zaprun triage-sarif` and the DAST rule gate before promoting any scanner-rule change.

### Example 3b: triage SARIF and gate a target-owned rule

```bash
zaprun triage-sarif \
  --target-dir /path/to/webapp \
  --sarif ./sast.sarif \
  --output output/zaprun-triage

cargo run --manifest-path xtasks/dast-verify/Cargo.toml -- gate \
  --candidate ./candidate-rule.js \
  --fixtures tests/synthetic-mocks \
  --output output/dast-verify.json

cargo run --manifest-path xtasks/dast-verify/Cargo.toml -- gate \
  --candidate ./target-owned-rule.js \
  --fixtures tests/synthetic-mocks \
  --output output/target-rule.json \
  --target-owned \
  --target-output /path/to/webapp/.zaprun/scripts
```

Generic rule candidates must pass the gate before they belong in this repository. App-specific rules stay target-owned.

### Example 4: gate a PR on high-severity findings

```bash
# Run the scan…
docker run --rm \
  -v "$PWD/output:/zap/wrk/output" \
  ghcr.io/kerberosmansour/zaprun:v0.2.0 \
  zaprun scan http://host.docker.internal:4000 --active
SCAN_EXIT=$?

# …then key on the documented exit code in your gate.
case "$SCAN_EXIT" in
  0)  echo "PASS: no high-severity findings"; exit 0 ;;
  1)  echo "FAIL: policy gate failed (see output/summary.json)"; exit 1 ;;
  3)  echo "ERROR: target unavailable"; exit 1 ;;
  4)  echo "ERROR: scan timed out"; exit 1 ;;
  *)  echo "ERROR: tool/env error ($SCAN_EXIT)"; exit 1 ;;
esac
```

The exit codes are stable — see [Exit codes](#exit-codes).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `image digest must match ^sha256:[0-9a-f]{64}$` | `--image` was given a tag, not a digest. | Use the digest form: `ghcr.io/kerberosmansour/zaprun@sha256:<hex>`. Tags are intentionally rejected. |
| `target_scheme_unsupported: only http(s) targets are accepted` | `--target` is `file://`, `ws://`, etc. | Use `http://` or `https://`. |
| `unknown argument: zaprun` | The image's first arg didn't match the literal `zaprun`. Common when shell-quoting added a trailing newline or extra word. | Pass `zaprun` as a clean single argv element. The dispatch is literal-string-equality by design. |
| `scan timed out after Ns` | Default `--scan-timeout 8m` was too short for the target. | Pass `--scan-timeout 30m` (or longer). |
| `target unavailable` (exit 3) | Target's `/` returned non-2xx, or the host gateway resolution failed. | Run `zaprun doctor --probe-target <url>` first; check `--add-host=host.docker.internal:host-gateway` is set on the `docker run`. |
| `Permission denied` writing reports | The container runs as UID 1000; the host mount is owned by a different UID. | `mkdir -p output && chmod 0777 output` before `docker run -v "$PWD/output:/zap/wrk/output"`. |
| `WARNING: requested image's platform (linux/amd64) does not match the detected host platform (linux/arm64/v8)` | Running on an arm64 host (Apple Silicon). | Benign — the image runs fine via QEMU. Add `--platform linux/amd64` to suppress the warning if it bothers you. |

For anything else, the run's `plan.yaml` + `zap-report.json` are the canonical evidence; `summary.json` is the normalised view. Open an issue at https://github.com/kerberosmansour/zaprun/issues with those attached.
