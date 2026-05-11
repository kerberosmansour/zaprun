# Architecture — zaprun

## At a glance

`zaprun` is a small Rust CLI plus a hardened OWASP ZAP Docker image plus a workflow template, designed to replace the fragile `zaproxy/action-*` GitHub Actions with a deterministic, digest-pinned DAST lane. The CLI drives ZAP through Automation Framework plans; the image bakes the CLI in; the workflow template wires both into a consumer's CI in a way that does not eval user-provided strings or hold long-lived registry credentials.

## Components

```
zaprun (this repo)
─────────────────────────
crates/zaprun           (the CLI — drives ZAP via Automation Framework plans)
crates/dast-spike       (orchestrator — wraps zaprun + nuclei + wapiti, manifest emission, baseline lifecycle)
crates/dast-spike-rules (curated CWE → scanner-rule mapping, typed schemas)
docker/zap              (Dockerfile + entrypoint + default policies)
templates/              (workflow YAML template)
tests/targets           (vulnerable-app registry — public OSS targets)
.github/workflows/      (own CI: build-zap-image.yml, ci.yml)

Consumer repo `.dast-spike/` directory (emitted by `dast-spike init`)
──────────────────────────────────────────────────────────────────
.dast-spike/
  ├── policy-pr.yml          (Tier 1 + 2 active rules; no Selenium)
  ├── policy-nightly.yml     (Tier 1 + 2 + 3; Selenium + Firefox-headless)
  ├── rules.tsv              (FAIL/WARN/IGNORE per ZAP rule)
  ├── baseline.json          (suppressions with `expires_at` half-life)
  ├── scripts/<cwe>-<…>.js   (custom getMetadata() rules)
  ├── manifest.json          (coverage ledger)
  └── zap-image-pin          (digest of the zaprun image)
.github/workflows/dast.yml   (PR + nightly; SHA-pinned, `--user 1000:1000`)
```

## Data flow (PR-blocking lane)

```
   developer commits
        │
        ▼
   GitHub Actions runner (ubuntu-latest)
        │
        │  start target (vendored binary or docker image, pinned)
        │  target listens on 127.0.0.1:<port>
        │
        │  dast-spike scan --target <url> --image <repo>@<digest>
        │    │
        │    ├─ load .dast-spike/policy-pr.yml + rules.tsv + baseline.json
        │    ├─ build replacer config (auth header) → /tmp/replacer.conf
        │    ├─ rewrite OpenAPI host: 127.0.0.1 → host.docker.internal
        │    ├─ docker run --user 1000:1000
        │    │     --add-host=host.docker.internal:host-gateway
        │    │     -v output:rw -v scripts:ro -v openapi:ro -v policy:ro
        │    │     ghcr.io/kerberosmansour/zaprun@sha256:<digest>
        │    │     dast-spike-entrypoint
        │    │
        │    └─ wait, capture output/zap-report.json + run-summary.json
        │
        ▼
   dast-spike check
        │  parse report, apply baseline (with expires_at gate),
        │  emit SARIF + GitHub Step Summary, exit 0/1
        ▼
   actions/upload-artifact (own pinned step) → zap-report
        │
        ▼
   PR status: pass/fail
```

## Trust boundaries

| Boundary | Direction | Mediation |
|---|---|---|
| `dast-spike` CLI → target repo filesystem | read / write | Symlink-traversal defence; writes only to `.dast-spike/` and `.github/workflows/` of the target. |
| `dast-spike` CLI → Docker daemon (local) | RPC | Image is digest-pinned; argv-list invocation (no shell interpolation). |
| Our Docker image → Wolfi base + official ZAP release assets | pull at build time | Base image digest-pinned; release tarball + helper scripts SHA-256-checked in the Dockerfile. |
| Consumer workflow → our published image | pull | `@sha256:<digest>` enforced by the CLI's `--image` parsing; SLSA Build Provenance attestation available. |
| ZAP container → target service under test | network (Docker bridge) | Local-only; target binds 127.0.0.1; ZAP container reaches it via `host.docker.internal`. |
| GHA runner → consumer's repo | inbound | `pull_request` only; never `pull_request_target`; analysis job runs with `permissions: contents: read` and no `issues: write`. |
| Image entrypoint argv | inbound | Literal-string-equality dispatch (`if [ "${1:-}" = "zaprun" ]; then …`). No regex, no case-fold, no `eval`. Unknown first-arg falls through to a legacy entrypoint that rejects with `unknown argument: <arg>`. |

## Component responsibilities

### `crates/zaprun` (Rust CLI)

The deterministic ZAP driver. Subcommands: `doctor`, `plan`, `scan <url> --active`, `api <spec> --target … --active`, `observe`, `calibrate`, `explain`. Every successful run writes the same artifact set under `--output`:

| File | Schema | Contents |
|---|---|---|
| `plan.yaml` | ZAP Automation Framework | The exact plan ZAP executed. |
| `run.json` | v1.0 | Run metadata: image digest, per-run API-key envelope, target, exit code. |
| `summary.json` | v1.0 | Normalised finding summary: severity counts + samples. |
| `coverage.json` | v1.0 | Coverage ledger: URLs discovered vs scanned. |
| `capabilities.json` | v1.0 | Doctor pre-flight result: backend, image, browser support. |
| `observations.json` | v1.0 | `observe`-mode replay record. |
| `zap-report.{json,html}` | ZAP traditional | Raw ZAP report (kept verbatim alongside the normalised summary). |
| `zap.sarif` | SARIF 2.1.0 | For GitHub Code Scanning + other SARIF consumers. |

Stable exit codes: `0 pass | 1 policy fail | 2 tool error | 3 target unavailable | 4 timeout | 5 coverage fail`.

The active-scan policy used by `api` is inlined into the AF plan as a SHA-256-pinned Rust constant (`API_MINIMAL_POLICY_INLINE`), so there is no dependency on `zap-api-scan.py`, `zap-baseline.py`, `zap-full-scan.py`, `~/.ZAP/policies/*.policy`, or `.ZAP_D` at scan time.

Per-run 32-byte cryptographically-random ZAP API key, wrapped in `secure_data::SecretString`, persisted to `run.json` at file mode `0600`. Log-injection-resistant tracing mirror via `security_events::sanitize::sanitize_for_text_sink`; the raw `zap.log` is retained verbatim for forensic analysis. SSRF / IMDS guard on `observe --target` (link-local `169.254/16` unconditionally refused; RFC1918 + loopback refused unless `--allow-internal-target`); `--target` for `scan` uses scheme-only validation because loopback is the headline scan target in CI.

TLS via `rustls-tls` only — no `native-tls` features pulled.

### `crates/dast-spike` (Rust binary)

The orchestrator. Owns scan invocation, baseline lifecycle, manifest emission, finding triage, regression-rule generation, image-bump, and the structural-contract test harness for the workflow template.

### `crates/dast-spike-rules` (library)

Schemas + parsers for every artefact: `cwe-to-rules.toml`, manifest, baseline, finding doc. No I/O; pure data.

### `docker/zap/` (Dockerfile + entrypoint + default policies)

Builds `ghcr.io/kerberosmansour/zaprun`. Wolfi base (digest-pinned), OpenJDK plus the official ZAP release tarball (SHA-256-pinned), checksum-pinned ZAP Docker helper scripts, the `API-Minimal` active-scan policy payload, optional add-ons that fail extracted-archive vulnerability scans excluded, checksum-pinned patched add-on replacements where ZAP core bundles stale copies. Layers UID 1000, default policies (`policy-pr.yml`, `policy-nightly.yml`), the Tier 1 passive DOM-XSS heuristic script, the entrypoint that gates Tier 3 behind `DAST_SPIKE_DOM_XSS_ENABLED=1`, and `_JAVA_OPTIONS=-Xmx4g -XX:+UseG1GC -Xss2m`.

### `templates/dast-workflow.yml`

Static workflow skeleton. Substituted only by action SHAs (40-char hex) and image digest (`^sha256:[0-9a-f]{64}$`). User-provided strings (slugs, threat-model content, finding-doc prose) NEVER flow in.

### `tests/targets/`

Test-target registry. Each target declares an image / build command, a health URL, and an expected high-finding range; drift is a test failure.

### `.github/workflows/build-zap-image.yml`

Our publish workflow. On every push to `main`, rebuilds, smoke-tests, scans the base image, scans the final image, extracts `.zap` add-ons for a second Trivy filesystem scan, and pushes `ghcr.io/kerberosmansour/zaprun:<git-sha>` with SLSA Build Provenance via `actions/attest-build-provenance`. **No `:latest` tag is published.** Consumers MUST pin by digest.
