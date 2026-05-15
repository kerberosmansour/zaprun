# Security — zaprun

> This file is the project-wide security defaults read by every downstream agent and human contributor before generating code or merging changes. User-provided strings in this document render inside `~~~text` fences so Markdown / YAML / HTML metacharacters are literal text, not interpretable.

## What this project is

~~~text
zaprun is a Rust runner + a hardened OWASP ZAP Docker image + a GitHub
Actions workflow template. It produces DAST scan artefacts (config files, a
hardened image, custom scan rules, manifest, SARIF reports) that downstream
projects consume to run reproducible DAST in CI.

zaprun is the orchestrator. It does not itself ingest user input over a
network, store secrets, serve HTTP, or process customer data. Its untrusted
inputs are all file-system content: a target repo's threat-model file, finding
docs, the curated cwe-to-rules.toml, and (transitively) HTTP responses from
the target service that the JVM scans during a run.
~~~

## Top risks (carried forward from the threat model)

~~~text
1. Breach: a tampered ZAP image runs as a privileged build step in many
   users' CI. If our ghcr.io/kerberosmansour/zaprun image is
   compromised, every consumer of the image runs attacker-controlled JVM
   code with `contents: read` access to their repo and (depending on the
   consumer's workflow design) other secrets.

2. Compliance fine: false DAST coverage claim. A team cites the manifest
   coverage ledger ("CWE-89 covered by ZAP rules 40018–40027") in a PCI
   DSS 6.2.3 (v4.0.1) or SOC 2 CC7.1 audit, but the rules never fired
   against the team's real attack surface. Auditor disproves.

3. Prolonged outage: nightly DOM-XSS scan OOMs the runner; team disables
   DAST. The Tier 3 nightly active scan is empirically tight for the
   GHA runner.
~~~

## Security defaults — non-negotiable

The following are baked into every artefact this project emits and every change to this project itself. Inherit these in any downstream consumer; deviate only with explicit `/slo-architect` review.

### Supply chain

- **Every `uses:` in any workflow we ship pins a 40-character SHA.** No tags, no branches, no short prefixes. The structural-contract test fixture rejects PRs that violate this.
- **Every Docker image we publish is referenced by `@sha256:<digest>` in consumer-facing examples and in the workflow template.** No `:latest`, no `:stable`, no version tags. **We do not publish `:latest`** at all.
- **Every Docker image we consume in our build (FROM lines, `docker/build-push-action` base images) is referenced by `@sha256:<digest>`.**
- **Every third-party scanner rule/template pack we consume is pinned by immutable source revision.** Nuclei templates are read only from `references/nuclei-templates-pinned-sha.toml`; no branch, tag, or live `HEAD` template checkout is permitted in CI.
- **Every published image carries SLSA L3 build provenance** via `actions/attest-build-provenance`. Consumers may verify with `cosign verify-attestation`; M5+ ships the verification gate as a workflow step.
- **`packages: write` token is scoped to the build/publish job only** in our own workflows. No other job in this repo has write access to `ghcr.io/kerberosmansour/zaprun`.
- **Bumping any pin (action SHA, image digest, ZAP upstream digest) is a PR-reviewed event.** Release automation opens image-pin bumps as PRs after a stable tag resolves to a signed digest. No silent drift.

### Workflow-emission discipline

Every `.github/workflows/dast.yml` we emit MUST satisfy:

- `on:` block contains `pull_request` and MUST NOT contain `pull_request_target`. **Hard ban.** No exceptions.
- Workflow-scope `permissions:` is `{}` (empty map).
- Per-job `permissions:` declares only what's needed: `contents: read` for analysis. **`issues: write` is never granted** — the upstream `zaproxy/action-baseline` auto-issue side effect is the canonical inheritance failure we refuse to repeat. `security-events: write` only on the SARIF-upload step (M3+).
- `actions/checkout` step uses `with: { fetch-depth: 0, persist-credentials: false }`.
- Every `docker run` includes `--user 1000:1000`.
- No `--autofix`, no `--severity`, no `--config` flags on `zap-*-scan.py` invocations.
- No `secrets.*` references in PR-event jobs. Production-target paths use `workflow_dispatch:` only.
- `concurrency:` block present with `cancel-in-progress: true`.
- `timeout-minutes:` present and ≤ 30 for PR scans, ≤ 60 for nightly.

These constraints are enforced in CI by structural-contract tests, which parse emitted YAML and assert each property individually.

### Container-runtime discipline

- Image runs as `USER 1000:1000`. **No `--privileged` flag** in any emitted workflow.
- `_JAVA_OPTIONS=-Xmx4g -Xss2m -XX:+UseG1GC -XX:MaxGCPauseMillis=200` baked into the entrypoint default; override only by environment.
- ZAP spider concurrency is bounded by default: `spider.thread=1` in PR and nightly policies. Active scanner thread bounds do not cover spider workers, so the spider budget is a separate policy invariant.
- DOM-XSS scanner (rule `40026`) is **disabled by default** in the image. Enable only via `ZAPRUN_DOM_XSS_ENABLED=1` (paired with baked-in `firefox-headless` by default, overrideable via `ZAPRUN_BROWSER_ID`, attack strength `LOW`, single-thread, internal-URL exclusions). PR scans use `policy-pr.yml` (Tier 1 passive heuristic + Tier 2 Retire.js); nightly scans use `policy-nightly.yml`.
- `globalexcludeurl` for known browser-internal hosts is baked into the image (defends against [zaproxy#7746](https://github.com/zaproxy/zaproxy/issues/7746)).
- The image carries a default ZAP permission policy that **denies JVM and GraalVM bridge access** from JS scripts: `Java.type`, `Polyglot.eval`, `org.graalvm.polyglot.*`, `Context.create`, and `Engine.create`. Custom scan rules cannot reach the underlying JVM or polyglot host APIs unless the user explicitly grants permission. (M5+: this is the load-bearing defence against `tm-dast-spike-abuse-6` — generated-rule poisoning.)

### Subprocess discipline (Rust runner)

- All subprocess invocations are argv-list form (`Command::new + .arg + .arg`). **No shell-string interpolation, ever.** Defends against the same class as `tm-scanner-orchestration-abuse-2 / SEC-6` in the SLO-sast pack.
- `gh` invocations: never `--repo`, never merge flags, no `gh auth login`, no `gh pr merge`. Inherited from `/slo-sast`.
- `git` invocations: never use `-c` to override config; never `--exec` style hooks; never `--no-verify`.

### Filesystem discipline

- Symlink-traversal defence on every write into `.zaprun/` and `.github/workflows/`. Every path component verified to be a directory, not a symlink, before any write. Refuse with clear stderr if any component is a symlink.
- File creation uses `O_NOFOLLOW`-equivalent semantics where the OS supports it.
- Cache directory location: per-digest under the user's XDG cache directory. Per-digest isolation means bumping the pin writes a sibling directory; older digests are never overwritten in place.

### Parser discipline

- **Threat-model parser**: regex `\bCWE-(\d+)\b` against rendered Markdown body only. HTML comments, fenced code blocks, and `~~~text` user-string fences are excluded. Inherited verbatim from `/slo-sast`'s `threat-model-parser-contract.md`.
- **Finding-doc parser**: serde-typed front-matter with `deny_unknown_fields`. Free-text body sections are read but only re-emitted into other artefacts inside `~~~text` fences.
- **`cwe-to-rules.toml` parser**: serde-typed with `deny_unknown_fields`; values constrained to closed enumerations or regex-validated strings. Free-text `note`/`wstg_ref` is fenced before any emission.
- **Manifest emission**: no free-text from threat-model prose, finding-doc prose, or curated-table notes flows into JSON. Only IDs, SHAs, and closed-enumeration values.
- **GitHub Step Summary emission**: every user-derived string rendered into GitHub summaries is placed inside a `~~~text` fence or equivalent context-specific Markdown escaping. No threat-model prose, finding-doc reason, or curated-table note may render as live Markdown.
- **YAML parsing**: `serde_yaml_ng` default settings — no entity expansion, no anchor recursion. Reject any individual YAML file > 1 MiB before parse. Defends against billion-laughs and similar.

### Custom-rule generation discipline (M5)

- Generated `getMetadata()` JS scan rules are validated by `xtasks/dast-verify gate` before commit. Required passes:
  - Schema validation (parses as valid JS, has a `getMetadata()` function returning the expected shape).
  - Lint check: no hard-coded URLs except `localhost`/`127.0.0.1`; no `Java.type`, `Polyglot.eval`, `org.graalvm.polyglot.*`, `Context.create`, or `Engine.create` access; no `eval(...)` on response data; no embedded Authorization tokens; no `XMLHttpRequest`/`fetch` to non-target hosts.
  - Red-then-green replay test: rule fires against a synthetic vulnerable mock, does NOT fire against a synthetic patched mock.
- Generated rules land in a PR for human review. The Rust gate is the necessary condition; PR review is the sufficient condition.
- **No autofix anywhere.** Same anti-pattern as `/slo-sast`. A compromised generated script must not be able to push edits back into the target repo.

### Compliance

- PCI compliance citations target **PCI DSS 6.2.3 (v4.0.1)**, never 6.3.2. v4.0.1 renumbered code-review from 6.3.2 to 6.2.3; v4.0.1's 6.3.2 is now the SBOM-inventory mandate (different scope, out of v1).
- `cwes_actually_covered` in the manifest is computed from rules that **fired at least once** in the last successful scan, not from rules that were *selected*.
- Coverage gaps surface explicitly in `manifest.coverage_gaps[]` with reasons. Never silently.

### PII / data handling

- `zaprun` does not log target HTTP responses. ZAP's report.json contains snippets of responses by design (evidence in alerts) — that file is uploaded as a workflow artefact and follows the consumer's retention policy. Documented limitation: do not run `zaprun` against production targets carrying PII; use staging/test targets only.
- The runner's logs (RUST_LOG=info default) carry only IDs, SHAs, rule names, and counts. No request bodies, no response bodies.

## Image tagging convention

The published image at `ghcr.io/kerberosmansour/zaprun` follows a strict tagging discipline:

| Tag form | Source | Stability |
|---|---|---|
| `@sha256:<64-hex>` | every push to main; every release | immutable — bound to a single OCI manifest |
| `:<full-git-sha>` | every push to main | immutable — added by `build-zap-image.yml` |
| `:edge` | every push to main | floating — re-points to the most recent main commit |
| `:vX.Y.Z` (e.g. `:v0.1.0`) | tag push `git push origin vX.Y.Z` | immutable per-release — added by `release.yml` |
| `:vX.Y` (e.g. `:v0.1`) | tag push (excluded for pre-releases) | floating — re-points to the latest patch on that minor |
| `:vX` (e.g. `:v0`) | tag push (excluded for pre-releases) | floating — re-points to the latest minor on that major |
| **`:latest`** | **NEVER PUBLISHED** | n/a |

**Pin by digest.** Consumers MUST pin to `ghcr.io/kerberosmansour/zaprun@sha256:<digest>` in CI, infrastructure, and image-pin files. The floating tags (`:edge`, `:vX.Y`, `:vX`) exist for ergonomic browsing, NOT for production pinning. The `zaprun` CLI's `--image` flag refuses non-digest references (`crates/zaprun/src/image_ref.rs`).

**Why no `:latest`.** The `:latest` convention is the single biggest cause of irreproducible CI image-pull behaviour; we never want a consumer to find a mystery `:latest` tag pointing at unknown content. Floating semver tags are the closest substitute and are bounded by explicit-versioned cadence.

**Provenance and signature verification.** Every published digest is signed (cosign keyless via Fulcio + Rekor) and carries three attestations (SLSA Build Provenance, SPDX-JSON SBOM, CycloneDX-JSON SBOM). To verify a digest:

```bash
# Signature
cosign verify \
  --certificate-identity-regexp '^https://github.com/kerberosmansour/zaprun/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/kerberosmansour/zaprun@sha256:<digest>

# Build provenance attestation (and SBOMs)
gh attestation verify \
  oci://ghcr.io/kerberosmansour/zaprun@sha256:<digest> \
  --repo kerberosmansour/zaprun
```

## Vulnerability disclosure

- Security issues should be reported privately. Open a [GitHub Security Advisory](https://github.com/kerberosmansour/zaprun/security/advisories/new) on this repo — **not** a public issue.
- We commit to acknowledging within 5 business days and providing an initial assessment within 15 business days.
- Coordinated disclosure preferred: 90 days from acknowledgement to public disclosure for high-severity issues, with extension by mutual agreement.

## Change management

- Every change to this `SECURITY.md` is a PR. Modifying the supply-chain or workflow-emission discipline sections is a contract change, not just an edit, and requires a second reviewer.

## Out of scope

- **WAF / RASP integration.** zaprun is the proxy; it does not replace WAFs.
- **Authenticated browser-form-based scanning** (vs API/JWT). v1 is API-first; M3+ may add via Zest record-and-replay if a real consumer pulls.
- **Non-Linux runners.** macOS / Windows are explicitly out of scope for v1.
- **Customer data in the target.** We document staging/test targets; production-with-PII is the user's responsibility.
- **Generic HTTP fuzzing.** Coverage is CWE-driven from the threat model; arbitrary fuzzing is a different problem we don't try to solve.

## See also

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — components, data flow, trust boundaries
