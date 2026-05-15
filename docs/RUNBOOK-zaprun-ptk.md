# OWASP PTK Integration — zaprun (AI-First Runbook v4)

> **Purpose**: Add OWASP PTK Phase 1 support to the hardened zaprun image and expose it through a safe, typed `zaprun` CLI lane.
> **Audience**: AI coding agents first, humans second.
> **Core philosophy**: Prefer automated guardrails over developer intention. Prefer direct inspection over guessing. Prefer executable assumptions over comments. Prefer bounded design over silent growth. Prefer evidence over claims.
> **How to use**: Work through milestones sequentially. Before each milestone, complete the Global Entry Protocol. After each, complete the Global Exit Protocol. Never skip ahead. Never silently widen scope. Treat this document as an execution contract.
> **Prerequisite reading**: [ARCHITECTURE.md](../ARCHITECTURE.md), [README.md](../README.md), [SECURITY.md](../SECURITY.md), [OWASP PTK Phase 1 ZAP blog](https://www.zaproxy.org/blog/2026-05-06-automating-owasp-ptk-with-zap-phase-1/), [OWASP PTK add-on docs](https://www.zaproxy.org/docs/desktop/addons/owasp-ptk/), [Client Side Integration automation docs](https://www.zaproxy.org/docs/desktop/addons/client-side-integration/automation/).

---

## 1. Runbook Metadata

| Field | Value |
|---|---|
| Runbook ID | `zaprun-ptk` |
| Project name | `zaprun` |
| Primary stack | Rust CLI + typed ZAP Automation Framework YAML + Docker/Wolfi hardened ZAP image |
| Primary package/app names | `crates/zaprun`, `docker/zap` |
| Prefix for tests and lesson files | `zaprun-ptk` |
| Default unit test command | `cargo test -p zaprun` |
| Default integration/BDD test command | `cargo test --workspace` |
| Default E2E/runtime validation command | `docker buildx build -f docker/zap/Dockerfile --load -t zaprun:ptk-local .` then targeted Docker smoke |
| Default build/boot command | `cargo build -p zaprun --release --locked` |
| Default formatter command | `cargo fmt --all -- --check` |
| Default static analysis / lint command | `cargo clippy --workspace --all-targets -- -D warnings` |
| Default dependency / security audit command | Build ZAP Image workflow Trivy scans; local fallback `cargo publish -p zaprun --dry-run --allow-dirty` for crate packaging |
| Default debugger or state-inspection tool | `cargo test -- --nocapture`, `docker run --entrypoint /opt/zap/zap.sh`, `docker logs`, generated `output/*/zap.log` |
| Allowed new dependencies by default | none |
| Schema/config migration allowed by default | no |
| Public interfaces stable by default | yes |

### Public interfaces that must remain stable unless explicitly listed otherwise

- `zaprun scan <url>`: existing active/passive web scan contract.
- `zaprun api <spec> --target <url>`: existing OpenAPI scan contract.
- `zaprun ptk <url>`: new PTK Phase 1 browser-backed scan lane.
- `zaprun doctor`, `zaprun plan`, `zaprun observe`, `zaprun calibrate`, `zaprun init`, `zaprun rederive`, `zaprun triage-sarif`, `zaprun explain`: existing CLI surface.
- `--image <repo>@sha256:<64-hex>`: digest-only image reference parser.
- Artifact contract: `plan.yaml`, `run.json`, `summary.json`, `coverage.json`, `capabilities.json`, `zap-report.json`, `zap-report.html`, `zap.sarif`.
- Image entrypoint dispatch: first argument `zaprun` invokes `/usr/local/bin/zaprun`; otherwise compatibility scan harness.
- Docker runtime invariants: `USER 1000:1000`, no live add-on installs at scan time, no `:latest` image tag requirement, checksum-pinned upstream downloads.

---

## 2. Milestone Tracker

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 1 | Bake PTK and Client Side Integration into the image | `done` | 2026-05-15 | 2026-05-15 | `docs/slo/lessons/zaprun-ptk-m1.md` | `docs/slo/completion/zaprun-ptk-m1.md` |
| 2 | Add typed Automation Framework support for Client Spider + PTK config | `done` | 2026-05-15 | 2026-05-15 | `docs/slo/lessons/zaprun-ptk-m2.md` | `docs/slo/completion/zaprun-ptk-m2.md` |
| 3 | Add `zaprun ptk` CLI and PTK artifact normalization | `done` | 2026-05-15 | 2026-05-15 | `docs/slo/lessons/zaprun-ptk-m3.md` | `docs/slo/completion/zaprun-ptk-m3.md` |
| 4 | Add PTK E2E, docs, and release readiness gates | `done` | 2026-05-15 | 2026-05-15 | `docs/slo/lessons/zaprun-ptk-m4.md` | `docs/slo/completion/zaprun-ptk-m4.md` |

<!-- Completed 2026-05-15. -->

---

## 3. End-to-End Architecture Diagram

```text
Existing:
  User / CI
    |
    | zaprun scan/api/doctor/...
    v
  crates/zaprun CLI
    |
    | typed Automation Framework plan.yaml
    v
  DockerBackend
    |
    | docker run --entrypoint /opt/zap/zap.sh <digest>
    v
  hardened zaprun image
    |
    | ZAP spider / Ajax spider / active scan
    v
  target app

Implemented:
  User / CI
    |
    | zaprun ptk <url>
    v
  crates/zaprun CLI
    |
    | typed AF plan with spiderClient + PTK configs
    v
  DockerBackend
    |
    | docker run --entrypoint /opt/zap/zap.sh <digest>
    v
  hardened zaprun image
    |
    | baked Client Side Integration + PTK add-ons
    v
  browser-backed Client Spider
    |
    | PTK Phase 1 automated SAST/IAST/DAST rules
    v
  ZAP alert model -> zap-report.json/html, summary.json, coverage.json, zap.sarif

Legend:
  Existing lines describe current zaprun behavior.
  Implemented lines describe new PTK Phase 1 behavior.
  Trust boundary: User/CI and target-controlled URLs enter only through typed CLI args and validated image refs.
```

### Component Summary Table

| Component | Responsibility | Existing/New/Changed | Milestone | Key Interfaces |
|---|---|---|---|---|
| `docker/zap/Dockerfile` | Build hardened image with pinned ZAP assets and baked add-ons | changed | M1 | add-on downloads, checksum args, image smoke |
| `crates/zaprun/src/plan.rs` | Emit typed Automation Framework YAML | changed | M2 | `Plan`, `Job`, `Plan::to_yaml` |
| `crates/zaprun/src/cli.rs` | Public CLI surface | changed | M3 | new `zaprun ptk` command |
| `crates/zaprun/src/ptk.rs` | PTK orchestration and artifact shaping | new | M3 | `PtkOptions`, `cmd_ptk` |
| `crates/zaprun/src/coverage.rs` and report modules | Coverage/report normalization | changed | M3 | `coverage.json`, `summary.json`, `zap.sarif` |
| Docs and workflows | Explain and verify PTK release behavior | changed | M4 | README, crate README, build image workflow |

### Data Flow Summary

| Flow | From | To | Protocol/Mechanism | Bounded? | Failure Mode | Milestone |
|---|---|---|---|---|---|---|
| Add-on acquisition | Docker build | ZAP extension release assets | HTTPS + SHA-256 verification | yes | build fails before image export | M1 |
| PTK plan emission | `zaprun ptk` | `plan.yaml` | typed Rust serialization | yes, max jobs still applies | CLI exits 2 before Docker | M2/M3 |
| Browser-backed crawl | ZAP Client Spider | target URL | browser automation through ZAP | yes, duration and browser count flags | coverage failure or ZAP non-zero exit | M3 |
| PTK findings | PTK add-on | ZAP alert model | ZAP internal alert storage -> report job | yes, reports under `--output` | policy fail when high alerts exist | M3 |
| Runtime artifacts | Docker mount | host output dir | mounted `/zap/wrk` | yes, directory canonicalized | structured `ZapshootError` | M3/M4 |

---

## 4. Global Entry Protocol

Before starting any milestone:

1. Read this runbook and the prerequisite docs listed at the top.
2. Run `git status -sb`; do not mix unrelated work.
3. Confirm whether `output/` contains local scan artifacts only and remains ignored.
4. Read the milestone's Files to read before changing.
5. Write or update the milestone's tests before implementation when behavior changes.
6. Confirm no credential, cookie, browser-storage, or private target material will be committed.

## 5. Global Exit Protocol

After each milestone:

1. Run the milestone-specific tests.
2. Run `cargo fmt --all -- --check`.
3. Run `cargo clippy --workspace --all-targets -- -D warnings` unless the milestone is docs-only.
4. Run `cargo test -p zaprun` unless the milestone is docs-only.
5. Fill the milestone Evidence Log before marking it complete.
6. Update the Milestone Tracker status, lessons file, and completion summary.

---

## 6. Milestone 1 — Bake PTK and Client Side Integration Into the Image

### Goal

The hardened zaprun image contains checksum-pinned PTK and Client Side Integration add-ons, and CI proves those add-ons are present without live runtime installation.

### Context

The ZAP Phase 1 PTK blog shows PTK automation through Client Spider, enabled via Automation Framework config such as `ptk.automatedScanning.enabled`. This repo already bakes ZAP, helper scripts, policies, and selected add-ons into `docker/zap/Dockerfile`; scans must not install add-ons at runtime. This milestone is intentionally image-only: it does not add a public CLI command yet.

### Important design rule

PTK add-ons are build-time supply-chain inputs, not runtime side effects. Every new `.zap` file must be downloaded from an explicit upstream URL with a pinned SHA-256 and then verified by smoke tests.

### Refactor budget

No refactor permitted beyond direct implementation.

### Contract Block

| Field | Contract |
|---|---|
| Inputs | ZAP blog guidance for PTK Phase 1; ZAP add-on release URLs; current `docker/zap/Dockerfile`; current build image workflow |
| Outputs | Hardened image includes PTK and Client Side Integration add-ons; image smoke test verifies add-on presence |
| Interfaces touched | Docker image contents; `.github/workflows/build-zap-image.yml` smoke steps; optional `crates/zaprun/assets/zap-image-pin.toml` metadata |
| Files allowed to change | `docker/zap/Dockerfile`; `.github/workflows/build-zap-image.yml`; `crates/zaprun/tests/e2e_image_build_contract.rs`; `crates/zaprun/assets/zap-image-pin.toml`; `README.md`; `crates/zaprun/README.md`; `CHANGELOG.md` |
| Files to read before changing | `docker/zap/Dockerfile`; `.github/workflows/build-zap-image.yml`; `.trivyignore`; `SECURITY.md`; `crates/zaprun/tests/e2e_image_build_contract.rs` |
| New files allowed | none unless a tiny checked-in manifest is needed under `crates/zaprun/assets/` |
| New dependencies allowed | No Rust dependencies. Docker image may add only ZAP add-on `.zap` archives needed for PTK Phase 1, each URL and SHA-256 pinned |
| Migration allowed | No |
| Compatibility commitments | Existing `zaprun scan`, `zaprun api`, image entrypoint dispatch, UID 1000, and no-live-add-on-install policy remain unchanged |
| Forbidden shortcuts | No `zap.sh -addoninstall`; no tag-only add-on URL without checksum; no disabling Trivy scans to pass; no broad `.trivyignore` for PTK dependencies without a specific upstream issue and expiry; no public `zaprun ptk` command in M1 |
| Exemplar code to copy | Existing `ZAP_NETWORK_ADDON_VERSION`, `ZAP_NETWORK_ADDON_SHA256`, `curl -fsSL`, and `sha256sum -c -` pattern in `docker/zap/Dockerfile` |
| Anti-exemplar code not to copy | The blog's demo-style runtime `-addoninstall ptk` command; it is appropriate for exploration, not zaprun's sealed CI image |
| Refactoring discipline | N/A — no refactor permitted beyond direct implementation |
| AI tolerance contract | N/A — no AI component |
| Data classification | Public — image manifest, release metadata, docs, and CI smoke commands |
| Proactive controls in play | C1 Define Security Requirements; C2 Leverage Security Frameworks and Libraries by using official ZAP add-on artifacts; C8 Protect Data Everywhere via pinned digests and existing image signing/attestation path; C10 Handle Errors by failing image build on checksum mismatch |
| Abuse acceptance scenarios | See BDD row `runtime_addon_install_blocked`; threat row `tm-zaprun-ptk-abuse-1` |

### Out of Scope / Must Not Do

- Do not add `zaprun ptk` yet.
- Do not change scan behavior for `web-pr` or `spa-pr`.
- Do not change default image digest selection in `scan_url.rs`.
- Do not attempt PTK authentication, custom rule tuning, or SAST SARIF mapping.

### Files Allowed to Change

| File | Planned change |
|---|---|
| `docker/zap/Dockerfile` | Add PTK and Client Side Integration add-on version/URL/SHA args and verified downloads |
| `.github/workflows/build-zap-image.yml` | Add smoke checks that the add-ons are present and loadable |
| `crates/zaprun/tests/e2e_image_build_contract.rs` | Add structural assertions that PTK add-ons are baked, not runtime-installed |
| `crates/zaprun/assets/zap-image-pin.toml` | Record add-on versions and digests if this repo keeps pin metadata here |
| `README.md`, `crates/zaprun/README.md`, `CHANGELOG.md` | Mention image-level PTK groundwork only |

### Step-by-Step

1. Resolve exact PTK and Client Side Integration add-on release assets and SHA-256 values from official ZAP extension releases.
2. Add Dockerfile ARGs for version, URL, and SHA-256 for each required add-on.
3. Download each add-on into `/opt/zap/plugin/` during `zap-install`, checking `sha256sum -c -`.
4. Preserve existing removal/replacement logic for stale bundled add-ons; do not delete unrelated plugins.
5. Add workflow smoke that proves `/opt/zap/plugin/*ptk*.zap` and Client Side Integration add-ons exist.
6. Add a ZAP CLI smoke that fails if ZAP cannot start with the baked add-ons.
7. Add contract tests asserting no runtime `-addoninstall ptk` or `addOns install: [ptk]` pattern is introduced.
8. Build the image locally and run the new smoke commands.
9. Run Trivy scans and inspect any PTK-introduced CVEs before deciding on exclusions.
10. Update docs/changelog with the image-only groundwork.

### BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then | Threat-model row | Control |
|---|---|---|---|---|---|---|
| `ptk_addons_are_baked` | happy path | a local Docker build of `docker/zap/Dockerfile` | the image exports successfully | `/opt/zap/plugin/` contains PTK and Client Side Integration add-on archives with pinned versions | N/A | checksum-pinned build inputs |
| `checksum_mismatch_fails_build` | dependency failure | a PTK add-on SHA in the Dockerfile is wrong | Docker reaches the `sha256sum -c -` step | the build fails before the final image is produced | `tm-zaprun-ptk-abuse-2` | SHA-256 verification |
| `runtime_addon_install_blocked` | abuse case | a contributor attempts to add runtime PTK install using `zap.sh -addoninstall ptk` or AF `addOns install` | contract tests inspect Dockerfile/workflow/plan code | tests fail and no runtime add-on install path is accepted | `tm-zaprun-ptk-abuse-1` | sealed image invariant; structural test |
| `existing_image_smokes_still_pass` | backward compatibility | the image now contains PTK | the existing image smoke job runs Java/ZAP versions, CLI help, UID, entrypoint injection guard, and scanner helper checks | all existing smoke checks still pass unchanged | N/A | compatibility suite |
| `trivy_reports_reviewed` | security gate | PTK add-ons introduce Java dependencies | Trivy scans final image and extracted `.zap` files | build passes or each finding has a narrow documented exception with upstream context | `tm-zaprun-ptk-abuse-3` | image vulnerability scanning |

### Regression Tests

- `cargo test -p zaprun --test e2e_image_build_contract`
- `cargo test -p zaprun`
- `cargo test --workspace`
- `.github/workflows/build-zap-image.yml` on PR

### Compatibility Checklist

- [x] `zaprun scan` behavior unchanged.
- [x] `zaprun api` behavior unchanged.
- [x] Existing Docker entrypoint behavior unchanged.
- [x] Image still runs as UID 1000.
- [x] No live add-on installation at scan time.
- [x] No new Rust dependency added.

### E2E Runtime Validation

Build locally:

```bash
docker buildx build -f docker/zap/Dockerfile --load -t zaprun:ptk-local .
```

Then run:

```bash
docker run --rm --entrypoint /opt/zap/zap.sh zaprun:ptk-local -version
docker run --rm --entrypoint sh zaprun:ptk-local -c 'ls /opt/zap/plugin | grep -Ei "ptk|client"'
docker run --rm zaprun:ptk-local zaprun --version
```

Pass criteria:

- ZAP starts.
- PTK and Client Side Integration add-on archives are present.
- Existing `zaprun --version` smoke still works.

### Smoke Tests

- Inspect `/opt/zap/plugin` in the image.
- Confirm the CI smoke output references PTK add-on presence.
- Confirm `docker run --rm zaprun:ptk-local zaprun --help` lists the existing commands plus the new `ptk` lane.

### Evidence Log

| Check | Command | Expected Result | Actual Result | Evidence Path |
|---|---|---|---|---|
| Contract test | `cargo test -p zaprun --test e2e_image_build_contract` | pass | pass, 6 tests | local command output |
| Image build | `docker buildx build -f docker/zap/Dockerfile --load -t zaprun:ptk-local .` | pass | pass, image digest `sha256:9521117fa4a0f487e8165e4af7ebb5037bf2b5048a5de5d18d3e9564c9ac58ef` | local Docker image |
| Add-on smoke | `docker run --rm --entrypoint sh zaprun:ptk-local -c 'ls /opt/zap/plugin | grep -Ei "ptk|client"'` | pass | pass; `client-alpha-0.24.0.zap` and `ptk-alpha-0.4.0.zap` present; `quickstart` absent | local command output |
| ZAP start smoke | `docker run --rm --entrypoint /opt/zap/zap.sh zaprun:ptk-local -version` | pass | pass, ZAP `2.17.0` | local command output |
| Full Rust tests | `cargo test -p zaprun` | pass | pass | local command output |

### Definition of Done

- [x] PTK and Client Side Integration add-ons are baked into the image.
- [x] Every new add-on artifact has version, URL, and SHA-256 pinned.
- [x] No runtime add-on installation is introduced.
- [x] Image smoke proves add-on presence and ZAP startup.
- [x] Existing `zaprun` image smoke remains green.
- [x] Docs/changelog describe image-level groundwork without promising public CLI support yet.
- [x] Evidence Log is filled.

---

## 7. Milestone 2 — Add Typed Automation Framework Support for Client Spider + PTK Config

### Goal

`crates/zaprun/src/plan.rs` can emit a valid, typed ZAP Automation Framework plan for PTK Phase 1: Client Spider plus PTK automation config, without accepting handwritten YAML or enabling runtime add-on installs.

### Context

M1 bakes PTK and Client Side Integration into the image. M2 is the Rust plan layer that makes PTK representable by zaprun, while keeping public CLI behavior unchanged until M3. The ZAP blog's Phase 1 example uses Client Spider and `ptk.automatedScanning.enabled: true`; those need to be encoded as typed Rust state, not ad hoc string concatenation.

### Important design rule

Make invalid PTK plans unrepresentable: PTK config can only be emitted through a typed `PtkConfig`, and Client Spider plans must keep bounded browser count and duration.

### Refactor budget

Small local refactor allowed only inside the plan serializer and its tests, if needed to add `env.configs` cleanly.

### Contract Block

| Field | Contract |
|---|---|
| Inputs | M1 image capability; ZAP Client Side Integration Automation Framework docs; PTK add-on docs; existing `Plan`, `Job`, and `Plan::to_yaml` implementation |
| Outputs | Typed plan support for `spiderClient`; typed PTK config under `env.configs`; serialization tests covering Phase 1 plan shape |
| Interfaces touched | Internal Rust plan API only: `Plan`, `Env`, `Job`, `PlanBuilder`, `Plan::to_yaml` |
| Files allowed to change | `crates/zaprun/src/plan.rs`; `crates/zaprun/tests/unit_plan_serialization.rs`; optional new `crates/zaprun/tests/unit_ptk_plan_serialization.rs`; `docs/RUNBOOK-zaprun-ptk.md` Evidence Log only |
| Files to read before changing | `crates/zaprun/src/plan.rs`; `crates/zaprun/src/scan_url.rs`; `crates/zaprun/src/scan_api.rs`; `crates/zaprun/tests/unit_plan_serialization.rs`; `crates/zaprun/tests/unit_plan_ci_refuses_addons.rs` |
| New files allowed | At most one focused unit test file under `crates/zaprun/tests/` |
| New dependencies allowed | none |
| Migration allowed | No schema migration. Existing plan YAML remains compatible for `scan`, `api`, and `plan` |
| Compatibility commitments | Existing `Plan::to_yaml` output for current jobs remains semantically unchanged; `AddOns` runtime-install guard remains intact; `MAX_JOBS` still applies |
| Forbidden shortcuts | No raw YAML fragments; no `serde_json::json!` blobs passed from callers for arbitrary config; no `HashMap<String, String>` for unbounded PTK keys in M2; no public CLI flag yet; no runtime add-on install job |
| Exemplar code to copy | Existing typed `Job::AjaxSpider` and `job_to_yaml` match arms in `crates/zaprun/src/plan.rs`; existing serialization tests in `crates/zaprun/tests/unit_plan_serialization.rs` |
| Anti-exemplar code not to copy | Handwritten user-derived Automation Framework YAML; generic stringly `addOns` install jobs; unbounded `env.configs` maps sourced from CLI input |
| Refactoring discipline | Follow `references/refactoring-discipline.md`: behavior-preserving microsteps, pre-test evidence from current plan tests, post-test proof after each plan serializer change |
| AI tolerance contract | N/A — no AI component |
| Data classification | Public — typed plan structs and public scan configuration only |
| Proactive controls in play | C5 Validate All Inputs by typed enum/config constructors; C10 Handle Errors via `PlanError` rather than malformed YAML; C1 Define Security Requirements via this runbook and the no-runtime-add-on invariant |
| Abuse acceptance scenarios | See BDD rows `runtime_addon_job_rejected` and `unbounded_ptk_config_rejected`; threat rows `tm-zaprun-ptk-abuse-1` and `tm-zaprun-ptk-abuse-4` |

### Out of Scope / Must Not Do

- Do not add the public `zaprun ptk` command.
- Do not run Docker or PTK E2E in this milestone except optional manual plan inspection.
- Do not add arbitrary user-provided PTK key/value config.
- Do not change `scan_url.rs` behavior for `web-pr` or `spa-pr`.
- Do not update default image digest or release docs.

### Files Allowed to Change

| File | Planned change |
|---|---|
| `crates/zaprun/src/plan.rs` | Add typed `EnvConfig` / `PtkConfig` support and `Job::SpiderClient` serialization |
| `crates/zaprun/tests/unit_plan_serialization.rs` | Assert existing plan shapes still serialize and PTK plan serializes deterministically |
| `crates/zaprun/tests/unit_ptk_plan_serialization.rs` | Optional focused tests if existing file becomes too broad |
| `docs/RUNBOOK-zaprun-ptk.md` | Evidence Log updates only after execution |

### Step-by-Step

1. Add failing serialization tests for a PTK Phase 1 plan containing `spiderClient` and PTK config keys.
2. Add a typed `PtkConfig` with explicit booleans for `automated_scanning`, `sast`, `iast`, and `dast`.
3. Extend `Env` / YAML emission to include optional `configs` while omitting it for existing plans.
4. Add `Job::SpiderClient` with `url`, `browser_id`, `max_duration_seconds`, and `number_of_browsers`.
5. Enforce bounds: `number_of_browsers` must be 1 by default and tests must cover nonzero bounded behavior if constructor validation exists.
6. Keep `AddOns` CI rejection unchanged and add a regression assertion if needed.
7. Verify existing `scan`, `api`, and `plan` unit tests pass without snapshot churn.
8. Run formatter, clippy, and zaprun tests.
9. Update only the M2 Evidence Log.

### BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then | Threat-model row | Control |
|---|---|---|---|---|---|---|
| `ptk_phase1_plan_serializes` | happy path | a typed plan with one context, PTK config enabled, and `Job::SpiderClient` | `Plan::to_yaml` serializes the plan | YAML contains `spiderClient` and explicit `ptk.automatedScanning.enabled: true` config without raw fragments | N/A | typed serializer |
| `existing_scan_plan_unchanged` | backward compatibility | the existing `web_pr_active_plan` and `spa_pr_active_plan` paths | tests serialize or execute them | generated YAML remains accepted by existing unit tests and does not include PTK config | N/A | regression tests |
| `runtime_addon_job_rejected` | abuse case | a contributor tries to model PTK by adding AF `addOns install: [ptk]` in CI mode | `PlanBuilder::build` validates the plan | build returns `PlanError::AddonUpdateInCi` or equivalent and no runtime install YAML is emitted | `tm-zaprun-ptk-abuse-1` | CI add-on install guard |
| `unbounded_ptk_config_rejected` | abuse case | a future caller attempts to pass arbitrary PTK config keys from user input | the typed plan API is inspected and tested | only explicit PTK booleans are accepted in M2; arbitrary key/value config cannot be represented | `tm-zaprun-ptk-abuse-4` | typed `PtkConfig` |
| `empty_context_still_rejected` | empty state | a PTK plan has no context | `PlanBuilder::build` runs | it returns the existing `EnvNoContexts` error | N/A | existing plan invariant |
| `too_many_jobs_still_rejected` | resource bound | a PTK plan is built with more than `MAX_JOBS` jobs | `PlanBuilder::build` runs | it returns `PlanError::TooManyJobs` | N/A | `MAX_JOBS` |

### Regression Tests

- `cargo test -p zaprun --test unit_plan_serialization`
- `cargo test -p zaprun --test unit_plan_ci_refuses_addons`
- `cargo test -p zaprun`
- `cargo test --workspace`

### Compatibility Checklist

- [x] Existing plan tests pass.
- [x] Existing scan/API plan generation remains unchanged.
- [x] No public CLI command was introduced during M2; `zaprun ptk` was introduced later in M3 after explicit end-to-end approval.
- [x] No runtime add-on install is introduced.
- [x] No arbitrary config map accepts user-provided PTK keys.
- [x] `MAX_JOBS` and empty-context validation still pass.

### E2E Runtime Validation

Runtime validation is intentionally limited in M2. Produce a plan serialization artifact through a unit test or temporary test fixture only; do not run PTK yet.

Pass criteria:

- Unit test asserts the PTK YAML shape expected by the ZAP docs.
- Existing runtime scan tests still pass.

### Smoke Tests

- Run `cargo test -p zaprun --test unit_plan_serialization -- --nocapture` when debugging plan output.
- Manually inspect serialized YAML only if a test fails; do not commit generated scratch YAML.

### Evidence Log

| Check | Command | Expected Result | Actual Result | Evidence Path |
|---|---|---|---|---|
| PTK plan serialization | `cargo test -p zaprun --test unit_plan_serialization ptk` | pass | pass | local command output |
| Runtime-install guard | `cargo test -p zaprun --test unit_plan_ci_refuses_addons` | pass | pass | local command output |
| Full zaprun tests | `cargo test -p zaprun` | pass | pass | local command output |
| Workspace tests | `cargo test --workspace` | pass | pass | local command output |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | pass | pass | local command output |

### Definition of Done

- [x] PTK Phase 1 plan shape is representable through typed Rust APIs.
- [x] Existing plan output remains compatible.
- [x] Runtime add-on install is still structurally blocked.
- [x] Tests cover `spiderClient`, PTK config keys, empty context, too many jobs, and add-on install rejection.
- [x] Public CLI command intentionally added in M3 after user-requested end-to-end execution.
- [x] Evidence Log is filled.

---

## 8. Completed Milestones 3 and 4

The original runbook stopped after M2 and required confirmation before M3/M4. On 2026-05-15, the user explicitly requested end-to-end execution, including a NodeGoat scan with the updated PTK-aware CLI and image. M3/M4 were therefore executed in the same pass.

### Milestone 3 — Add `zaprun ptk` CLI and PTK Artifact Normalization

Status: `done`

Completed scope:

- Added `zaprun ptk <url>` as a distinct Phase 1 lane.
- Generated Client Spider + PTK plans through typed Rust plan APIs.
- Ran PTK through `DockerBackend` with digest-only image references.
- Wrote PTK-aware `summary.json`, `coverage.json`, `zap-report.*`, and `zap.sarif`.

Evidence:

| Check | Command | Expected Result | Actual Result | Evidence Path |
|---|---|---|---|---|
| PTK dry-run E2E | `cargo test -p zaprun --test e2e_zaprun_ptk_yaml_only` | pass | pass | local command output |
| CLI help smoke | `docker run --rm zaprun:ptk-local zaprun ptk --help` | pass | pass | local command output |
| PTK plan output | `zaprun ptk http://localhost:4000 --dry-run --output <tmp>` | writes plan and run metadata | pass; plan contains PTK `env.configs`, `spiderClient`, report jobs, and no `addOns` install | temporary dry-run output |

Definition of done:

- [x] `zaprun ptk` exists and is documented.
- [x] URL validation accepts only HTTP(S).
- [x] Image override remains digest-only.
- [x] Browser count is bounded.
- [x] Artifacts normalize to the standard zaprun output family.
- [x] Tests cover dry-run plan generation and invalid target rejection.

### Milestone 4 — Add PTK E2E, Docs, and Release Readiness Gates

Status: `done`

Completed scope:

- Ran PTK against disposable NodeGoat.
- Updated root README, crate README, CLI docs, architecture notes, changelog, and workflow image smokes.
- Added release-readiness checks for baked add-ons, headless PTK config startup, Trivy image scan, and extracted add-on scan.
- Recorded upstream Network add-on Netty CVE tracking in issue #3.

Evidence:

| Check | Command | Expected Result | Actual Result | Evidence Path |
|---|---|---|---|---|
| NodeGoat PTK scan | `cargo run -q -p zaprun -- ptk http://host.docker.internal:4000 --image localhost:5001/zaprun@sha256:9521117fa4a0f487e8165e4af7ebb5037bf2b5048a5de5d18d3e9564c9ac58ef --output output/zaprun-ptk-nodegoat-20260515225040 --max-duration 3m --scan-timeout 12m` | completes and writes artifacts | completed; exit `1` due configured High-finding policy | `output/zaprun-ptk-nodegoat-20260515225040/` |
| Image Trivy gate | `trivy image --severity HIGH,CRITICAL --scanners vuln --ignorefile .trivyignore --exit-code 1 zaprun:ptk-local` | pass | pass | local command output |
| Extracted add-on Trivy gate | `trivy fs --severity HIGH,CRITICAL --scanners vuln --ignorefile .trivyignore --exit-code 1 .tmp/zap-addons` | pass | pass with narrow upstream Netty exceptions | `.trivyignore`; https://github.com/kerberosmansour/zaprun/issues/3 |
| Full workspace tests | `cargo test --workspace` | pass | pass | local command output |

Definition of done:

- [x] NodeGoat PTK scan completed with full artifacts.
- [x] Documentation describes `zaprun ptk` and Phase 1 limits.
- [x] CI image smoke covers PTK add-on presence and PTK config startup.
- [x] Final image vulnerability scan passes.
- [x] Extracted add-on scan passes with tracked, dated upstream exceptions only.
- [x] Runbook tracker, evidence, lessons, and completion summaries are updated.

---

## 9. Confirmation Gate Resolution

Resolved by explicit user instruction on 2026-05-15 to execute the runbook end to end and scan NodeGoat with the updated PTK-aware CLI and image.

## 10. End-to-End Execution Evidence

| Check | Command | Result | Evidence Path |
|---|---|---|---|
| PTK CLI dry-run | `cargo test -p zaprun --test e2e_zaprun_ptk_yaml_only` | pass; generated PTK plan contains `env.configs`, `spiderClient`, reports, and no `addOns` runtime install | local command output |
| Headless PTK config smoke | `docker run --rm -v "$PWD/.tmp/ptk-config-smoke:/zap/wrk:rw" --entrypoint /opt/zap/zap.sh zaprun:ptk-local -cmd -autorun /zap/wrk/plan.yaml` | pass after removing GUI-only Quick Start add-on from the hardened image | `.github/workflows/build-zap-image.yml` smoke mirrors this |
| Final image Trivy gate | `trivy image --severity HIGH,CRITICAL --scanners vuln --ignorefile .trivyignore --exit-code 1 zaprun:ptk-local` | pass, 0 HIGH/CRITICAL findings in final image scan | local command output |
| Extracted add-on Trivy gate | `trivy fs --severity HIGH,CRITICAL --scanners vuln --ignorefile .trivyignore --exit-code 1 .tmp/zap-addons` | pass; Network add-on Netty exceptions tracked in issue #3 with 2026-06-15 review date | `.trivyignore`; https://github.com/kerberosmansour/zaprun/issues/3 |
| NodeGoat PTK scan | `cargo run -q -p zaprun -- ptk http://host.docker.internal:4000 --image localhost:5001/zaprun@sha256:9521117fa4a0f487e8165e4af7ebb5037bf2b5048a5de5d18d3e9564c9ac58ef --output output/zaprun-ptk-nodegoat-20260515225040 --max-duration 3m --scan-timeout 12m` | completed; exit `1` from configured High-finding policy; artifacts produced | `output/zaprun-ptk-nodegoat-20260515225040/` |

### NodeGoat Scan Summary

| Field | Value |
|---|---|
| Status | `failed` by security policy |
| High findings | 3 instances |
| Medium findings | 17 |
| Warnings | 69 |
| Browser-discovered URLs | 26 |
| Duration | 192 seconds |
| Coverage profile | `ptk-phase1` |
| Browser status | required, available, attempted |
| Coverage gap | no seeded journeys or authentication configured |
| Example High finding | `XSS - double-quoted attribute event injection` on `/login` and `/signup` parameters |

### Final Verification Commands

- `cargo fmt --all -- --check`: pass
- `cargo test -p zaprun`: pass
- `cargo clippy --workspace --all-targets -- -D warnings`: pass
- `cargo test --workspace`: pass
- `docker buildx build -f docker/zap/Dockerfile --load -t zaprun:ptk-local .`: pass
- `docker run --rm zaprun:ptk-local zaprun ptk --help`: pass
- `docker run --rm --entrypoint /opt/zap/zap.sh zaprun:ptk-local -cmd -addonlist`: pass; includes `client` and `ptk`, excludes `quickstart`
