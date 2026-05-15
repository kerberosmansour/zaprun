#[test]
fn dockerfile_builds_zaprun_from_current_workspace_sources() {
    let dockerfile = std::fs::read_to_string(repo_root().join("docker/zap/Dockerfile")).unwrap();
    assert!(dockerfile.contains("COPY Cargo.toml Cargo.lock ./"));
    assert!(dockerfile.contains("COPY crates/ ./crates/"));
    assert!(dockerfile.contains("cargo build -p zaprun --release --locked"));
    assert!(dockerfile.contains("COPY --from=cargo-build"));
    assert!(dockerfile.contains("/build/target/release/zaprun /usr/local/bin/zaprun"));
    assert!(dockerfile.contains("/usr/local/bin/zaprun-entrypoint"));
    assert!(!dockerfile.contains("/usr/local/bin/dast-spike-entrypoint"));
}

#[test]
fn image_workflow_smokes_current_zaprun_cli_surface() {
    let workflow =
        std::fs::read_to_string(repo_root().join(".github/workflows/build-zap-image.yml")).unwrap();
    assert!(workflow.contains("zaprun --version"));
    for subcommand in [
        "scan",
        "api",
        "doctor",
        "plan",
        "ptk",
        "observe",
        "calibrate",
        "init",
        "rederive",
        "triage-sarif",
        "explain",
    ] {
        assert!(
            workflow.contains(subcommand),
            "build-zap-image.yml must smoke-test `zaprun {subcommand} --help`"
        );
    }
    assert!(!workflow.contains("dast-spike-entrypoint"));
}

#[test]
fn dockerfile_bakes_ptk_and_client_addons_with_pinned_checksums() {
    let dockerfile = std::fs::read_to_string(repo_root().join("docker/zap/Dockerfile")).unwrap();
    for expected in [
        "ZAP_CLIENT_ADDON_VERSION=0.24.0",
        "ZAP_CLIENT_ADDON_URL=https://github.com/zaproxy/zap-extensions/releases/download/client-v${ZAP_CLIENT_ADDON_VERSION}/client-alpha-${ZAP_CLIENT_ADDON_VERSION}.zap",
        "ZAP_CLIENT_ADDON_SHA256=779510906f67fc62e5cd535e13663f3d374ef3270818c8333264fc81c13826a9",
        "ZAP_PTK_ADDON_VERSION=0.4.0",
        "ZAP_PTK_ADDON_URL=https://github.com/zaproxy-addons/ptk/releases/download/v${ZAP_PTK_ADDON_VERSION}/ptk-alpha-${ZAP_PTK_ADDON_VERSION}.zap",
        "ZAP_PTK_ADDON_SHA256=67ccb8873bac57b60d51920da015469e0afee767e148968bc647f72fbc07f224",
        "client-alpha-${ZAP_CLIENT_ADDON_VERSION}.zap",
        "ptk-alpha-${ZAP_PTK_ADDON_VERSION}.zap",
    ] {
        assert!(
            dockerfile.contains(expected),
            "Dockerfile must contain pinned add-on input `{expected}`"
        );
    }
}

#[test]
fn dockerfile_removes_gui_only_quickstart_addon_for_headless_ptk_runs() {
    let dockerfile = std::fs::read_to_string(repo_root().join("docker/zap/Dockerfile")).unwrap();
    assert!(
        dockerfile.contains("rm -f /opt/zap/plugin/quickstart-*.zap"),
        "Dockerfile must remove Quick Start from the headless image so AF generic configs do not trip GUI-only startup paths"
    );
}

#[test]
fn ptk_addons_are_never_installed_at_runtime() {
    let root = repo_root();
    let files = [
        root.join("docker/zap/Dockerfile"),
        root.join(".github/workflows/build-zap-image.yml"),
        root.join("crates/zaprun/src/plan.rs"),
        root.join("crates/zaprun/src/scan_url.rs"),
        root.join("crates/zaprun/src/scan_api.rs"),
    ];
    for path in files {
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("-addoninstall ptk"),
            "{} must not install PTK at runtime via zap.sh",
            path.display()
        );
        assert!(
            !content.contains("\"install\":[\"ptk\"]")
                && !content.contains("install: [ptk]")
                && !content.contains("install:\\n  - ptk"),
            "{} must not install PTK through an Automation Framework addOns job",
            path.display()
        );
    }
}

#[test]
fn image_workflow_smokes_ptk_and_client_addons() {
    let workflow =
        std::fs::read_to_string(repo_root().join(".github/workflows/build-zap-image.yml")).unwrap();
    for expected in [
        "client-alpha-*.zap",
        "ptk-alpha-*.zap",
        "grep -E '(^|[[:space:]])client[[:space:]]'",
        "grep -E '(^|[[:space:]])ptk[[:space:]]'",
        "! grep -E '(^|[[:space:]])quickstart[[:space:]]'",
        "ptk.automatedScanning.enabled: true",
        "-cmd -autorun /zap/wrk/plan.yaml",
    ] {
        assert!(
            workflow.contains(expected),
            "build-zap-image.yml must smoke-test `{expected}`"
        );
    }
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}
