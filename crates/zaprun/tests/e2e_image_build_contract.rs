#[test]
fn dockerfile_builds_zaprun_from_current_workspace_sources() {
    let dockerfile = std::fs::read_to_string(repo_root().join("docker/zap/Dockerfile")).unwrap();
    assert!(dockerfile.contains("COPY Cargo.toml Cargo.lock ./"));
    assert!(dockerfile.contains("COPY crates/ ./crates/"));
    assert!(dockerfile.contains("cargo build -p zaprun --release --locked"));
    assert!(dockerfile.contains("COPY --from=cargo-build"));
    assert!(dockerfile.contains("/build/target/release/zaprun /usr/local/bin/zaprun"));
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
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}
