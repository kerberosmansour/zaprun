use dast_spike::scanners::nuclei::validate_nuclei_pin;

#[test]
fn nuclei_template_pin_is_40_hex_chars() {
    let sha = validate_nuclei_pin(&repo_root().join("references/nuclei-templates-pinned-sha.toml"))
        .unwrap();
    assert_eq!(sha.len(), 40);
}

#[test]
fn invalid_nuclei_template_pin_fails() {
    let temp = tempfile::tempdir().unwrap();
    let pin = temp.path().join("pin.toml");
    std::fs::write(
        &pin,
        "repo = \"projectdiscovery/nuclei-templates\"\ncommit_sha = \"main\"\n",
    )
    .unwrap();
    let err = validate_nuclei_pin(&pin).unwrap_err();
    assert!(err.to_string().contains("40 hex chars"));
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}
