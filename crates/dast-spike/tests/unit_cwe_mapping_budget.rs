use dast_spike_rules::{CweRuleMappingDocument, MappingBudget};

#[test]
fn curated_mapping_respects_budget() {
    let doc =
        CweRuleMappingDocument::load(&repo_root().join("references/dast-tuner/cwe-to-rules.toml"))
            .unwrap();
    doc.validate(MappingBudget::default()).unwrap();
}

#[test]
fn over_budget_mapping_fails() {
    let text = r#"
[[mappings]]
cwe = "CWE-79"
zap_rules = [
  { id = "1", level = "FAIL", surface = "both" },
  { id = "2", level = "FAIL", surface = "both" },
  { id = "3", level = "FAIL", surface = "both" },
]
"#;
    let doc: CweRuleMappingDocument = toml::from_str(text).unwrap();
    let err = doc
        .validate(MappingBudget {
            zap_rules: 2,
            nuclei_templates: 6,
            custom_scripts: 2,
        })
        .unwrap_err();
    assert!(err.to_string().contains("exceeds budget"));
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}
