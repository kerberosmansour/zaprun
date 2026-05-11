use regex::Regex;
use std::collections::HashSet;

#[test]
fn unit_dockerfile_from_is_digest_pinned() {
    let dockerfile = std::fs::read_to_string(repo_root().join("docker/zap/Dockerfile")).unwrap();
    let re =
        Regex::new(r"^FROM\s+\S+@sha256:[0-9a-f]{64}(?:\s+[Aa][Ss]\s+[A-Za-z0-9._-]+)?$").unwrap();
    let mut stages = HashSet::new();
    for line in dockerfile.lines().filter(|line| line.starts_with("FROM ")) {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        let image = parts[1];
        if !stages.contains(image) {
            assert!(
                re.is_match(line),
                "Dockerfile FROM must use @sha256:<64hex>: {line}"
            );
        }
        if parts.len() == 4 && parts[2].eq_ignore_ascii_case("AS") {
            stages.insert(parts[3].to_owned());
        }
    }
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}
