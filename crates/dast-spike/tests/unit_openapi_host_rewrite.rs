use dast_spike::scan::rewrite_openapi_host;

#[test]
fn rewrites_localhost_server_to_host_docker_internal() {
    let temp = tempfile::tempdir().unwrap();
    let spec = temp.path().join("openapi.yaml");
    std::fs::write(
        &spec,
        r#"
openapi: "3.1.0"
servers:
  - url: http://127.0.0.1:3001
paths: {}
"#,
    )
    .unwrap();

    let output = rewrite_openapi_host(&spec, temp.path()).unwrap();
    let rewritten = std::fs::read_to_string(output).unwrap();
    assert!(rewritten.contains("http://host.docker.internal:3001"));
}
