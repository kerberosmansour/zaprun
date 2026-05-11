fn main() {
    println!("cargo:rerun-if-env-changed=DAST_SPIKE_SMOKE_SERVICE_PATH");
    println!("cargo:rerun-if-changed=../../tests/targets/registry.toml");
}
