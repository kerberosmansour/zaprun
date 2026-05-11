use crate::report::normalize::{load_zap_report, NormalizedReport};
use crate::scan::{
    build_image_reference, build_replacer_config, rewrite_openapi_host, run_command_with_timeout,
};
use crate::scanner::{Policy, ScanError, Scanner, Target};
use crate::types::{ImageRef, Surface};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct ZapScanner {
    pub image_ref: ImageRef,
    pub output_dir: PathBuf,
    pub enable_dom_xss: bool,
    pub auth_replacer_config: Option<PathBuf>,
}

impl Scanner for ZapScanner {
    fn name(&self) -> &'static str {
        "zap"
    }

    fn supported_cwes(&self) -> &[&'static str] {
        &[
            "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-200", "CWE-352", "CWE-601", "CWE-611",
            "CWE-918",
        ]
    }

    fn supported_surfaces(&self) -> &[Surface] {
        &[Surface::ApiOpenapi, Surface::WebMpa, Surface::WebSpa]
    }

    fn run(&self, target: &Target, policy: &Policy) -> Result<NormalizedReport, ScanError> {
        fs::create_dir_all(&self.output_dir).map_err(|err| ScanError::Runtime(err.to_string()))?;
        if std::env::var_os("DAST_SPIKE_FAKE_SCAN").is_some() {
            return self.write_fake_report();
        }

        let scan_target = if let Some(openapi_path) = &target.openapi_path {
            rewrite_openapi_host(openapi_path, &self.output_dir)
                .map_err(|err| ScanError::Runtime(err.to_string()))?;
            PathBuf::from("/zap/wrk/output/openapi-docker.yaml")
        } else {
            PathBuf::from(&target.url)
        };

        if let Some(config) = &self.auth_replacer_config {
            if !config.exists() {
                build_replacer_config(None, &self.output_dir)
                    .map_err(|err| ScanError::Runtime(err.to_string()))?;
            }
        }

        let output_mount = self
            .output_dir
            .canonicalize()
            .map_err(|err| ScanError::Runtime(err.to_string()))?;
        let image_ref = build_image_reference(&self.image_ref);
        let mut command = Command::new("docker");
        command
            .arg("run")
            .arg("--rm")
            .arg("--user")
            .arg("1000:1000")
            .arg("--add-host=host.docker.internal:host-gateway")
            .arg("-v")
            .arg(format!("{}:/zap/wrk/output:rw", output_mount.display()));

        if policy.rules_tsv_path.exists() {
            let rules = policy
                .rules_tsv_path
                .canonicalize()
                .map_err(|err| ScanError::Runtime(err.to_string()))?;
            command
                .arg("-v")
                .arg(format!("{}:/zap/wrk/rules.tsv:ro", rules.display()));
        }
        if let Some(policy_path) = &policy.policy_yaml_path {
            if policy_path.exists() {
                let policy_mount = policy_path
                    .canonicalize()
                    .map_err(|err| ScanError::Runtime(err.to_string()))?;
                command
                    .arg("-v")
                    .arg(format!("{}:/zap/wrk/policy.yml:ro", policy_mount.display()));
            }
        }
        command.arg("-e").arg(if self.enable_dom_xss {
            "DAST_SPIKE_DOM_XSS_ENABLED=1"
        } else {
            "DAST_SPIKE_DOM_XSS_ENABLED=0"
        });
        command
            .arg(image_ref)
            .arg("--target")
            .arg(scan_target)
            .arg("--output-dir")
            .arg("/zap/wrk/output")
            .arg("--policy")
            .arg("/zap/wrk/policy.yml");

        let status = run_command_with_timeout(&mut command, policy.timeout).map_err(|err| {
            if err.kind() == std::io::ErrorKind::TimedOut {
                ScanError::Timeout {
                    seconds: policy.timeout.as_secs(),
                }
            } else {
                ScanError::Runtime(format!("failed to run docker: {err}"))
            }
        })?;
        if !(status.success() || status.code() == Some(2)) {
            return Err(ScanError::Runtime(format!(
                "ZAP container exited with status {status}"
            )));
        }
        load_zap_report(&self.output_dir.join("zap-report.json"))
            .map_err(|err| ScanError::Runtime(err.to_string()))
    }
}

impl ZapScanner {
    fn write_fake_report(&self) -> Result<NormalizedReport, ScanError> {
        let report = json!({
            "site": [{
                "alerts": []
            }]
        });
        fs::write(
            self.output_dir.join("zap-report.json"),
            serde_json::to_vec_pretty(&report)
                .map_err(|err| ScanError::Runtime(err.to_string()))?,
        )
        .map_err(|err| ScanError::Runtime(err.to_string()))?;
        fs::write(
            self.output_dir.join("zap-report.html"),
            "<!doctype html><title>dast-spike fake ZAP report</title>\n",
        )
        .map_err(|err| ScanError::Runtime(err.to_string()))?;
        load_zap_report(&self.output_dir.join("zap-report.json"))
            .map_err(|err| ScanError::Runtime(err.to_string()))
    }
}
