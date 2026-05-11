use crate::report::normalize::{parse_wapiti_report, NormalizedReport};
use crate::scan::run_command_with_timeout;
use crate::scanner::{Policy, ScanError, Scanner, Target};
use crate::types::Surface;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct WapitiScanner {
    pub output_dir: PathBuf,
}

impl Scanner for WapitiScanner {
    fn name(&self) -> &'static str {
        "wapiti"
    }

    fn supported_cwes(&self) -> &[&'static str] {
        &[
            "CWE-22", "CWE-79", "CWE-89", "CWE-200", "CWE-611", "CWE-918",
        ]
    }

    fn supported_surfaces(&self) -> &[Surface] {
        &[Surface::WebMpa, Surface::WebSpa]
    }

    fn run(&self, target: &Target, policy: &Policy) -> Result<NormalizedReport, ScanError> {
        fs::create_dir_all(&self.output_dir).map_err(|err| ScanError::Runtime(err.to_string()))?;
        let output = self.output_dir.join("wapiti-report.json");
        let mut command = if which::which("wapiti").is_ok() {
            Command::new("wapiti")
        } else {
            Command::new("wapiti3")
        };
        command
            .arg("-u")
            .arg(&target.url)
            .arg("-f")
            .arg("json")
            .arg("-o")
            .arg(&output);
        let status = run_command_with_timeout(&mut command, policy.timeout).map_err(|err| {
            if err.kind() == std::io::ErrorKind::TimedOut {
                ScanError::Timeout {
                    seconds: policy.timeout.as_secs(),
                }
            } else {
                ScanError::Runtime(format!("failed to run wapiti: {err}"))
            }
        })?;
        if !status.success() {
            return Err(ScanError::Runtime(format!(
                "wapiti exited with status {status}"
            )));
        }
        let text =
            fs::read_to_string(&output).map_err(|err| ScanError::Runtime(err.to_string()))?;
        parse_wapiti_report(&text).map_err(|err| ScanError::Runtime(err.to_string()))
    }
}
