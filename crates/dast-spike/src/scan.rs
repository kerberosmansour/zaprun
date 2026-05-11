use crate::scanner::ScanError;
use crate::types::ImageRef;
use crate::{DastSpikeError, Result};
use regex::Regex;
use serde_yaml_ng::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

pub const ZAP_IMAGE_REPOSITORY: &str = "ghcr.io/kerberosmansour/zaprun";

pub fn rewrite_openapi_host(input: &Path, output_dir: &Path) -> Result<PathBuf> {
    let text = fs::read_to_string(input)?;
    let mut yaml: Value = serde_yaml_ng::from_str(&text)?;
    rewrite_servers(&mut yaml);
    fs::create_dir_all(output_dir)?;
    let output = output_dir.join("openapi-docker.yaml");
    let rendered = serde_yaml_ng::to_string(&yaml)?;
    fs::write(&output, rendered)?;
    Ok(output)
}

pub fn infer_target_url(target: &str) -> Result<String> {
    if target.starts_with("http://") || target.starts_with("https://") {
        return Ok(target.trim_end_matches('/').to_string());
    }
    let text = fs::read_to_string(target)?;
    let yaml: Value = serde_yaml_ng::from_str(&text)?;
    if let Some(url) = yaml
        .get("servers")
        .and_then(Value::as_sequence)
        .and_then(|servers| servers.first())
        .and_then(|server| server.get("url"))
        .and_then(Value::as_str)
    {
        return Ok(url.trim_end_matches('/').to_string());
    }
    Err(DastSpikeError::Usage(format!(
        "could not infer target URL from {target}"
    )))
}

pub fn build_image_reference(image_ref: &ImageRef) -> String {
    image_ref.full_ref(ZAP_IMAGE_REPOSITORY)
}

pub fn build_replacer_config(token: Option<&str>, output_dir: &Path) -> Result<Option<PathBuf>> {
    let Some(token) = token else {
        return Ok(None);
    };
    fs::create_dir_all(output_dir)?;
    let path = output_dir.join("zap-replacer.conf");
    let contents = format!(
        "replacer.full_list(0).description=AuthHeader\n\
         replacer.full_list(0).enabled=true\n\
         replacer.full_list(0).matchtype=REQ_HEADER\n\
         replacer.full_list(0).matchstr=Authorization\n\
         replacer.full_list(0).regex=false\n\
         replacer.full_list(0).replacement=Bearer {token}\n"
    );
    fs::write(&path, contents)?;
    Ok(Some(path))
}

pub fn run_command_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> std::io::Result<ExitStatus> {
    let mut child = command.spawn()?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("scan timed out after {}s", timeout.as_secs()),
            ));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

pub fn parse_duration(input: &str) -> Result<Duration> {
    if let Some(seconds) = input.strip_suffix('s') {
        let seconds = seconds.parse::<u64>().map_err(|_| {
            DastSpikeError::Usage(format!("invalid duration {input}; expected <seconds>s"))
        })?;
        Ok(Duration::from_secs(seconds))
    } else if let Some(minutes) = input.strip_suffix('m') {
        let minutes = minutes.parse::<u64>().map_err(|_| {
            DastSpikeError::Usage(format!("invalid duration {input}; expected <minutes>m"))
        })?;
        Ok(Duration::from_secs(minutes * 60))
    } else {
        Err(DastSpikeError::Usage(format!(
            "invalid duration {input}; use suffix s or m"
        )))
    }
}

pub fn scanner_io_error(err: std::io::Error) -> ScanError {
    if err.kind() == std::io::ErrorKind::TimedOut {
        ScanError::Timeout { seconds: 0 }
    } else {
        ScanError::Runtime(err.to_string())
    }
}

fn rewrite_servers(yaml: &mut Value) {
    let Some(servers) = yaml.get_mut("servers").and_then(Value::as_sequence_mut) else {
        return;
    };
    let re = Regex::new(r"http://127\.0\.0\.1:(\d+)").expect("static regex compiles");
    for server in servers {
        if let Some(url) = server
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_string)
        {
            let rewritten = re.replace_all(&url, "http://host.docker.internal:$1");
            if let Some(slot) = server.get_mut("url") {
                *slot = Value::String(rewritten.to_string());
            }
        }
    }
}
