use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::Utc;

use crate::capabilities::{
    BrowserProbe, CapabilitiesReport, DockerProbe, ImageProbe, JavaProbe, OutputDirProbe,
    TargetProbe, SCHEMA_VERSION,
};
use crate::error::ZapshootError;
use crate::image_ref::ImageRef;

/// Per-probe wall-clock budget.
const PROBE_BUDGET: Duration = Duration::from_secs(5);
/// Total doctor wall-clock budget.
const TOTAL_BUDGET: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct DoctorOptions {
    pub backend: String,
    pub image: Option<String>,
    pub probe_target: Option<String>,
    pub output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ReachabilityOutcome {
    pub reachable: bool,
    pub error: Option<String>,
}

/// Result of a doctor run: the typed report plus a bit indicating whether all
/// required probes passed (used by the CLI to decide between `Pass` and `ToolError`).
#[derive(Debug)]
pub struct DoctorOutcome {
    pub report: CapabilitiesReport,
    pub all_required_ok: bool,
    pub first_error: Option<ZapshootError>,
}

pub fn run_doctor(opts: &DoctorOptions) -> Result<DoctorOutcome, ZapshootError> {
    let started = Instant::now();
    let started_at = Utc::now();

    // ---- output dir probe (do this first; needed regardless of other outcomes)
    let output_dir = probe_output_dir(&opts.output);
    let output_writable = output_dir.writable;

    // ---- docker probe
    let docker = if opts.backend == "docker" {
        probe_docker()
    } else {
        DockerProbe {
            available: false,
            error: Some("backend_not_docker".into()),
        }
    };

    // ---- image probe (required when --image is provided)
    let image = match opts.image.as_deref() {
        Some(s) => probe_image(s),
        None => ImageProbe {
            pinned: false,
            repo: None,
            sha256: None,
            error: Some("no_image_provided".into()),
        },
    };

    // ---- optional ancillary probes (best-effort)
    let java = Some(JavaProbe {
        available: which::which("java").is_ok(),
    });
    let browser = Some(BrowserProbe {
        firefox_in_path: which::which("firefox").is_ok() || which::which("firefox-bin").is_ok(),
        geckodriver_in_path: which::which("geckodriver").is_ok(),
    });

    // ---- optional reachability probe
    let target = match opts.probe_target.as_deref() {
        Some(url) => {
            let outcome = probe_target_reachability(url, PROBE_BUDGET);
            Some(TargetProbe {
                url: url.to_string(),
                reachable: outcome.reachable,
                error: outcome.error,
            })
        }
        None => None,
    };

    // ---- total-budget guard
    let total_elapsed = started.elapsed();
    let partial = total_elapsed >= TOTAL_BUDGET;

    // Decide pass/fail.  Required = docker available (when backend=docker), image
    // pinned IF an --image was provided, output writable, and target reachable IF
    // a --probe-target was provided.
    let mut first_error: Option<ZapshootError> = None;
    if !output_writable {
        first_error.get_or_insert(ZapshootError::OutputDirNotWritable);
    }
    if opts.backend == "docker" && !docker.available {
        first_error.get_or_insert(ZapshootError::DockerNotInPath);
    }
    if opts.image.is_some() && !image.pinned {
        // The most specific error is preferred; the image probe stashed a string code.
        let err = match image.error.as_deref() {
            Some("not_digest") => ZapshootError::ImageRefNotDigest,
            Some("digest_malformed") => ZapshootError::ImageRefDigestMalformed,
            Some("repo_charset") => ZapshootError::ImageRefRepoCharset,
            Some("repo_too_long") => ZapshootError::ImageRefRepoTooLong,
            _ => ZapshootError::ImageRefNotDigest,
        };
        first_error.get_or_insert(err);
    }
    if let Some(t) = &target {
        if !t.reachable {
            first_error.get_or_insert(ZapshootError::TargetUnreachable);
        }
    }
    if partial {
        first_error.get_or_insert(ZapshootError::TotalBudgetExceeded);
    }

    let report = CapabilitiesReport {
        schema_version: SCHEMA_VERSION.to_string(),
        backend: opts.backend.clone(),
        docker,
        image,
        output_dir,
        target,
        java,
        browser,
        partial,
        started_at,
        finished_at: Utc::now(),
    };

    // Always write capabilities.json, even on failure.
    write_capabilities(&opts.output, &report)?;

    Ok(DoctorOutcome {
        all_required_ok: first_error.is_none(),
        first_error,
        report,
    })
}

fn probe_output_dir(out: &Path) -> OutputDirProbe {
    if let Err(e) = std::fs::create_dir_all(out) {
        return OutputDirProbe {
            writable: false,
            error: Some(e.to_string()),
        };
    }
    let probe = out.join(".zaprun-write-probe");
    match std::fs::write(&probe, b"ok") {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            OutputDirProbe {
                writable: true,
                error: None,
            }
        }
        Err(e) => OutputDirProbe {
            writable: false,
            error: Some(e.to_string()),
        },
    }
}

fn probe_docker() -> DockerProbe {
    match which::which("docker") {
        Ok(_) => DockerProbe {
            available: true,
            error: None,
        },
        Err(_) => DockerProbe {
            available: false,
            error: Some("not_in_path".into()),
        },
    }
}

fn probe_image(s: &str) -> ImageProbe {
    match ImageRef::parse(s) {
        Ok(ImageRef::Digest { repo, sha256_hex }) => ImageProbe {
            pinned: true,
            repo: Some(repo),
            sha256: Some(sha256_hex),
            error: None,
        },
        Err(e) => ImageProbe {
            pinned: false,
            repo: None,
            sha256: None,
            error: Some(error_code(&e)),
        },
    }
}

fn error_code(e: &crate::image_ref::ImageRefError) -> String {
    use crate::image_ref::ImageRefError;
    match e {
        ImageRefError::NotDigest => "not_digest",
        ImageRefError::DigestMalformed => "digest_malformed",
        ImageRefError::RepoCharset => "repo_charset",
        ImageRefError::RepoTooLong => "repo_too_long",
    }
    .to_string()
}

/// Probe whether a target URL is reachable via TCP connect within a budget.
/// Uses `std::net::TcpStream::connect_timeout`; falls back to DNS resolution
/// if the URL host has no port (defaults: 80 for http, 443 for https).
pub fn probe_target_reachability(url: &str, budget: Duration) -> ReachabilityOutcome {
    let (host, port) = match parse_host_port(url) {
        Some(p) => p,
        None => {
            return ReachabilityOutcome {
                reachable: false,
                error: Some("url_parse_error".into()),
            };
        }
    };

    let addr_iter = match (host.as_str(), port).to_socket_addrs() {
        Ok(it) => it,
        Err(e) => {
            return ReachabilityOutcome {
                reachable: false,
                error: Some(format!("dns: {e}")),
            };
        }
    };

    let mut last_err: Option<String> = None;
    for addr in addr_iter {
        match std::net::TcpStream::connect_timeout(&addr, budget) {
            Ok(_) => {
                return ReachabilityOutcome {
                    reachable: true,
                    error: None,
                }
            }
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    ReachabilityOutcome {
        reachable: false,
        error: last_err.or_else(|| Some("no_addresses".into())),
    }
}

fn parse_host_port(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let port_default = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let host_part = rest.split('/').next().unwrap_or(rest);
    if let Some((host, port_str)) = host_part.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        Some((host.to_string(), port))
    } else {
        Some((host_part.to_string(), port_default))
    }
}

fn write_capabilities(out: &Path, report: &CapabilitiesReport) -> Result<(), ZapshootError> {
    std::fs::create_dir_all(out)?;
    let path = out.join("capabilities.json");
    let json =
        serde_json::to_string_pretty(report).map_err(|e| ZapshootError::Io(e.to_string()))?;
    std::fs::write(&path, json)?;
    Ok(())
}
