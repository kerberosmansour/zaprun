//! Backend abstraction for executing AF plans.
//!
//! The Docker backend runs ZAP's Automation Framework directly, overriding the
//! managed image entrypoint so `zaprun` does not go through the packaged
//! Python helper scripts.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::ZapshootError;
use crate::image_ref::ImageRef;
use crate::supervisor::{escape_log_line_for_tracing, LogRingBuffer};

pub trait Backend {
    /// Run the plan at `plan_path`, mounting `run_dir` as the container's
    /// output directory.  Returns the supervised exit code.
    fn run(
        &self,
        plan_path: &Path,
        run_dir: &Path,
        opts: &RunOptions,
    ) -> Result<RunOutcome, ZapshootError>;
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub api_key: String,
    pub scan_timeout: Duration,
    pub browser_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub exit_code: i32,
    pub exit_reason: String,
    pub log_truncated: bool,
}

#[derive(Debug, Clone)]
pub struct DockerBackend {
    pub image: ImageRef,
}

impl DockerBackend {
    /// Construct a backend.  The type system enforces that `image` is a
    /// `Digest` (the only constructor for `ImageRef`), so tag-only references
    /// can never reach this point.
    pub fn new(image: ImageRef) -> Self {
        Self { image }
    }
}

impl Backend for DockerBackend {
    fn run(
        &self,
        plan_path: &Path,
        run_dir: &Path,
        opts: &RunOptions,
    ) -> Result<RunOutcome, ZapshootError> {
        if !plan_path.exists() {
            return Err(ZapshootError::Io("plan_not_found".to_string()));
        }
        let run_dir = run_dir.canonicalize().map_err(ZapshootError::from)?;
        let log_path = run_dir.join("zap.log");
        let log = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&log_path)?;
        let log = Arc::new(Mutex::new(log));
        let ring = Arc::new(Mutex::new(LogRingBuffer::new(10_000)));

        let mut cmd = Command::new("docker");
        cmd.arg("run")
            .arg("--rm")
            .arg("--user")
            .arg("1000:1000")
            .arg("--add-host=host.docker.internal:host-gateway")
            .arg("--entrypoint")
            .arg("/opt/zap/zap.sh")
            .arg("-v")
            .arg(format!("{}:/zap/wrk:rw", run_dir.display()))
            .arg(self.image.as_canonical_string())
            .arg("-cmd")
            .arg("-silent")
            .arg("-autorun")
            .arg("/zap/wrk/plan.yaml")
            .arg("-config")
            .arg("api.disablekey=false")
            .arg("-config")
            .arg(format!("api.key={}", opts.api_key))
            .arg("-config")
            .arg("scanner.threadPerHost=1")
            .arg("-config")
            .arg("spider.thread=1");

        if let Some(browser_id) = &opts.browser_id {
            cmd.arg("-config")
                .arg(format!("rules.domxss.browserid={browser_id}"));
        }

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ZapshootError::Io(format!("failed_to_spawn_docker: {e}")))?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let mut readers = Vec::new();
        if let Some(stdout) = stdout {
            readers.push(spawn_log_reader(
                stdout,
                Arc::clone(&log),
                Arc::clone(&ring),
            ));
        }
        if let Some(stderr) = stderr {
            readers.push(spawn_log_reader(
                stderr,
                Arc::clone(&log),
                Arc::clone(&ring),
            ));
        }

        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() >= opts.scan_timeout {
                let _ = child.kill();
                let _ = child.wait();
                for reader in readers {
                    let _ = reader.join();
                }
                return Err(ZapshootError::TotalBudgetExceeded);
            }
            std::thread::sleep(Duration::from_millis(250));
        };

        for reader in readers {
            let _ = reader.join();
        }
        let exit_code = status.code().unwrap_or(128);
        let log_truncated = ring.lock().map(|r| r.truncated()).unwrap_or(false);
        Ok(RunOutcome {
            exit_code,
            exit_reason: if status.success() {
                "zap_exit_ok".to_string()
            } else {
                format!("zap_exit_{exit_code}")
            },
            log_truncated,
        })
    }
}

fn spawn_log_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    log: Arc<Mutex<std::fs::File>>,
    ring: Arc<Mutex<LogRingBuffer>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.split(b'\n') {
            let Ok(mut line) = line else {
                break;
            };
            line.push(b'\n');
            if let Ok(mut f) = log.lock() {
                let _ = f.write_all(&line);
            }
            let lossy = String::from_utf8_lossy(&line);
            let safe = escape_log_line_for_tracing(lossy.trim_end_matches('\n'));
            tracing::debug!(target: "zaprun::backend", zap = %safe);
            if let Ok(mut r) = ring.lock() {
                r.push(safe);
            }
        }
    })
}
