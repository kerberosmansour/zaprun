//! ZAP child-process supervisor.
//!
//! The supervisor is the single point of authority for log capture (bounded
//! ring buffer + verbatim file mirror) and for the two wall-clock timeouts
//! (startup + scan).  In M2 it is constructed and unit-tested but is not yet
//! driven by a real Docker container -- M3 wires that up.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use security_events::sanitize::sanitize_for_text_sink;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorTimeout {
    Startup,
    Scan,
}

#[derive(Debug)]
pub struct Supervisor {
    pub startup_timeout: Duration,
    pub scan_timeout: Duration,
}

impl Supervisor {
    pub fn new(startup_timeout: Duration, scan_timeout: Duration) -> Self {
        Self {
            startup_timeout,
            scan_timeout,
        }
    }

    /// Synthetic helper for tests: poll a predicate until either it returns
    /// true (Ok) or the startup budget elapses (Err::Startup).
    pub fn wait_ready_synthetic<F>(&self, mut ready: F) -> Result<(), SupervisorTimeout>
    where
        F: FnMut(Instant) -> bool,
    {
        let start = Instant::now();
        loop {
            if ready(start) {
                return Ok(());
            }
            if start.elapsed() >= self.startup_timeout {
                return Err(SupervisorTimeout::Startup);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Synthetic helper for tests: same shape but for scan-completion.
    pub fn wait_complete_synthetic<F>(&self, mut done: F) -> Result<(), SupervisorTimeout>
    where
        F: FnMut(Instant) -> bool,
    {
        let start = Instant::now();
        loop {
            if done(start) {
                return Ok(());
            }
            if start.elapsed() >= self.scan_timeout {
                return Err(SupervisorTimeout::Scan);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// In-process bounded ring buffer for child stdout/stderr lines.
///
/// `cap` is the maximum number of lines retained.  Excess lines are dropped
/// from the front; `truncated()` returns true once any drop has occurred.
#[derive(Debug)]
pub struct LogRingBuffer {
    inner: VecDeque<String>,
    cap: usize,
    truncated: bool,
}

impl LogRingBuffer {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(cap.min(4096)),
            cap,
            truncated: false,
        }
    }

    pub fn push(&mut self, line: String) {
        if self.inner.len() == self.cap {
            self.inner.pop_front();
            self.truncated = true;
        }
        self.inner.push_back(line);
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.inner.iter().cloned().collect()
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Defense against CWE-117 log injection: escape control characters and
/// truncate over-long lines before mirroring child stdout into the structured
/// `tracing` sink.
///
/// Raw bytes still go to `<run-dir>/zap.log` verbatim -- the file is the
/// source of truth.  The `tracing` mirror is what gets sanitized.
pub fn escape_log_line_for_tracing(input: &str) -> String {
    const MAX: usize = 4 * 1024;
    let trimmed: &str = if input.len() > MAX {
        // Slice on a char boundary at-or-before MAX bytes.
        let mut end = MAX;
        while !input.is_char_boundary(end) {
            end -= 1;
        }
        &input[..end]
    } else {
        input
    };
    let sanitized = sanitize_for_text_sink(trimmed);
    if input.len() > MAX {
        format!("{sanitized}... [truncated]")
    } else {
        sanitized
    }
}
