//! Typed Automation Framework plan builder.
//!
//! `Plan` is the only public way to produce `plan.yaml` for the Docker backend.
//! There is no parser for user-supplied YAML in MVP1 -- callers always emit.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Map, Value};
use thiserror::Error;

const MAX_JOBS: usize = 32;
const MAX_CLIENT_SPIDER_BROWSERS: u64 = 2;

#[derive(Debug, Clone, Error)]
pub enum PlanError {
    #[error("plan_too_many_jobs: AF plan exceeds {MAX_JOBS} jobs")]
    TooManyJobs,
    #[error("env_no_contexts: AF plan must define at least one env.context")]
    EnvNoContexts,
    #[error("addon_update_in_ci: live add-on installs/updates are forbidden in CI mode")]
    AddonUpdateInCi,
    #[error(
        "client_spider_browser_count_out_of_bounds: spiderClient numberOfBrowsers must be 1..=2"
    )]
    ClientSpiderBrowserCountOutOfBounds,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Plan {
    pub env: Env,
    pub jobs: Vec<Job>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Env {
    pub contexts: Vec<Context>,
    pub ptk_config: Option<PtkConfig>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Context {
    pub name: String,
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PtkConfig {
    pub automated_scanning: bool,
    pub sast: bool,
    pub iast: bool,
    pub dast: bool,
}

impl PtkConfig {
    pub fn phase1() -> Self {
        Self {
            automated_scanning: true,
            sast: true,
            iast: true,
            dast: true,
        }
    }
}

/// AF plan job. Tagged enum -- the tag is the YAML `type:` field.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Job {
    AddOns {
        install: Vec<String>,
        update: bool,
    },
    Spider {
        max_duration_seconds: u64,
        url: String,
    },
    AjaxSpider {
        url: String,
        browser_id: String,
        max_duration_seconds: u64,
    },
    SpiderClient {
        url: String,
        browser_id: String,
        max_duration_seconds: u64,
        number_of_browsers: u64,
    },
    OpenApi {
        api_file: String,
        target_url: String,
    },
    PassiveScanWait {
        max_duration_seconds: u64,
    },
    ActiveScan {
        policy_inline: bool,
        dom_xss_enabled: bool,
    },
    Report {
        template: String,
        file: String,
    },
    ExitStatus {
        error_level: String,
        warn_level: String,
    },
}

#[derive(Default)]
pub struct PlanBuilder {
    contexts: Vec<Context>,
    jobs: Vec<Job>,
    ptk_config: Option<PtkConfig>,
    ci_mode: bool,
}

impl Plan {
    pub fn builder() -> PlanBuilder {
        // Default ci_mode = true: the safer default. Callers must opt out explicitly.
        PlanBuilder {
            ci_mode: true,
            ..Default::default()
        }
    }

    pub fn to_yaml(&self) -> Result<String, serde_yaml_ng::Error> {
        let doc = PlanYaml {
            env: EnvYaml {
                contexts: &self.env.contexts,
                parameters: EnvParameters {
                    fail_on_error: true,
                    fail_on_warning: false,
                    progress_to_stdout: true,
                },
                configs: self.env.ptk_config.as_ref().map(PtkConfig::to_af_configs),
            },
            jobs: self.jobs.iter().map(job_to_yaml).collect(),
        };
        serde_yaml_ng::to_string(&doc)
    }
}

#[derive(Debug, Serialize)]
struct PlanYaml<'a> {
    env: EnvYaml<'a>,
    jobs: Vec<JobYaml>,
}

#[derive(Debug, Serialize)]
struct EnvYaml<'a> {
    contexts: &'a [Context],
    parameters: EnvParameters,
    #[serde(skip_serializing_if = "Option::is_none")]
    configs: Option<BTreeMap<&'static str, bool>>,
}

#[derive(Debug, Serialize)]
struct EnvParameters {
    #[serde(rename = "failOnError")]
    fail_on_error: bool,
    #[serde(rename = "failOnWarning")]
    fail_on_warning: bool,
    #[serde(rename = "progressToStdout")]
    progress_to_stdout: bool,
}

#[derive(Debug, Serialize)]
struct JobYaml {
    #[serde(rename = "type")]
    job_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<Value>,
    #[serde(rename = "policyDefinition", skip_serializing_if = "Option::is_none")]
    policy_definition: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risks: Option<Vec<&'static str>>,
}

fn job_to_yaml(job: &Job) -> JobYaml {
    match job {
        Job::AddOns { install, update } => JobYaml {
            job_type: "addOns",
            parameters: Some(json!({
                "install": install,
                "update": update,
            })),
            policy_definition: None,
            risks: None,
        },
        Job::Spider {
            max_duration_seconds,
            url,
        } => JobYaml {
            job_type: "spider",
            parameters: Some(json!({
                "context": "default",
                "url": url,
                "maxDuration": seconds_to_minutes(*max_duration_seconds),
                "threadCount": 1,
            })),
            policy_definition: None,
            risks: None,
        },
        Job::AjaxSpider {
            url,
            browser_id,
            max_duration_seconds,
        } => JobYaml {
            job_type: "spiderAjax",
            parameters: Some(json!({
                "context": "default",
                "url": url,
                "browserId": browser_id,
                "maxDuration": seconds_to_minutes(*max_duration_seconds),
                "numberOfBrowsers": 1,
                "inScopeOnly": true,
            })),
            policy_definition: None,
            risks: None,
        },
        Job::SpiderClient {
            url,
            browser_id,
            max_duration_seconds,
            number_of_browsers,
        } => JobYaml {
            job_type: "spiderClient",
            parameters: Some(json!({
                "context": "default",
                "url": url,
                "browserId": browser_id,
                "maxDuration": seconds_to_minutes(*max_duration_seconds),
                "numberOfBrowsers": number_of_browsers,
                "scopeCheck": "Strict",
            })),
            policy_definition: None,
            risks: None,
        },
        Job::OpenApi {
            api_file,
            target_url,
        } => JobYaml {
            job_type: "openapi",
            parameters: Some(json!({
                "apiFile": api_file,
                "targetUrl": target_url,
                "context": "default",
            })),
            policy_definition: None,
            risks: None,
        },
        Job::PassiveScanWait {
            max_duration_seconds,
        } => JobYaml {
            job_type: "passiveScan-wait",
            parameters: Some(json!({
                "maxDuration": seconds_to_minutes(*max_duration_seconds),
            })),
            policy_definition: None,
            risks: None,
        },
        Job::ActiveScan {
            policy_inline,
            dom_xss_enabled,
        } => JobYaml {
            job_type: "activeScan",
            parameters: Some(json!({
                "context": "default",
                "threadPerHost": 1,
                "maxAlertsPerRule": 20,
            })),
            policy_definition: policy_inline
                .then(|| active_scan_policy_definition(*dom_xss_enabled)),
            risks: None,
        },
        Job::Report { template, file } => JobYaml {
            job_type: "report",
            parameters: Some(json!({
                "template": template,
                "reportDir": "/zap/wrk",
                "reportFile": file,
                "reportTitle": "zaprun ZAP report",
                "displayReport": false,
            })),
            policy_definition: None,
            risks: Some(vec!["high", "medium", "low", "info"]),
        },
        Job::ExitStatus {
            error_level,
            warn_level,
        } => JobYaml {
            job_type: "exitStatus",
            parameters: Some(json!({
                "errorLevel": af_level(error_level),
                "warnLevel": af_level(warn_level),
                "okExitValue": 0,
                "errorExitValue": 1,
                "warnExitValue": 0,
            })),
            policy_definition: None,
            risks: None,
        },
    }
}

impl PtkConfig {
    fn to_af_configs(&self) -> BTreeMap<&'static str, bool> {
        BTreeMap::from([
            ("ptk.automatedScanning.enabled", self.automated_scanning),
            ("ptk.scanrules.DAST.enabled", self.dast),
            ("ptk.scanrules.IAST.enabled", self.iast),
            ("ptk.scanrules.SAST.enabled", self.sast),
        ])
    }
}

fn seconds_to_minutes(seconds: u64) -> u64 {
    seconds.div_ceil(60).max(1)
}

fn af_level(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => format!(
            "{}{}",
            first.to_ascii_uppercase(),
            chars.as_str().to_ascii_lowercase()
        ),
        None => String::new(),
    }
}

fn active_scan_policy_definition(dom_xss_enabled: bool) -> Value {
    let mut policy = Map::new();
    policy.insert("defaultStrength".to_string(), json!("Low"));
    policy.insert("defaultThreshold".to_string(), json!("Medium"));
    if !dom_xss_enabled {
        policy.insert(
            "rules".to_string(),
            json!([
                {
                "id": 40026,
                "name": "Cross Site Scripting (DOM Based)",
                "threshold": "Off",
            }
            ]),
        );
    }
    Value::Object(policy)
}

impl PlanBuilder {
    pub fn context(mut self, name: &str, url: &str) -> Self {
        self.contexts.push(Context {
            name: name.to_string(),
            urls: vec![url.to_string()],
        });
        self
    }

    pub fn ci_mode(mut self, on: bool) -> Self {
        self.ci_mode = on;
        self
    }

    pub fn ptk_config(mut self, config: PtkConfig) -> Self {
        self.ptk_config = Some(config);
        self
    }

    pub fn job(mut self, j: Job) -> Self {
        self.jobs.push(j);
        self
    }

    pub fn build(self) -> Result<Plan, PlanError> {
        if self.contexts.is_empty() {
            return Err(PlanError::EnvNoContexts);
        }
        if self.jobs.len() > MAX_JOBS {
            return Err(PlanError::TooManyJobs);
        }
        for j in &self.jobs {
            if let Job::SpiderClient {
                number_of_browsers, ..
            } = j
            {
                if !(1..=MAX_CLIENT_SPIDER_BROWSERS).contains(number_of_browsers) {
                    return Err(PlanError::ClientSpiderBrowserCountOutOfBounds);
                }
            }
        }
        if self.ci_mode {
            for j in &self.jobs {
                if let Job::AddOns { install, update } = j {
                    if *update || !install.is_empty() {
                        return Err(PlanError::AddonUpdateInCi);
                    }
                }
            }
        }
        Ok(Plan {
            env: Env {
                contexts: self.contexts,
                ptk_config: self.ptk_config,
            },
            jobs: self.jobs,
        })
    }
}

impl From<PlanError> for crate::error::ZapshootError {
    fn from(e: PlanError) -> Self {
        crate::error::ZapshootError::Io(e.to_string())
    }
}
