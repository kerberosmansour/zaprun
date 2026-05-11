//! `coverage.json` — first-class coverage telemetry.
//!
//! Per the runbook safety property "no artifact gap on failure" and the
//! Juice Shop trap ("0 highs" should not look passed when SPA flows were never
//! crawled), every run emits a coverage report describing which crawler ran,
//! whether browser-backed crawl was attempted, and the explicit gap list.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub schema_version: String,
    pub profile: String,
    pub browser: BrowserCoverage,
    pub crawl: CrawlCoverage,
    pub coverage_gaps: Vec<CoverageGap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserCoverage {
    pub required: bool,
    pub available: bool,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlCoverage {
    pub traditional_urls: u32,
    pub ajax_urls: u32,
    pub seeded_requests_sent: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageGap {
    pub kind: CoverageGapKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapKind {
    BrowserMissing,
    PassiveOnly,
    TargetUnreachable,
    ActiveScanDidNotComplete,
    AuthenticationNotConfigured,
    SeededJourneysNotConfigured,
}

impl Coverage {
    pub fn for_web_pr_traditional(
        traditional_urls: u32,
        ajax_urls: u32,
        seeded_requests_sent: u32,
    ) -> Self {
        Coverage {
            schema_version: SCHEMA_VERSION.to_string(),
            profile: "web-pr".to_string(),
            browser: BrowserCoverage {
                required: false,
                available: false,
                status: "not-attempted".to_string(),
            },
            crawl: CrawlCoverage {
                traditional_urls,
                ajax_urls,
                seeded_requests_sent,
            },
            coverage_gaps: Vec::new(),
        }
    }

    pub fn for_spa_pr_browser(traditional_urls: u32, ajax_urls: u32) -> Self {
        Coverage {
            schema_version: SCHEMA_VERSION.to_string(),
            profile: "spa-pr".to_string(),
            browser: BrowserCoverage {
                required: true,
                available: true,
                status: "attempted".to_string(),
            },
            crawl: CrawlCoverage {
                traditional_urls,
                ajax_urls,
                seeded_requests_sent: 0,
            },
            coverage_gaps: vec![CoverageGap {
                kind: CoverageGapKind::SeededJourneysNotConfigured,
                message: "spa-pr ran browser-backed Ajax crawling, but no seeded journeys or authentication were configured".to_string(),
            }],
        }
    }

    pub fn for_web_pr_passive_only(traditional_urls: u32) -> Self {
        let mut c = Self::for_web_pr_traditional(traditional_urls, 0, 0);
        c.coverage_gaps.push(CoverageGap {
            kind: CoverageGapKind::PassiveOnly,
            message: "scan ran in --passive mode; active rules did not execute".to_string(),
        });
        c
    }

    pub fn for_target_unreachable(target: &str) -> Self {
        let mut c = Self::for_web_pr_traditional(0, 0, 0);
        c.coverage_gaps.push(CoverageGap {
            kind: CoverageGapKind::TargetUnreachable,
            message: format!("target {target} did not respond from the scanner namespace"),
        });
        c
    }

    pub fn for_active_scan_failed(reason: &str) -> Self {
        let mut c = Self::for_web_pr_traditional(0, 0, 0);
        c.coverage_gaps.push(CoverageGap {
            kind: CoverageGapKind::ActiveScanDidNotComplete,
            message: format!("active scan did not run to completion: {reason}"),
        });
        c
    }
}
