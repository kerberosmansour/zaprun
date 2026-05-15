use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "dast-spike",
    version,
    about = "Reproducible DAST scanner runner"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Scan(ScanArgs),
    Check(CheckArgs),
    Triage(TriageArgs),
    BumpImage(BumpImageArgs),
}

#[derive(Debug, Args, Clone)]
pub struct ScanArgs {
    #[arg(long)]
    pub target: String,
    #[arg(long, default_value = ".dast-spike/policy-pr.yml")]
    pub policy: PathBuf,
    #[arg(long, default_value = ".dast-spike/rules.tsv")]
    pub rules: PathBuf,
    #[arg(long, default_value = ".dast-spike/baseline.json")]
    pub baseline: PathBuf,
    #[arg(long, default_value = "./output")]
    pub output: PathBuf,
    #[arg(long)]
    pub image: Option<String>,
    #[arg(long)]
    pub enable_dom_xss: bool,
    #[arg(long, value_enum, default_value_t = ScannerName::Zap)]
    pub scanner: ScannerName,
    #[arg(long = "enable-scanner", value_enum)]
    pub enable_scanner: Vec<ScannerName>,
    #[arg(long)]
    pub auth_replacer_config: Option<PathBuf>,
    #[arg(long, default_value = "30s")]
    pub health_timeout: String,
}

#[derive(Debug, Args, Clone)]
pub struct CheckArgs {
    #[arg(long)]
    pub report: PathBuf,
    #[arg(long, default_value = ".dast-spike/baseline.json")]
    pub baseline: PathBuf,
    #[arg(long)]
    pub sarif: Option<PathBuf>,
    #[arg(long)]
    pub github_summary: bool,
}

#[derive(Debug, Args, Clone)]
pub struct TriageArgs {
    pub plugin_id: Option<String>,
    #[arg(long)]
    pub review: bool,
    #[arg(long)]
    pub scope_url_pattern: Option<String>,
    #[arg(long)]
    pub justification: Option<String>,
    #[arg(long, default_value_t = 90)]
    pub expires_in_days: i64,
    #[arg(long, default_value = ".dast-spike/baseline.json")]
    pub baseline: PathBuf,
    #[arg(long, default_value = "zap")]
    pub scanner: String,
    #[arg(long)]
    pub author: Option<String>,
}

#[derive(Debug, Args, Clone)]
pub struct BumpImageArgs {
    #[arg(long)]
    pub no_pr: bool,
    #[arg(long)]
    pub check: bool,
    #[arg(long, default_value = "references/zap-image-pin.toml")]
    pub pin_file: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub struct InitArgs {
    #[arg(long, default_value = ".")]
    pub target_dir: PathBuf,
    #[arg(long)]
    pub deployment_target: Option<String>,
    #[arg(long)]
    pub image: Option<String>,
}

#[derive(Debug, Args, Clone)]
pub struct ReDeriveArgs {
    #[arg(long, default_value = ".")]
    pub target_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScannerName {
    Zap,
    Nuclei,
    Wapiti,
}

impl ScannerName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zap => "zap",
            Self::Nuclei => "nuclei",
            Self::Wapiti => "wapiti",
        }
    }
}
