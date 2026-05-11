use clap::Parser;
use dast_spike::cli::{Cli, Commands};
use dast_spike::{check, image_pin, orchestrator, triage, DastSpikeError};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .init();

    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Scan(args) => orchestrator::run_scan(args),
        Commands::Check(args) => check::run(args),
        Commands::Triage(args) => triage::run(args),
        Commands::BumpImage(args) => image_pin::run_bump_image(args),
    };

    if let Err(err) = result {
        eprintln!("dast-spike: {err}");
        std::process::exit(exit_code(&err));
    }
}

fn exit_code(err: &DastSpikeError) -> i32 {
    err.exit_code()
}
