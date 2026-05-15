//! BDD: `zaprun --help` and every subcommand `--help` MUST print a worked
//! `Examples:` block; the root `--help` MUST also print an `Exit codes:` block
//! that documents the full `ExitCode` contract from `crates/zaprun/src/exit.rs`.
//!
//! Why both substrings: the founder's feedback for ticket #2 asks for "a great
//! -h manual". A great help has at minimum (a) discoverable usage, (b) at least
//! one copy-pasteable example per subcommand, and (c) a single source of truth
//! for the exit-code contract on the top-level help so users know what an exit
//! code means without grepping the codebase.
//!
//! These assertions are exact substring matches because clap's wrap behaviour
//! is terminal-width-dependent and we don't want a width mismatch to flip the
//! test red.

use assert_cmd::Command;
use predicates::str::contains;

fn cmd() -> Command {
    Command::cargo_bin("zaprun").expect("zaprun binary built")
}

#[test]
fn root_help_has_examples_and_exit_codes_block() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Examples:"))
        .stdout(contains("Exit codes:"));
}

const SUBCOMMANDS: &[&str] = &[
    "scan",
    "api",
    "doctor",
    "plan",
    "ptk",
    "observe",
    "calibrate",
    "explain",
];

#[test]
fn every_subcommand_help_has_examples_block() {
    for sub in SUBCOMMANDS {
        cmd()
            .arg(sub)
            .arg("--help")
            .assert()
            .success()
            .stdout(contains("Examples:"))
            // Sanity: the subcommand's own name should appear in its help, not
            // just the parent's. Catches accidental copy-paste regressions.
            .stdout(contains(*sub));
    }
}
