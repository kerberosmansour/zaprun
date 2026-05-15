use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_TOKENS: &[&str] = &[
    "Java.type",
    "Polyglot.eval",
    "org.graalvm.polyglot.",
    "Context.create",
    "Engine.create",
    "eval(response.body)",
];

const REQUIRED_METADATA: &[&str] = &[
    "zaprun-rule-name",
    "cwe",
    "risk",
    "confidence",
    "surface",
    "match",
    "generality",
];

fn main() {
    let code = match run() {
        Ok(accepted) => {
            if accepted {
                0
            } else {
                1
            }
        }
        Err(err) => {
            eprintln!("dast-verify: {err}");
            2
        }
    };
    std::process::exit(code);
}

fn run() -> Result<bool, String> {
    let args = Args::parse(std::env::args().skip(1))?;
    let candidate_text = fs::read_to_string(&args.candidate)
        .map_err(|err| format!("candidate read failed: {err}"))?;
    let metadata = parse_metadata(&candidate_text);

    let mut failures = Vec::new();
    for key in REQUIRED_METADATA {
        if !metadata.contains_key(*key) {
            failures.push(format!("missing-metadata: {key}"));
        }
    }
    validate_cwe(&metadata, &mut failures);
    validate_enum("risk", &metadata, &["low", "medium", "high"], &mut failures);
    validate_enum(
        "confidence",
        &metadata,
        &["low", "medium", "high"],
        &mut failures,
    );
    validate_enum("surface", &metadata, &["api", "web", "both"], &mut failures);
    validate_forbidden_tokens(&candidate_text, &mut failures);
    validate_fixture_corpus(&args.fixtures, metadata.get("match"), &mut failures);

    let app_literal = metadata.get("app-literal").cloned();
    if app_literal.is_some() && !args.target_owned {
        failures.push(
            "app-specific-literal: generic candidates must not depend on private app literals"
                .to_string(),
        );
    }

    let mut written_rule = None;
    let accepted = failures.is_empty();
    let decision = if accepted && args.target_owned {
        let target_output = args
            .target_output
            .as_ref()
            .ok_or_else(|| "--target-output is required with --target-owned".to_string())?;
        fs::create_dir_all(target_output)
            .map_err(|err| format!("target output create failed: {err}"))?;
        let file_name = args
            .candidate
            .file_name()
            .ok_or_else(|| "candidate must have a file name".to_string())?;
        let destination = target_output.join(file_name);
        fs::copy(&args.candidate, &destination)
            .map_err(|err| format!("target-owned rule write failed: {err}"))?;
        written_rule = Some(destination);
        "target-owned-accepted"
    } else if accepted {
        "generic-accepted"
    } else {
        "rejected"
    };

    write_report(
        &args.output,
        &Report {
            decision,
            generic_eligible: accepted && !args.target_owned,
            target_owned: args.target_owned,
            candidate: &args.candidate,
            failures: &failures,
            written_rule: written_rule.as_deref(),
            metadata: &metadata,
        },
    )?;

    Ok(accepted)
}

#[derive(Debug)]
struct Args {
    candidate: PathBuf,
    fixtures: PathBuf,
    output: PathBuf,
    target_owned: bool,
    target_output: Option<PathBuf>,
}

impl Args {
    fn parse(mut raw: impl Iterator<Item = String>) -> Result<Self, String> {
        let Some(command) = raw.next() else {
            return Err(
                "usage: dast-verify gate --candidate <file> --fixtures <dir> --output <file>"
                    .to_string(),
            );
        };
        if command != "gate" {
            return Err(format!("unsupported command: {command}"));
        }

        let mut candidate = None;
        let mut fixtures = None;
        let mut output = None;
        let mut target_owned = false;
        let mut target_output = None;
        while let Some(arg) = raw.next() {
            match arg.as_str() {
                "--candidate" => candidate = raw.next().map(PathBuf::from),
                "--fixtures" => fixtures = raw.next().map(PathBuf::from),
                "--output" => output = raw.next().map(PathBuf::from),
                "--target-owned" => target_owned = true,
                "--target-output" => target_output = raw.next().map(PathBuf::from),
                other => return Err(format!("unsupported argument: {other}")),
            }
        }

        Ok(Self {
            candidate: candidate.ok_or_else(|| "--candidate is required".to_string())?,
            fixtures: fixtures.ok_or_else(|| "--fixtures is required".to_string())?,
            output: output.ok_or_else(|| "--output is required".to_string())?,
            target_owned,
            target_output,
        })
    }
}

fn parse_metadata(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("//") else {
            continue;
        };
        let Some((key, value)) = rest.trim().split_once(':') else {
            continue;
        };
        out.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    out
}

fn validate_cwe(metadata: &BTreeMap<String, String>, failures: &mut Vec<String>) {
    let Some(cwe) = metadata.get("cwe") else {
        return;
    };
    let Some(id) = cwe.strip_prefix("CWE-") else {
        failures.push(format!("invalid-cwe: {cwe}"));
        return;
    };
    if id.is_empty() || !id.chars().all(|ch| ch.is_ascii_digit()) {
        failures.push(format!("invalid-cwe: {cwe}"));
    }
}

fn validate_enum(
    key: &str,
    metadata: &BTreeMap<String, String>,
    allowed: &[&str],
    failures: &mut Vec<String>,
) {
    let Some(value) = metadata.get(key) else {
        return;
    };
    if !allowed
        .iter()
        .any(|allowed| value.eq_ignore_ascii_case(allowed))
    {
        failures.push(format!("invalid-{key}: {value}"));
    }
}

fn validate_forbidden_tokens(text: &str, failures: &mut Vec<String>) {
    for token in FORBIDDEN_TOKENS {
        if text.contains(token) {
            failures.push(format!("forbidden-token: {token}"));
        }
    }
    if text.contains("http://") || text.contains("https://") {
        failures.push("forbidden-callback: non-localhost callback literal".to_string());
    }
}

fn validate_fixture_corpus(
    fixtures: &Path,
    match_text: Option<&String>,
    failures: &mut Vec<String>,
) {
    let Some(match_text) = match_text else {
        return;
    };
    let vulnerable = read_fixture_texts(&fixtures.join("vulnerable"));
    let patched = read_fixture_texts(&fixtures.join("patched"));
    if vulnerable.is_empty() {
        failures.push("missing-fixtures: vulnerable corpus is empty".to_string());
        return;
    }
    if patched.is_empty() {
        failures.push("missing-fixtures: patched corpus is empty".to_string());
        return;
    }
    if !vulnerable
        .iter()
        .any(|fixture| fixture.contains(match_text))
    {
        failures.push("fixture-miss: no vulnerable fixture matched".to_string());
    }
    if patched.iter().any(|fixture| fixture.contains(match_text)) {
        failures.push("fixture-false-positive: patched fixture matched".to_string());
    }
}

fn read_fixture_texts(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter_map(|path| fs::read_to_string(path).ok())
        .collect()
}

struct Report<'a> {
    decision: &'a str,
    generic_eligible: bool,
    target_owned: bool,
    candidate: &'a Path,
    failures: &'a [String],
    written_rule: Option<&'a Path>,
    metadata: &'a BTreeMap<String, String>,
}

fn write_report(path: &Path, report: &Report<'_>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("output create failed: {err}"))?;
    }
    let failures = report
        .failures
        .iter()
        .map(|failure| format!("\"{}\"", json_escape(failure)))
        .collect::<Vec<_>>()
        .join(",");
    let metadata = report
        .metadata
        .iter()
        .map(|(key, value)| format!("\"{}\":\"{}\"", json_escape(key), json_escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    let written_rule = match report.written_rule {
        Some(path) => format!("\"{}\"", json_escape(&path.display().to_string())),
        None => "null".to_string(),
    };
    let body = format!(
        concat!(
            "{{\n",
            "  \"schema_version\":\"1.0\",\n",
            "  \"decision\":\"{}\",\n",
            "  \"generic_eligible\":{},\n",
            "  \"target_owned\":{},\n",
            "  \"candidate\":\"{}\",\n",
            "  \"failures\":[{}],\n",
            "  \"written_rule\":{},\n",
            "  \"metadata\":{{{}}}\n",
            "}}\n"
        ),
        report.decision,
        report.generic_eligible,
        report.target_owned,
        json_escape(&report.candidate.display().to_string()),
        failures,
        written_rule,
        metadata
    );
    fs::write(path, body).map_err(|err| format!("output write failed: {err}"))
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            ch => vec![ch],
        })
        .collect()
}
