use crate::baseline;
use crate::cli::TriageArgs;
use crate::{DastSpikeError, Result};
use dast_spike_rules::{SuppressionScope, BASELINE_HARD_LIMIT};
use dialoguer::{Confirm, Input, Select};

pub fn run(args: TriageArgs) -> Result<()> {
    if args.review {
        return review(args);
    }
    let plugin_id = args.plugin_id.ok_or_else(|| {
        DastSpikeError::Usage(
            "dast-spike triage requires <PLUGIN_ID> unless --review is set".to_string(),
        )
    })?;
    let (mut doc, _) = baseline::load_or_empty(&args.baseline, true)?;
    if doc.suppressions.len() >= BASELINE_HARD_LIMIT {
        return Err(DastSpikeError::Usage(format!(
            "baseline at hard limit {BASELINE_HARD_LIMIT} - run 'dast-spike triage --review' first"
        )));
    }

    let scope = match args.scope_url_pattern {
        Some(pattern) => SuppressionScope::UrlPattern {
            url_pattern: pattern,
        },
        None => {
            let choices = ["url_pattern", "global"];
            let selected = Select::new()
                .with_prompt("Suppression scope")
                .items(&choices)
                .default(0)
                .interact()
                .map_err(|err| DastSpikeError::Usage(err.to_string()))?;
            if selected == 0 {
                let pattern: String = Input::new()
                    .with_prompt("URL pattern")
                    .interact_text()
                    .map_err(|err| DastSpikeError::Usage(err.to_string()))?;
                SuppressionScope::UrlPattern {
                    url_pattern: pattern,
                }
            } else {
                SuppressionScope::Global { global: true }
            }
        }
    };

    let justification = match args.justification {
        Some(value) => value,
        None => Input::new()
            .with_prompt("Justification")
            .interact_text()
            .map_err(|err| DastSpikeError::Usage(err.to_string()))?,
    };
    let author = args
        .author
        .or_else(|| std::env::var("GIT_AUTHOR_EMAIL").ok())
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "unknown".to_string());
    let suppression = baseline::new_suppression(
        args.scanner,
        plugin_id,
        scope,
        justification,
        author,
        args.expires_in_days,
    );
    suppression.validate()?;
    doc.suppressions.push(suppression);
    doc.validate(baseline::today(), true)?;
    baseline::save(&args.baseline, &doc)?;
    println!("baseline updated: {}", args.baseline.display());
    Ok(())
}

fn review(args: TriageArgs) -> Result<()> {
    let (mut doc, _) = baseline::load_or_empty(&args.baseline, true)?;
    let today = baseline::today();
    let mut changed = 0;
    for suppression in &mut doc.suppressions {
        if suppression.expires_at >= today {
            continue;
        }
        let prompt = format!(
            "Extend suppression {} expired {}?",
            suppression.plugin_id, suppression.expires_at
        );
        let keep = Confirm::new()
            .with_prompt(prompt)
            .default(false)
            .interact()
            .map_err(|err| DastSpikeError::Usage(err.to_string()))?;
        if keep {
            suppression.expires_at = today + chrono::Duration::days(args.expires_in_days);
            suppression.review_count += 1;
            changed += 1;
        }
    }
    doc.validate(today, true)?;
    baseline::save(&args.baseline, &doc)?;
    println!("reviewed {changed} suppression(s)");
    Ok(())
}
