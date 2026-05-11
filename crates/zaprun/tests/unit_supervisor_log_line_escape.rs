use zaprun::supervisor::escape_log_line_for_tracing;

/// Per critique F-SEC-6 (CWE-117): the tracing mirror must escape control
/// characters and truncate over-long lines. Raw bytes go to `zap.log`
/// verbatim; the structured tracing mirror is what gets escaped.
#[test]
fn newlines_escaped_for_tracing_mirror() {
    let injected = "\nINFO scan complete";
    let safe = escape_log_line_for_tracing(injected);
    assert!(
        !safe.contains('\n'),
        "newline must not survive into the tracing mirror: {safe:?}"
    );
}

#[test]
fn carriage_returns_escaped() {
    let safe = escape_log_line_for_tracing("foo\rbar");
    assert!(!safe.contains('\r'));
}

#[test]
fn ansi_escape_chars_escaped() {
    let injected = "\x1b[2J\x1b[Hclear screen";
    let safe = escape_log_line_for_tracing(injected);
    assert!(
        !safe.contains('\x1b'),
        "ANSI escape must not survive: {safe:?}"
    );
}

#[test]
fn long_line_truncated_at_4_kib() {
    let huge = "A".repeat(8 * 1024);
    let safe = escape_log_line_for_tracing(&huge);
    assert!(
        safe.len() <= 4 * 1024 + 32,
        "line must be truncated at 4 KiB (got {} bytes)",
        safe.len()
    );
    assert!(safe.contains("...") || safe.contains("[truncated"));
}

#[test]
fn ordinary_ascii_passes_through_intact() {
    let safe = escape_log_line_for_tracing("ZAP started on 0.0.0.0:8080");
    assert!(safe.contains("ZAP started on"));
}
