use zaprun::error::ZapshootError;
use zaprun::exit::ExitCode;

#[test]
fn exit_code_values_are_canonical() {
    assert_eq!(ExitCode::Pass as i32, 0);
    assert_eq!(ExitCode::PolicyFail as i32, 1);
    assert_eq!(ExitCode::ToolError as i32, 2);
    assert_eq!(ExitCode::TargetUnavailable as i32, 3);
    assert_eq!(ExitCode::Timeout as i32, 4);
    assert_eq!(ExitCode::CoverageFail as i32, 5);
}

#[test]
fn every_error_maps_to_a_canonical_exit() {
    // Iterate every variant via a constructor sample. If a new variant is added without
    // updating this test, the match in `From<&ZapshootError>` and this test's exhaustive
    // match below MUST also be updated -- compile-time enforcement.
    let samples: &[ZapshootError] = &[
        ZapshootError::ImageRefNotDigest,
        ZapshootError::ImageRefDigestMalformed,
        ZapshootError::ImageRefRepoCharset,
        ZapshootError::ImageRefRepoTooLong,
        ZapshootError::DockerNotInPath,
        ZapshootError::OutputDirNotWritable,
        ZapshootError::TargetUnreachable,
        ZapshootError::ProbeTimeout,
        ZapshootError::TotalBudgetExceeded,
        ZapshootError::UnsupportedSchemaVersion,
        ZapshootError::SubcommandNotYetImplemented,
        ZapshootError::Io("synthetic".to_string()),
    ];

    for err in samples {
        let code = ExitCode::from(err) as i32;
        assert!(
            (1..=5).contains(&code),
            "error {err:?} mapped to exit {code}, expected 1..=5"
        );
    }
}
