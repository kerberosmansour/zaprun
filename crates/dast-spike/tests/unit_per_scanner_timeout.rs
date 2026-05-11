use dast_spike::scan::run_command_with_timeout;
use std::process::Command;
use std::time::Duration;

#[test]
fn command_timeout_is_enforced() {
    let mut command = Command::new("sh");
    command.arg("-c").arg("sleep 2");
    let err = run_command_with_timeout(&mut command, Duration::from_millis(100)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}
