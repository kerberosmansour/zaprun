# zaprun-ptk M3 Lessons

Date: 2026-05-15

- A separate `zaprun ptk` lane keeps PTK Phase 1 behavior explicit instead of quietly changing `scan` or `api`.
- The command should produce the same artifact family as existing scans: `plan.yaml`, `run.json`, `summary.json`, `coverage.json`, `zap-report.*`, and `zap.sarif`.
- A NodeGoat PTK run exits `1` when High findings are present; artifact completeness is the success signal for execution, while the exit code is the security policy result.
