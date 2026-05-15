# zaprun-ptk M1 Completion

Date: 2026-05-15

Completed image-level PTK groundwork:

- Baked checksum-pinned Client Side Integration `0.24.0` and OWASP PTK `0.4.0` add-ons.
- Preserved the no-runtime-add-on-install invariant with structural tests.
- Removed GUI-only Quick Start from the headless image after the PTK config smoke exposed a ZAP 2.17.0 headless startup failure.
- Verified image build, add-on presence, ZAP startup, and `zaprun` CLI smoke.
