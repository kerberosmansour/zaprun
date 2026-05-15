# zaprun-ptk M1 Lessons

Date: 2026-05-15

- PTK Phase 1 needs both `client` and `ptk` add-ons baked into the image; runtime Marketplace installation remains blocked.
- ZAP's GUI-oriented Quick Start add-on trips a headless Automation Framework config path in ZAP 2.17.0, so the hardened CLI image removes `quickstart-*.zap`.
- Add-on supply-chain inputs are pinned by version, URL, and SHA-256; image smokes verify presence and loadability.
