# zaprun-ptk M4 Lessons

Date: 2026-05-15

- Final-image Trivy and extracted-add-on Trivy cover different surfaces; extracted add-on POM metadata can reveal upstream bundled dependency issues not visible in the image scan.
- The latest official ZAP Network add-on is still `network-v0.27.0`, so Netty CVE exceptions need a narrow `.trivyignore` entry plus a dated tracking issue.
- The release smoke should apply a minimal PTK Automation Framework config, not just list add-ons, because add-on loadability alone did not catch the Quick Start headless failure.
