# zaprun-ptk M2 Lessons

Date: 2026-05-15

- `env.configs` should stay typed and narrow for PTK Phase 1; arbitrary key/value config would reopen the stringly YAML surface this project avoids.
- `spiderClient` needs explicit bounds for browser count because PTK runs real browsers and can consume materially more CPU and memory.
- Existing plan invariants, especially no runtime add-on install and empty-context rejection, carried cleanly into the PTK plan path.
