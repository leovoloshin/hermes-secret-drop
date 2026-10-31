# Installed Spark vault verification

Probe: `20261031-200f6a5bf966`.

Authorization and operator-reported installation: `work/LBS-INSTALL-DONE.md`.
Builder-observed unauthenticated status matrix is recorded in `docs/TESTING.md`; the served malformed request was rejected at authentication, and Funnel-marker refusal was observed directly on loopback. A client marker sent through Serve is stripped, not proof of real Funnel behavior.

## Current checkpoint

- Bounded unauthenticated requests completed; no bodies, headers, canary or bearer values printed.
- Generated a fresh fake canary into `work/live-probe-20261031-200f6a5bf966/canary.txt` with 0600 under a 0700 directory. The directory is git-ignored. Its contents have not been read into the model transcript or arguments.
- Exact root setup commands are in `work/ROOT-STEPS.md`. Root block and generated helper syntax were checked without executing the root setup.
- The planned fixture owner/device is `probe-20261031-200f6a5bf966`; handle/template is `canary.20261031-200f6a5bf966`. It cannot overwrite Leo's namespace. No `--telegram-owner-id`, principal-policy update or real-device provisioning is requested.
- Root setup has **not** been executed by the builder. Authenticated matrix/save, installed broker use, ciphertext/audit/journal/state.db canary scans, and fixture cleanup/revocation remain unverified.

Next: LBS runs the setup block in `work/ROOT-STEPS.md`, then returns the metadata-only result. Builder uses the private header/body files for real served-URL probes. The subsequent root step performs broker use, exact-canary-only scans (never message dumps), and scoped fixture cleanup.

No gateway restart, plugin enable, Hermes configuration edit, Telegram send, Funnel enable, other Serve path change, real secret or thedoorpc action is authorized by this probe. `LBS-VAULT-SPARK-DONE` has not been earned.

Focused T1/guidance review of the root handoff completed read-only. Three initial low findings were corrected: no bytecode writes to the frozen installed package, helper/template validation before provisioning with scoped failure cleanup, and pinned directory-fd handoff I/O plus root-owned curl headers with `-q`. Re-review found no blocking code, syntax or data-scope issues. Both root heredocs and the generated helper parse successfully; none of those root actions has run. The installed product code is unchanged, so no new service build/restart or production audit attack was run by the builder.
