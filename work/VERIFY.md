# Installed Spark vault verification

Probe: `20261031-200f6a5bf966`.

Authorization: `work/LBS-INSTALL-DONE.md` and subsequent direct LBS instructions. Observed unauthenticated/authenticated status matrices are in `docs/TESTING.md` (do not interpret client-marker tests as actual Funnel traffic).

## Completed

- LBS reports the reviewed setup block ran as root successfully: installed library matches repo, registry backed up, vault service active, private 0600 header/metadata handed off, and gateway/plugin/Funnel/principals untouched.
- Builder read only the non-secret `root-ready.json` metadata into the transcript. Private input/header file permissions/ownership were checked in-process; their values were not printed.
- Authenticated live curl matrix and fake canary save completed at `2026-10-31T17:45:40Z`. Every expected status passed; save returned exactly the handle-only object. Each response was checked in-process for canary/bearer absence.
- Curl disabled .curlrc (`-q`), used an empty allowlisted child environment and file-based auth/body input, and deleted private temporary request/response files. No canary/bearer values were placed in argv, environment, URLs or displayed output.
- Safe machine-readable client evidence exists at ignored `work/live-probe-20261031-200f6a5bf966/client-results.json`. The original fake pattern and test header remain 0600 in a 0700 ignored directory for the next step.

## Fixture scope

Owner/device: `probe-20261031-200f6a5bf966`.
Handle/template: `canary.20261031-200f6a5bf966`.
This is an isolated fake-owner namespace, not Leo's real device or Telegram principal mapping. No real secret or real target is involved.

## Next root gate

`work/ROOT-STEPS.md` now contains ONLY the next broker/scan/revoke block; do not rerun old setup/rollback. It validates the pinned canary/helper digest, invokes the installed broker, immediately removes this template/device and verifies old bearer HTTP 401, then scans before deleting evidence. Scans filter exact raw canary bytes from fake ciphertext, audit, all exported journal fields since setup and required state.db (optional WAL/SHM), never printing matches or querying SQL. Only after scans pass are fake namespace/helper/private credentials removed.

Broker use, root-only absence scans and cleanup are **not yet verified**. `LBS-VAULT-SPARK-DONE` remains pending the root metadata-only proof. No root action was executed by the builder, and no gateway restart, plugin enable, Hermes config edit, Telegram send, Funnel/other Serve change or thedoorpc action occurred.

## Review

Both handoffs received focused T1/guidance reviews. Setup's initial three low issues were fixed. The next block's review fixes revoke the credential before long scans, export all journal fields, require state.db, label raw-byte search limits, record granular cleanup progress and discard journal stderr. Re-review found no new Critical/High/Medium/Low issues; syntax was checked without execution. Product code is unchanged; the prior full T3 audit and its deployment gates/needs-validation leads are unchanged.
