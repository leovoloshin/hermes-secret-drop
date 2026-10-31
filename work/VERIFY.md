# Installed Spark vault verification — complete

Probe: `20261031-200f6a5bf966`.

Authorization: `work/LBS-INSTALL-DONE.md` and direct LBS instructions. Detailed observed HTTP matrices and scan summary: `docs/TESTING.md`.

## Evidence and provenance

- LBS reports installation of reviewed source `9257f01`: 13 changes, both units active, tailnet Serve path installed, gateway untouched, plugin staged/not enabled.
- LBS ran the reviewed setup; installed library matches repo, registry backed up, disposable device/header created in the isolated fake owner namespace. No real owner device or Telegram principal mapping was provisioned.
- Builder authenticated live curl matrix/save passed on `2026-10-31T17:45:40Z`. Expected statuses all matched; save response was exactly the handle-only object. Response bytes were checked in-process for canary and bearer absence. Private file-based input, curl `-q`, allowlisted empty child environment and private disposable response files kept values out of arguments/environment/URLs/displayed output.
- LBS ran the reviewed broker/scan/revoke block as root at `2026-10-31T18:17:47Z`–`18:17:51Z`, exit 0 and root-probe-complete signal. Builder read metadata-only `root-proof.json`: status passed, broker exit 0/no timeout, output exactly `accepted:[REDACTED]`, revoked bearer HTTP 401.
- Root exact-pattern scans found no raw canary in fake owner ciphertext, current audit, state.db, WAL or SHM; all exported journal fields since setup were also negative. Previous audit archive did not exist. This is finite raw-byte/export evidence, not SQL row reconstruction or arbitrary encoding/compression detection. No matching lines or message contents were displayed.
- Root proof records test template/device removal, HTTP service restart, fake ciphertext/helper/directory deletion, private credential removal and leo bearer-handoff removal; vault key retained. LBS reports vault service active. No gateway/plugin/principal/Serve modification by that block.

## Retained private test evidence

Ignored directory: `work/live-probe-20261031-200f6a5bf966/` (0700).
Metadata: `root-ready.json`, `client-results.json`, `root-proof.json` (0600 leo).
Original generated fake `canary.txt` remains private for exact-pattern verification. Its contents and the bearer have never been printed or read into model arguments/transcript. Never commit or dump these private artifacts; the public notes contain no values.

## Scope and remaining activation

Owner/device `probe-20261031-200f6a5bf966`, handle/template `canary.20261031-200f6a5bf966` are revoked/removed. **Do not rerun ROOT-STEPS or reuse the fixture.**

Spark verification is complete. Last full pytest result: **105 passed in 9.26s**; final code audited at `816904d`, T3/T1 reports and deployment gates in `docs/SECURITY-REVIEW.md`. New work only records operator/observed evidence; product code unchanged.

Plugin enable, gateway restart, principal changes, real-secret onboarding and Serve changes remain Leo's call and were not performed. Native iOS `w24:p2` and desktop `w1Z:p2` acceptance/visual verification continue separately; this is not the global native-product done signal.

## Review

Both root handoffs received focused T1/guidance review. Reported low issues were corrected; rereview found no new Critical/High/Medium/Low issues. Root syntax was checked without executing root actions by the builder. Prior full T3 needs-validation leads (local slot cycling and conditional redaction oracle), host trust gates and native UI scope remain explicitly unchanged.
