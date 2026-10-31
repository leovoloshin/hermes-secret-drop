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

Owner/device `probe-20261031-200f6a5bf966`, handle/template `canary.20261031-200f6a5bf966` are revoked/removed. **Do not rerun the historical probe block (`eb005c9:work/ROOT-STEPS.md`) or reuse that fixture.** The current ROOT-STEPS is a separate on-demand code-update handoff.

The original installed Spark verification is complete. At that closure, pytest was **105 passed in 9.26s** and product code was audited at `816904d`; that milestone changed documentation only. The later on-demand addendum supersedes the request/save contract, so this live proof is not a claim that the new `secret|login` code has been installed or live-tested.

Plugin enable, gateway restart, principal changes, real-secret onboarding and Serve changes remain Leo's call and were not performed. Native iOS `w24:p2` and desktop `w1Z:p2` acceptance/visual verification continue separately; this is not the global native-product done signal.

## Review

Both root handoffs received focused T1/guidance review. Reported low issues were corrected; rereview found no new Critical/High/Medium/Low issues. Root syntax was checked without executing root actions by the builder. Prior full T3 needs-validation leads (local slot cycling and conditional redaction oracle), host trust gates and native UI scope remain explicitly unchanged.

## Native continuation checkpoint

User directed continuation with iOS owner `w24:p2` and desktop owner `w1Z:p2`. Parent inspected the existing four iOS 100026 and five desktop 132 vault PNGs: layouts are readable and values visually masked; saved/cancel confirmations show metadata. Provenance matters: iOS images are UIKit controller fixtures with mock transport, and desktop images are Qt fixtures against a local contract server—not authenticated native saves to the live Spark service or proof of macOS publication.

Parent's computer facade has no display/capture/input backend on this host; real device/macOS capture must use the owners' established remote native verification path. No direct live desktop screenshot was fabricated.

Integrated source checks identified iOS display-name-to-bot-ID trust minting, Keychain cache/readback failure bypass and missing strict handoff guards, plus macOS Keychain-to-plaintext-file fallback. Owners were instructed to fix these, add behavior-level regressions, preserve real credentials/data, and freeze final code for independent review. Memory-clearing UI copy must describe field clearing, not certify all process memory.

Scoped full T3 native run-4 audits completed on the earlier freezes, source-only: iOS `10089629` / studio1 `47b4057` has no confirmed findings and one unresolved UIKit composer-refocus lead; desktop `a5eda9e017` has no confirmed findings, two unresolved macOS focus/Keychain-identity leads, and one rejected late-reply vulnerability claim (still a robustness issue). Parent validated both findings/coverage files: iOS 3 records/24 units, desktop 3 records/19 units. Owners subsequently changed focus/signing/QA gates and began the on-demand UI; these older audits are not final approval of the new code. New frozen hashes require delta revalidation. Existing publication jobs must remain immutable/unduplicated, with source/build provenance preserved. Native production/Keychain/live-auth and final visual acceptance are not yet complete; no global `LBS-VAULT-DONE` signal.

## On-demand addendum

`work/ADDENDUM-ONDEMAND.md` replaces proactive entry with one allowlisted request action and mandatory `secret|login`. The API contract is `docs/VAULT-API.md`; both native owners received the exact body/error/status contract. New code is not deployed by the builder: root vault update/test provisioning remains a reviewed LBS step. Plugin activation, gateway restart, principal and Serve changes remain forbidden here.

Spark on-demand code proof: **192 passed in 28.79s** in the offline Docker sandbox.
The separate service/broker cold-start smoke of the kind cutover, before final
short-prefix hardening, passed all **29 checks in 3.55s**,
with temporary state removed. Both kinds save/use correctly; request-only and
kind/field bindings hold; fake credentials remain out of results, argv/environment
and plaintext files/logs. A separately reproduced pre-existing timeout/cutoff
password-prefix leak is fixed and covered by eight actual-target regressions,
including sub-four-byte prefixes at abnormal cuts in the final full-suite run.
The before/after probe printed booleans only; no canary/bearer values or raw
tracebacks were shown. Throwaway scripts were removed. Details: `docs/TESTING.md`.

On-demand API code committed/pushed as `88e6a783887b8d3d22c4aabd61bb408dc0a63551`;
`VAULT-API-KINDS-READY` emitted. Root handoff prepares that exact code archive,
not the mutable checkout; root deployment remains unexecuted by the builder.

### iOS 100027 visual checkpoint

Owner reports frozen/pushed local `68c2b5e`, studio1
`1804bde0e0648e4d1506a463057b6a81990a0588`, patch SHA-256
`569027ce75a60721a014ea607480844fca49a5080ca435d290a0b067218d2f9f`.
Report: `/home/leo/tglens-ios/artifacts/ios-100027-vault-ondemand-report.md`.
Parent inspected all five 1320×2868 PNGs: one masked field for secret, plain
username plus masked password for login, read-only sentence/small handle,
adjacent buttons, Give it here→Saved, and cleared cancellation state.

These are offscreen native UIKit controller renders with contract transport and
a simulated keyboard overlay—not a running simulator/physical device, real OS
keyboard/focus or authenticated Spark save. CoreSimulator framework/runtimes are
absent on studio1; lbm/device verification remains pending. Scoped full T3 run-5
is underway on the new freeze; earlier run-4 is not its approval. Desktop owner
continues build 135 on-demand implementation/verification; no new publish is
authorized before its final-source audit delta.

### Desktop 135 visual/source checkpoint

Owner reports on-demand freeze `1c564ca950` and build `7.3.4-tglens.135`,
with 4/4 local-mock UI tests in 23.73s and existing hook/security suites green.
Parent inspected five `macos_135_vault_*` PNGs: secret and login field counts,
masking, read-only context, adjacent buttons, saved confirmation and chat Saved
state are readable. Owner identifies these as studio1 WindowServer captures
against a local mock vault—not authenticated Spark or Leo's running app.
Capture/build provenance metadata was requested; no publication was authorized.

The new full T3 run-5 caught a functional fail-closed blocker: the production
signer gate compares `5KQRTTL9DS`, but recorded actual signatures use
`5KQRRTL9DS`. Parent independently read both the source and prior codesign
record; QA's early return masked the failure. Owner is correcting the constant
without changing signing/groups or bypassing the check, and removing the
saved-sheet memory-erasure overclaim. `1c564ca950` is not approved for publication;
the corrected freeze and artifact require revalidation.

### New root update handoff

`work/ROOT-STEPS.md` now addresses only the immutable `88e6a78` code update with
`--no-serve`; no fixture/device/request is created yet. A fresh bare clone with
pinned tar settings reproduced the archive SHA-256
`d9eda685359d5ec5bc3ce42d25628d63ab147459ee8c56f48c8f6208bb0da61d`;
the tar's git commit ID equals the pinned full commit. AST parsing passed without
executing root code. Read-only systemd metadata found the gateway active and both
vault unit fragments at the expected paths, empty drop-ins and no daemon reload
needed. Protected root data/template checks remain root-operator preflights,
not facts inferred by the builder.

Root update handoff review is complete: focused T1/guidance rereviews found no
remaining issue in the final block. Corrections include fixed error codes/command
labels, data preflight before code replacement, explicit template-kind refusal,
archive commit/digest binding, interruption-safe installer waiting, uncertain
outcome handling and changed vault InvocationIDs to prove restart. Final AST
parse passed; **the builder did not execute the root block**. Root-owned data,
templates and config are checked by the block before changes, not presumed safe.
LBS must review/run it and return metadata-only `root-update.json`; no fake
credentials or ten-minute native requests are created in this deployment step.
