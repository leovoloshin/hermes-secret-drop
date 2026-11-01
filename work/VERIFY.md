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
state are readable. The later producer report
`/home/leo/tglens/artifacts/release-report-135.md` identifies `window()->grab()`,
so these are **Qt widget captures from a macOS QA process**, not OS WindowServer
screenshots or proof of physical visibility/focus/modality. The server is a local
mock, not authenticated Spark. No publication was authorized. The report's old
`--owner leo`/predictable-tmp live recipe was rejected; fake-owner fixtures must
come only from a later reviewed Spark ROOT-STEPS block, never native ad-hoc setup.

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

### iOS audit and artifact metadata follow-through

Parent challenged the original rejection reasoning: absent push entitlements do
not rule out local notifications. Run-5 reopened for a narrow unit; a fresh
hunter and independent re-verifiers traced the one main-app producer (incoming
calls, no URL) and the URL-producing extension (not shipped). Both rejections
stand with corrected evidence. Parent then ran validators: **2 records / 32 units
valid** (19 covered, 2 candidate linked to rejected records, 2 blocked, 9 OOS).
The final signed/installed metadata and legacy-notification/platform facts remain
unobserved; the first closure was not used to conceal the coverage gap.

Parent independently streamed only `Telegram.app/Info.plist` inside offline
Docker after the ordinary archive reader hit its 64 MiB per-member limit.
Bundle ID and build match, URL schemes are exactly telegram/tg/tonsite/ton/tc,
with no tglens/rubric scheme; plist SHA-256:
`461cab539dc7bf2d51f379dd45d6b625eba16ef0cd8e8ddb9ccf22ed7cf405d9`.
Actual staged tar SHA-256 matches the owner's
`2d0e8369807e85def2f6f057304197532b8e8b6760947973632d478d9ce4cdbb`.
The auditor's read-only Apple metadata check confirms the same staged bundle has
no associated-domains or aps-environment; it is ad-hoc signed, not the final
lbm/phone signature. No app code was executed for these metadata checks, and the
throwaway reader was removed. Final signed/installed metadata remains unobserved.

Build 100028 fixes the false cancel/timeout confirmations and denies unattested
OS/notification vault entry. Owner freeze:
`dd95bd5a78f3a70a331d7b59730854a661764cc6`, studio1
`591717368ed8089656f95953a92b9426e413048f`; private artifact SHA-256
`72e7cacc86c1c1afe33df90f67f45bd9e75f47a913d1d78e4bf4017c2fc3a4ca`.
Independent source/identity review in `tglens-ios/delta-100028/` confirmed the
entry deny and one-GET/no-re-POST behavior, but found a test-only production
windowless branch, save-409 reconciliation gap and a narrow sync-result race.
Those fixes passed independent read-only review at 100029 source
`dc9ef2a9bb49bb0fa76efceff9f51a99d2255482`, studio1
`a0596d183f80d0f683a1c6ed79fe699981af9edb`: plain windowless return, save-409
single-GET reconciliation, atomic result/winner publication and non-blocking
async sheet UI with closed/generation guards. Review:
`/home/leo/security-audit-skill/tglens-ios/delta-100029/`.
100029 artifact SHA-256:
`f8835de84f211ccf602b6314cb27bee8dc42413073f48ac9e036ac3791788be8`.
Old 100027/100028 artifact hashes remain unchanged. The owner reports all nine
test phases and 47-file/113-marker hooks passing; independent review executed
no app or test and does not claim positive real-UIWindow presentation.

Artifact/doc-only commit `ef046cc493e63c7df765ccf97d000a8581acbbfd` adds six
fresh 1320×2868 fixtures tagged 100029 without changing source. Parent inspected
all six: both kinds, Give it here/Saved, confirmed-200 cancellation and an
unconfirmed-503 cancellation with both fields cleared and no false no-save claim.
The main unknown outcome is readable; its trailing diagnostic is ellipsized.
These remain offscreen UIKit/URLProtocol/simulated-keyboard layout evidence,
not phone, OS keyboard, positive UIWindow or live authenticated proof.

### Artifact privacy boundary

Name/source inspection confirms the private 100027/100028/100029 iOS bundles contain
`Telegram.app/tglens_canvas_token`, copied by the existing Canvas pipeline.
This is the Canvas relay credential, **not** the Vault bearer; no token contents
were read or printed. It is separate from the vault's per-device Keychain import.
The existing design remains an explicitly out-of-scope Canvas/supply-chain
release fact, not a claim that every secret in the app is safe. Artifacts must
remain private 0600 inside 0700, never Git/public uploads. The builder did not
change, rotate or remove that credential or authorize broader distribution.

### Desktop follow-through

Build 136 fixes the Team ID guard and misleading memory-clearing copy. Its
source freeze is 83fb1a6802 (compiled code 0a9079742e); staged archive SHA-256 is
`be2e763d867be92a9d713829300c8056b8d3ef85d32e563aa35cacd6c744b8fd`.
Parent inspected the corrected Saved capture. Report:
`/home/leo/tglens/artifacts/release-report-136.md`.
Actual OS capture is blocked: `CGPreflightScreenCaptureAccess()==0`, screencapture
exit 1, “could not create image from display”; no TCC/security settings changed.
The Qt widget captures prove layout only. UI suite: owner-observed **4/4 in
28.059s**, with the existing 3/18/6 invariant/security suites and hooks green.

The desktop audit's independently traced functional blockers were integrated
in build 138 source `d4443f31baa12be764051c4c06e276c265c25d66`: fresh full-bundle
signing provenance, pinned digest/commit/entitlements, no active-app overwrite,
passcode-lock local teardown/no server cancel plus all-layout submit/raise/event
gates, native peek teardown/refusal, helper signature validation, process core
limit and metadata-only tri-state token presence. Source report:
`/home/leo/tglens/artifacts/release-report-138.md`. Staged archive SHA-256:
`6fec374b538f9423bee7de928c34fca776b0f341d255ed470f18344afefdbbae`.
Owner-observed gates: 29 files/45 hooks, invariants 3/3, MCP 18/18, updater 7/7
(six actual-script negative cases), UI 4/4 in 32.494s Linux / 22.77s macOS.
These are reported functional results, not a parent attestation of native sandboxing.

Run-5 is frozen at build 136: **9 findings valid / 38 units valid**, parent
validators passed; 0 confirmed, 7 needs-validation and 2 rejected. New full
scoped run-6 is reviewing the actual 138 source/artifact, including all changed
boundaries and retained platform facts. No current-source T3 approval or macOS
publication is claimed while it is in progress.
OS exploitability remains needs-validation, not a fabricated confirmed finding.
Older signed-build Keychain trust and private signing-key ACL facts require
Leo's decision; no key/group/credential changes or real probes are authorized.

LBS root-update receipt `work/live-probe-kind-update/root-update.json` was checked
and is absent. The reviewed a6782de root handoff remains unexecuted by the builder.

### Original owner restoration

After the mass OMP exit, neither native owner was in the agent registry, but
both original panes remained at their bash prompts. LBS explicitly authorized
restoring both saved sessions, with original models and working trees preserved.
Parent used `herdr agent start --kind omp --restore <exact saved session>` in
the existing `w1Z:p2` and `w24:p2` panes. Both reached interactive readiness;
their session IDs are unchanged and both live status bars show Gemini 4 Argon.
No model override, new owner, reset, clean, checkout, stash or native file edit
was performed by the parent. Unrelated MCP startup auth failures were not acted on.

Desktop HEAD at recovery was `ead02fa0705e3e202600197d5d7517c999e06dc1`
(build-138 code-equivalent artifact/doc commit), with no 139+ handoff. The
interrupted working tree is retained. The restored owner is finishing the
validated main-chat FullMsgId route, existing crash-reports-disable policy,
truthful immutable compiled-source metadata and SDK-correct signing/manual-update
policy before a fresh integration build/freeze. Run-6 is completing only its
138 snapshot while awaiting that legitimate final handoff; it does not approve
uncommitted work. The iOS owner keeps source dc9ef2a / reviewed 100029 frozen,
with actual phone/OS/live-auth prerequisites still blocked.

### Final full desktop audit at 142

The restored owner froze build 142 code
`5804bb33fcdb5287eb0344f28668f3162e891f67`; artifact/report-only commit
`f9b65465f397ba226d38b925afa8559b1be4e942` leaves that code unchanged.
Write-once staged archive SHA-256:
`b398a85ad2020c422b302520c2ec48a0602ea1b164349ddc3c4149491700e8b1`.
The independent audit checked the commit-before-stage chain, matching metadata,
no Helpers/crashpad members and both automatic-update keys false.

Run-6 completed at exactly that source, preserving 138/141 snapshots. Parent
validators passed: **3 findings valid / 60 coverage units valid**. Result:
0 confirmed, 3 needs-validation trust leads; 46 covered, 3 linked to those leads,
1 blocked Linux-runner unit and 10 out of scope. The remaining facts are the
lbm signing-key access/partition policy, legacy Keychain trust of other same-team
builds (recorded 105 and 111–131), and self-hosted CI runner host/account/group
and write/dispatch principals. These were not probed or accepted on Leo's behalf.

142 uses an actual top-level application-modal dialog and authoritative
QGuiApplication focus-window gating. Involuntary focus loss keeps a wiped,
disarmed modal until deliberate dismissal; root external-UI/control routes are
blocked while armed or paused. App-owned crash reports are compiled out by the
pipeline. Parent inspected the explicit paused-state layout artifact
`desktop_142_vault_paused.png`: no credential fields, clear explanation and visible
pointer Dismiss. It is Linux offscreen/local-mock rendering only—not Cocoa,
physical activation, real Keychain or authenticated live proof.

The report discloses a five-minute three-hunter overlap, an early source probe
file and /dev/shm copy that were removed, and truncated replies recovered from
validated scratch copies. No flawless-process or exhaustive-security claim is made.

The final notes exposed bounded contract/cutover gaps: a second agent-peek entry,
over-broad vault host/request matching and session selection, a vacuous
click-exclusion test, and legacy producer/promoter paths that bypass current
validation or can report READY after signing failure. The original owner is
finishing those, source-level crash-off enforcement, standard DER generation
and dead-code removal in a new freeze. The 142 full audit does not approve that
future code; it will receive separately scoped independent T1/T2 review.
Rollback minimum policy, existing dumps, keys/groups, CI permissions and account
data are not being changed.
