# LBS vault security review

## Reviewed source and result

- **Tier 3:** full, standard-profile source/local audit of Spark service, encrypted store, broker, staged plugin, installer, units and docs. Frozen code: `816904d95f7a3189386b49b8f39cffbec9f2cebc` (base `505bd3b`). No earlier audit ledger existed.
- **Tier 1:** independent `security-reviewer` passes over the initial diff and subsequent code deltas, including `8c95f9f..816904d`. Final delta: no high or medium defects; low/informational hardening notes remain in the external report.
- Final structured result: **0 confirmed vulnerabilities, 2 needs_validation records, 20 rejected/fixed records**. Needs-validation records have no severity. This is not a claim that deployment is risk-free or authorized for real secrets.
- Coverage: **43 units: 37 covered, 2 candidate linked to needs_validation, 4 out of scope**. Native Rubric clients/visual verification, Hermes core, host deployment state, and tests as shipped code are outside this Spark audit scope. Tests were inspected/exercised as evidence.
- Parent ran both validators after closure: `PASS: 22 findings valid`; `PASS: 43 coverage units valid`.

Full artifacts: `/home/leo/security-audit-skill/lbs-secret-vault/run-1/` (`REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, `findings.json`, `coverage-ledger.json`, `run-metadata.json`). Evidence was independently rechecked on the frozen snapshot. Final delivery additionally corrects documentation wording; no backend/plugin code changed after `816904d`.

## Fixes independently verified

- Unprivileged backend port-squatting: production listener uses kernel-protected loopback port 938; root daemon/installer reject unprotected ports. Only HTTP unit capability is NET_BIND_SERVICE.
- Authentication rate-limit isolation: failed loopback requests cannot consume an authenticated device's budget.
- Request-line/header memory and indefinite holds: 8 KiB budgets and absolute five-second connection deadline. Continuous local slot cycling is **not** solved; see below.
- Owner authorization: device bearer owner binding, single-use encrypted request transitions, direct Telegram-owner ContextVar checks for the plugin, absent/malformed policy/context denied without environment fallback.
- Storage exhaustion: independent owner-hash Fernet documents, UTF-8 serialization, per-owner handles/request bounds and document cap; missing key with any owner ciphertext fails closed. A secondary owner can no longer consume the primary owner's document budget.
- Broker delivery: fixed root-approved template/handle binding, protected stdin only, no secret argv/environment, exact output redaction, protected executable/cwd/interpreter paths, no general-user run_as. Bounded concurrent agent workers avoid serialized abandoned execution queues; broker refuses excess use admission.
- Deployment cutover: no-follow staged copies, root-owned installed code, no candidate imports during dry-run, isolated installed-code provisioning instructions, early Serve ownership/Funnel preflight, foreign-route refusal before stopping units, uninstall limited to marked lib/plugin trees. Restore instructions invalidate old device/owner grants instead of resurrecting them.

## Outstanding validation records

### Local pre-auth slot cycling

A local process can repeatedly open sixteen zero-byte loopback connections, reconnect after the deadline, and occupy all public HTTP workers. In the isolated sandbox at the production five-second deadline, **44/44 authenticated owner saves failed over approximately eleven seconds**; saves returned 200 before and after the attack. The deadline bounds an individual hold and memory, not sustained denial of service.

Unresolved deployment fact: whether any local principal able to connect to `127.0.0.1:938` is less trusted than the owner. A `relay` uid 1001 exists; its trust/permissions were not established. Serve parses complete upstream headers before dialing the backend, so the experiment does not prove remote zero-byte tailnet connections reach this pool. Verify local-account/process trust read-only before onboarding; do not attack the live service. Sandbox evidence: `agents/v4-slot-cycling/artifacts/slot_cycle_v4.txt`.

### Output-redaction oracle

When an approved target emits attacker-controlled candidate text, markers can reveal which candidate matched. Exact-match and trailing-prefix variants were reproduced with dummy data; the latter recovered a forty-byte dummy token through repeated guesses. Exact redaction is not information-flow isolation or DLP against attacker-influenced output.

Unresolved facts: **no approved template ships** (installer seeds an empty list); deployed/custom template inventory was not inspected; no actual lower-trust output-influence/reply-observation path was identified. Before approving a real template, review the entire target, its output provenance, remote account trust, interpreters/loaders/libraries/config dependencies, and who can influence/read its output. Do not approve an attacker-influenced-output template merely because exact canary redaction passes. Evidence: `agents/v4-redact-oracle/artifacts/redact_oracle_v4.txt`, `agents/w5-broker/artifacts/trailing_prefix_oracle_check-2.txt`.

## Real-secret onboarding gates

**Root is trusted; this vault is not a sandbox against the agent's root shell.** Current gateway metadata reports `terminal.backend=local` and three numeric general Telegram allowlist entries. Their identities and per-principal root-tool access were not established. Plugin checks deny non-owner calls through the plugin, but any caller able to drive root terminal/code/file tools can read/decrypt root files or bypass the sockets directly. Before real secrets, the supervisor must verify and explicitly trust every root-capable principal, or remove/confine non-owner root-capable tools under another uid without vault, socket or process access. No such risk acceptance is recorded here. This build did not change/restart the gateway.

Additional deployment facts/gates:

- Provision the correct numeric **owner user** ID (not bot ID) into private `principals.json`; all plugin operations deny until configured. Actual deployed Hermes ContextVars and `bound_session_key()` were inspected and smoke-exercised with copied deployment source; recheck propagation/reset and isolation mode on every Hermes upgrade. `/opt/barry/hermes` is not the inspected deployment. Current plugin isolation setting was unset; host isolation without propagated trusted context denies calls.
- LBS completed root installation and the authorized live root canary proof; builder exercised real served HTTPS, and root proof recorded broker success, quiet scans and scoped revocation/cleanup. This is not exhaustive systemd confinement or installer-idempotence proof. Native Keychain/UI verification continues separately.
- Parent read-only pre-install observations: no `/lbs-vault` Serve route, Funnel:443 false, Tailscale OperatorUser unset, port 938 free, privileged-port cutoff 1024. Keep route administration root-trusted, cutoff above 938, and do not delegate NET_BIND_SERVICE to untrusted processes. These are observations, not a guarantee of future host state.
- The installed Tailscale 1.104.1 commit's Funnel-marker behavior/ordering was not verified from matching source. The app rejects `Tailscale-Funnel-Request`; installer refuses Funnel on 443. Do not enable Funnel or publicly probe the vault to test this.
- Legacy Secret Drop `.env` values, passthrough names, active plugin configuration and any preexisting/custom vault data were not inspected or migrated. Root operator must review metadata only and remove owner-approved legacy exposure at the authorized activation step without printing/retrieving old values.
- `cryptography` 48.0.0 known-advisory status was not established offline; no dependency pin/hash or CVE-free claim is made. Read-only audit metadata found its global package directory root:root 0755 and group staff empty. Global Python packages/site configuration remain trusted operator inputs.
- Root reviewers must inspect real helper dependencies and `env.PATH`; the real host `/usr/bin/env` resolution was not checked. No default command target is approved.
- Audit history is a bounded, shared rotating metadata log, not immutable forensic evidence. Root or authenticated churn can evict old history. Retained requests count against the 128-record one-day budget; cancel does not immediately free a slot.
- A use transport/audit error may follow execution. Only plugin-to-agent transport/malformed replies are mapped to `vault_outcome_unknown`; structured broker errors retain their codes. Never automatically retry without checking target state. No exactly-once crash guarantee.
- No migration from experimental pre-release `vault.enc` is provided; this builder installed no runtime data. If such data exists, preserve it and obtain root offline review before installation; do not assume the owner-hash format imports it.

## Exercised verification

All target execution used generated fake canaries in the Docker sandbox documented in `TESTING.md`: UID 1000, private loopback/no external networking, read-only source/toolchain/rootfs, empty allowlisted environment, private 64 MiB scratch, capability drop/no-new-privileges, CPU/memory/pid/file/wall-clock limits. No production endpoint, real credential, chat history, Telegram message or target reboot was involved.

- Final suite: **105 passed in 9.26s**. Includes request expiry/replay/cancel/owner binding, auth and origin/target refusals, malformed/size cases, permissions/restart persistence, per-owner capacity, real stdin target/redaction, argv/environment scans, plugin identity/context isolation, bounded concurrency, lost-reply uncertainty and installer copy attacks.
- Final separate daemon smoke on `816904d`: cold-start actual `python -m lbs_vault.service` and `python -m lbs_vault.broker`; unauthenticated HTTP **401**, authenticated save **200**, use exit **0**, output `accepted:[REDACTED]`; stop/restart both, saved status persisted, second use exit **0**. Canary absent from ciphertext, audit, tool results and daemon output. Scratch/throwaway code was removed.
- Actual Hermes session-context source smoke: environment-forged/unbound and unpropagated worker denied; copied owner context returned metadata only; group context denied.
- `bash -n` both operator scripts passed; actual non-root invocations of both refused with exit **1** before mutation.
- The install/probe gate was subsequently authorized and completed: builder observed real served unauthenticated HTTP **401**, authenticated malformed **400**, oversized **413**, origin/public-create refusals **403**, and canary save **200**. LBS's metadata-only root proof passed with broker exit **0**, exact redacted output, revoked bearer **401**, exact-canary-negative ciphertext/audit/state.db/WAL/SHM/all-field-journal scans, optional prior audit archive absent, fixture removed and vault key retained. No values/matching lines were displayed. Full live evidence: `TESTING.md` and `work/VERIFY.md`. Native visual proof and owner-controlled plugin/real-secret activation remain separate; documented needs-validation leads are unchanged.

## Audit process disclosure

The external report records coordinator handoff, fresh replacements for unusable verifier results, and a missed separate wave-7 critic compensated by a complete wave-8 re-hunt and combined critic plus a distinct final-clean critic. Two early write-isolation incidents were restored/removed; final frozen snapshot hashes matched, and no final source/evidence change was attributed to them. These deviations are disclosed, not presented as a flawless process or exhaustive security proof. Parent corrected an outdated stale-route disposition to final uninstall abort behavior without assuming historical deployment state; verdict unchanged.
