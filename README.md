# LBS password vault

Encrypted Spark vault service, root broker, and staged handle-only Hermes plugin. Native masked entry is owned by Rubric, using [the exact API contract](docs/VAULT-API.md). Values travel directly from native field over tailnet HTTPS, never through Telegram or agent arguments.

## Components

- `lbs_vault/store.py`: whole-document Fernet encryption, owner binding, single-use expiring requests, private atomic storage and metadata audit.
- `lbs_vault/service.py`: loopback-only HTTP entry with per-device bearer auth, bounded bodies, Host/Origin checks, rate limiting; root-only Unix agent socket.
- `lbs_vault/broker.py`: separate root process, fixed approved target templates, secret on protected stdin, timeout/output bounds and exact redaction.
- `plugin/`: install under `/root/.hermes/plugins/lbs-vault/`; tools list/request/status/use only. No get tool or generic env injection.
- `scripts/install.sh`, `scripts/uninstall.sh`, `systemd/`: root operator deployment, preserving unrelated Tailscale paths; no gateway restart.

Default storage `/root/.hermes/lbs-vault/`, `LBS_VAULT_DIR` overrides for isolated testing. Default HTTP loopback port **938**, `LBS_VAULT_PORT` overrides only within the kernel-protected privileged range; the service must not be impersonable by a non-root local port squatter while stopped. No package installation or network downloads at install time; system Python 3 with cryptography is required. See [keys and recovery](docs/KEYS.md), [broker configuration](docs/BROKER.md), and [isolated verification](docs/TESTING.md).

Operator runs `sudo scripts/install.sh` only from an immutable, reviewed source export. Prefer exporting the reviewed commit as leo into an archive, extracting it into a new root-owned directory, and executing that root-owned installer; never install an evolving checkout. Device provisioning uses the isolated installed-code invocation in `docs/VAULT-API.md`, never root Python from a user-owned cwd. Token goes to a new 0600 file, never stdout. Install does not provision real devices, add command targets, activate Hermes configuration, or restart the gateway. An empty templates list refuses all use. Explicitly approve root-trusted target templates before use. No thedoorpc commands ship or run.

Tests use fake canaries and temporary dirs. Run `python3 -m pytest -q` in an isolated sandbox; no real hosts or real credentials. Installation/live validation are separate owner gates; no claim of deployed availability from unit tests.

## Clean cutover

Upstream Secret Drop plaintext `.env` persistence, desktop web UI, dashboard endpoint, passthrough configuration, and old plugin hooks were removed. There is deliberately no compatibility alias or migration reading existing secrets. Do not install repository root as the former secret-drop plugin; use the staged `plugin/` directory through the installer. No Secret Source registration: that contract exports values to the agent environment and conflicts with this product's no-env requirement.

Before activation, the supervisor must review only old `secret-drop-names` metadata, disable the old plaintext plugin at the authorized restart, and remove owner-approved old `.env` entries and `terminal.env_passthrough` names without printing values. Existing plaintext values are not migrated or read by this build/installer; they do not become encrypted simply because code was upgraded. This is an operator gate, not an automatic deletion of unrelated credentials.

The root agent trust boundary is explicit: same-privilege malicious code can read root memory/files. This design prevents ordinary handle-only tools from retrieving values; it cannot sandbox a compromised root Hermes process. Templates must be trusted and not encode, transform, persist, or forward secrets to unapproved parties. Exact output redaction is not DLP against malicious targets.

## Changes

2026-10-31: replaced plaintext Secret Drop with encrypted owner-scoped LBS vault; documented device provisioning, client HTTP API, broker templates, key backup and operational gates. Security evidence and deployment status: `docs/SECURITY-REVIEW.md`.
