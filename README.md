# LBS password vault

Encrypted Spark vault service, root broker, and staged handle-only Hermes plugin. Native masked entry is owned by Rubric, using [the exact API contract](docs/VAULT-API.md). Values travel directly from native field over tailnet HTTPS, never through Telegram or agent arguments.

## Components

- `lbs_vault/store.py`: whole-document Fernet encryption, owner binding, single-use expiring requests, private atomic storage and metadata audit.
- `lbs_vault/service.py`: loopback-only HTTP entry with per-device bearer auth, bounded bodies, Host/Origin checks, rate limiting; root-only Unix agent socket.
- `lbs_vault/broker.py`: separate root process, fixed approved target templates, secret on protected stdin, timeout/output bounds and exact redaction.
- `plugin/`: install under `/root/.hermes/plugins/lbs-vault/`; tools list/request/status/use only. No get tool or generic env injection.
- `scripts/install.sh`, `scripts/uninstall.sh`, `systemd/`: root operator deployment, preserving unrelated Tailscale paths; no gateway restart.

Default storage `/root/.hermes/lbs-vault/`, `LBS_VAULT_DIR` overrides for isolated testing. Default HTTP loopback port 8738, `LBS_VAULT_PORT` overrides. No package installation or network downloads at install time; system Python 3 with cryptography is required. See [keys and recovery](docs/KEYS.md) and [broker configuration](docs/BROKER.md).

Operator runs `sudo scripts/install.sh` only after reviewing this tree. Device provisioning uses `python3 -m lbs_vault.provision`; token goes to a new 0600 file, never stdout. Install does not provision real devices, add command targets, activate Hermes configuration, or restart the gateway. An empty templates list means all use is refused. Explicitly approve target templates in root-owned config before use. No thedoorpc commands ship or run.

Tests use fake canaries and temporary dirs. Run `python3 -m pytest -q` in an isolated sandbox; no real hosts or real credentials. Installation/live validation are separate owner gates; no claim of deployed availability from unit tests.

## Clean cutover

Upstream Secret Drop plaintext `.env` persistence, desktop web UI, dashboard endpoint, passthrough configuration, and old plugin hooks were removed. There is deliberately no compatibility alias or migration reading existing secrets. Do not install repository root as the former secret-drop plugin; use the staged `plugin/` directory through the installer. No Secret Source registration: that contract exports values to the agent environment and conflicts with this product's no-env requirement.

The root agent trust boundary is explicit: same-privilege malicious code can read root memory/files. This design prevents ordinary handle-only tools from retrieving values; it cannot sandbox a compromised root Hermes process. Templates must be trusted and not encode, transform, persist, or forward secrets to unapproved parties. Exact output redaction is not DLP against malicious targets.

## Changes

2026-10-31: replaced plaintext Secret Drop with encrypted owner-scoped LBS vault; documented device provisioning, client HTTP API, broker templates, key backup and operational gates. Security evidence and deployment status: `docs/SECURITY-REVIEW.md`.
