# LBS vault broker and Hermes plugin

The broker is how LBS *uses* a stored secret without ever holding it. It is a
separate root process (`python3 -m lbs_vault.broker`) that runs one
root-approved, fixed command with the secret on that command's stdin and returns
only the exit status and redacted output.

```
Hermes agent ──tool call──▶ plugin (lbs-vault)            metadata only
   vault_use{template_id, handle}
        │  JSON line over /run/lbs-vault/agent.sock (root 0600, dir 0700)
        ▼
vault service (root)  ── owner from LBS_VAULT_OWNER, never from the agent
        │  {op:"use", owner, template_id, handle} over
        │  /run/lbs-vault-broker/broker.sock (root 0600, dir 0700, SO_PEERCRED uid 0)
        ▼
broker (root) ── loads templates.json ── checks template.handle == handle
        │        Store.resolve(owner, handle) (decrypts in the broker only)
        ▼
fixed argv, fresh env, new session ◀── value + "\n" on a stdin pipe
        │ stdout+stderr merged, bounded, redacted
        ▼
{template_id, handle, exit_code, timed_out, truncated, output, duration_ms}
```

## What the agent can and cannot do

The plugin registers four tools in toolset `lbs_vault`:

| Tool | Sends to agent socket | Returns |
|---|---|---|
| `vault_list` | `{"op":"list"}` | `{"secrets":[{handle,purpose,username,updated_at}], "templates":[{id,handle,description,timeout_s}]}` |
| `vault_request` | `{"op":"request","handle","purpose","ttl_s"?}` | `{id,handle,purpose,expires_at,status,link,next_step}`; LBS sends `link` (`tglens://vault?req=<id>`) to Leo |
| `vault_status` | `{"op":"status","id"}` | `{handle,purpose,status}` |
| `vault_use` | `{"op":"use","template_id","handle"}` | the broker result above |

Errors come back as `{"error": code, "status": http_status}` (plugin-side
validation errors omit `status`). There is no get/read/export tool, no tool
argument that carries a value, and no environment injection into the agent
shell. `vault_use` accepts only a template id and the handle that template is
bound to; it cannot add arguments, environment, a working directory, or a
command.

## Templates (`templates.json`)

Path: `$LBS_VAULT_TEMPLATES`, default `$LBS_VAULT_DIR/templates.json`
(`/root/.hermes/lbs-vault/templates.json`). The broker re-reads it on every use,
so edits apply without a restart. It refuses every use (`503
template_config_insecure`) unless the file is a regular single-link file owned by
the broker's uid (root), not group/world-writable, not a symlink, inside a
directory with the same properties. Keep it `0600 root:root`.

```json
{
  "templates": [
    {
      "id": "example.sudo-uptime",
      "handle": "example.sudo",
      "argv": ["/usr/bin/ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/root/.ssh/known_hosts", "operator@example.invalid", "sudo", "-S", "-p", "", "uptime"],
      "description": "Example only: approved remote uptime with root-managed SSH configuration",
      "timeout_s": 30,
      "max_output_bytes": 65536
    }
  ]
}
```

| Field | Rule |
|---|---|
| `id` | `^[a-z0-9][a-z0-9._-]{1,63}$`, unique |
| `handle` | the one handle this template may use (same regex); a `use` naming another handle is `403 handle_mismatch` |
| `argv` | 1–64 fixed strings, normalized absolute executable; executable and lexical/canonical parents root/broker-owned, not group/other-writable (sticky ancestors only). Canonical executable is used with configured argv[0] preserved. Written/resolved shell/interpreter names refused. Direct shebang interpreter must also be protected and native ELF (no `/usr/bin/env`). Root reviewers must review helper code, ELF loaders, libraries and referenced config/data dependencies; file ownership is not a whole-program sandbox. |
| `description` | optional, ≤ 200 chars, shown to the agent |
| `timeout_s` | optional, 1–300, default 60 |
| `max_output_bytes` | optional, 1–262144, default 65536 |
| `cwd` | optional absolute root-trusted directory, checked like executable parents; **leaf may not be writable by group/other even if sticky**; default root's home (or `/`) |
| `env` | optional fixed `KEY: value` map (≤ 32 entries). `LD_*`, `PYTHON*`, `PERL*`, `RUBY*`, `NODE_*`, `BASH_*`, `GCONV_*`, `IFS`, `ENV`, `BASH_ENV`, `DISPLAY`, `SSH_ASKPASS`, `SUDO_ASKPASS` are refused. Never put a secret here. |
| `stdin_newline` | optional bool, default true: append `\n` after the value |

The installed-code check below validates templates and prints only metadata.
A validation failure prints a fixed reason. Never run a root `python -m`
command from the user-owned checkout.

### Secret delivery: protected stdin only

The value plus a newline is written to an anonymous stdin pipe and the write
end is closed after delivery. Targets retain the broker's trusted root uid.
No `run_as` field is accepted: another process under a general user's uid
could inspect that user's target stdin or control its SSH configuration.
Root processes remain trusted and can inspect root memory/files/pipes.
The value is never placed in argv, environment, a file, or an askpass helper.
Programs that read a password from stdin work directly:
`sudo -S -p ''`, `ssh host sudo -S -p '' cmd`, `cryptsetup --key-file=-`,
`openssl ... -passin stdin`, or a test target that reads one line from stdin.
Because the value is stored with no control characters, a single line is
always the whole value. If a command needs the secret somewhere other than
stdin, wrap it in a root-owned, root-reviewed program that reads stdin — do not
add it to argv or env.

## Process isolation and limits

* Environment built from scratch: `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
  `LANG`/`LC_ALL=C.UTF-8`, `HOME`, `USER`, `LOGNAME`, then the template's fixed `env`.
  Nothing is inherited from the broker or the agent.
* `start_new_session=True` (own session and process group), `close_fds`, `umask 077`.
  Production targets stay root, with no Linux capabilities; no uid switching.
* On timeout the whole process group gets `SIGTERM`, then `SIGKILL` after 2 s.
  After a normal exit, anything left in the group is killed. The leader is not
  reaped until after the group kill, so its process-group id cannot be reused.
  If the leader exits while a descendant still holds the output pipe, the broker
  waits at most 2 s before killing the group.
* At most 4 concurrent uses (`429 busy` beyond that); request lines are capped at 16 KiB.

## Output bounding and redaction

stdout and stderr are merged. The broker keeps `max_output_bytes + len(value) - 1`
bytes and discards the rest while still draining the pipe. Redaction runs once,
over the complete buffered bytes, not per read chunk, so an occurrence split
across reads is still found. Because the extra `len(value) - 1` bytes are kept,
an occurrence that starts before the limit and crosses it is also complete and
redacted. Every byte belonging to any occurrence, including overlapping ones,
collapses to `[REDACTED]`. When the stream ended within the limit, a trailing
partial prefix of the value of at least 4 bytes is also redacted. The result is
then cut to the limit and decoded as UTF-8 with replacement. As a final check,
if the value still appears in the decoded output, the output is withheld
(`output: ""`, `output_withheld: true`).

Redaction covers the exact value. A program that transforms the value (base64,
hex, reversed, one character per line) defeats it, so only approve commands
that do not print their input.

## Audit

Every use appends one metadata line through `Store.audit` to
`$LBS_VAULT_DIR/audit.jsonl`: `actor` = owner, `handle`, `op: "use"`, and a
status of `exit:<code>`, `timeout`, `unknown_template`, `handle_mismatch`,
`not_found`, `template_exec_failed`, or another fixed error code. No argv,
output, exception text, or value is logged.

## Error codes from `use`

| Code | Status | Meaning |
|---|---|---|
| `bad_request` / `invalid_handle` | 400 | malformed owner, template id, or handle |
| `handle_mismatch` | 403 | template is bound to a different handle |
| `unknown_template` | 404 | no approved template with that id |
| `not_found` | 404 | handle not stored for this owner |
| `busy` | 429 | four uses already running |
| `template_exec_failed` | 502 | `argv[0]` could not be executed |
| `broker_error` | 500/502 | broker failed; details are never echoed |
| `broker_unavailable` | 503 | broker socket not reachable |
| `broker_timeout` | 504 | no broker reply within the client wait (default 300 s + grace) |
| `template_config_missing` / `_insecure` / `_invalid` / `_unreadable` | 503 | fix `templates.json` |

## Running

| Variable | Default | Used by |
|---|---|---|
| `LBS_VAULT_DIR` | `/root/.hermes/lbs-vault` | broker (store, default templates path) |
| `LBS_VAULT_TEMPLATES` | `$LBS_VAULT_DIR/templates.json` | broker, service (`list`) |
| `LBS_VAULT_BROKER_SOCKET` | `/run/lbs-vault-broker/broker.sock` | broker, service |
| `LBS_VAULT_SOCKET` | `/run/lbs-vault/agent.sock` | service, plugin |

```
sudo systemctl start lbs-vault-broker.service
sudo /usr/bin/python3 -I -c 'import sys; sys.path.insert(0,"/opt/lbs-vault/lib"); from lbs_vault.broker import main; raise SystemExit(main())' check
```

Run it as root under its own systemd unit with
`RuntimeDirectory=lbs-vault-broker` and `RuntimeDirectoryMode=0700`, separate
from the service's `/run/lbs-vault` so stopping one unit never removes the
other's socket. The socket is created `0600`; only uid 0 (or the broker's own
uid, for tests run as an ordinary user) may connect, checked with `SO_PEERCRED`.
The shipped unit (`systemd/lbs-vault-broker.service`) sets `NoNewPrivileges=yes`
and `RestrictSUIDSGID=yes`, so a template cannot gain privilege through a local
setuid binary: local `sudo -S` inside a template will fail, while remote
`ssh host sudo -S -p '' cmd` works. `PrivateTmp=yes` gives templates a private
`/tmp`, and `argv[0]` must sit on an exec-capable filesystem.

In-process entry points (tests): `load_templates(path)`, `list_templates(path)`,
`run_template(template, secret)`, `execute_use(store, owner, template_id, handle, templates_path)`,
`redact(buf, secret, limit, complete=True)`, `make_broker_server(socket_path, store, templates_path)`
and the client `request_use(owner, template_id, handle, socket_path=..., timeout=...)`.

## Hermes plugin

Staged in `plugin/` (`plugin.yaml`, `__init__.py`); installed as
`/root/.hermes/plugins/lbs-vault/`. It registers the four tools with
`ctx.register_tool(name, toolset="lbs_vault", schema, handler)` — handlers take
`(args, **kwargs)` and return a JSON string — plus a system-prompt section
telling the model to use `vault_request` instead of asking for secrets in chat.
It imports nothing from `lbs_vault` and reads `LBS_VAULT_SOCKET` at call time.

Activation needs `lbs-vault` in `plugins.enabled` in `/root/.hermes/config.yaml`
and a Hermes gateway restart (plugins load at startup). The installer stages the
files but does not edit `plugins.enabled` or restart the gateway.

## Limits

* The decrypted value lives in the broker process memory as a Python `str` for
  the duration of one use; byte buffers are zeroed afterwards, the `str` cannot be.
* The child process receives the value by design. A template whose program
  echoes or transforms its stdin can leak it; the root operator approves each
  template.
* The broker trusts the `owner` field because only root can reach its socket;
  the service fills it from its root-owned configuration, never from the agent.

## Gateway owner binding

Before activation, provision the verified numeric owner user ID. The plugin reads private `principals.json` and task-local sender ContextVars and denies non-owner/group/unbound **plugin calls**. It does not block a non-owner who can drive root terminal/code/file tools: those bypass sockets/files directly. Current general gateway allowlist contains three numeric entries; supervisor must verify their identities and root-tool access. Real-secret onboarding is gated on restricting/confning non-owner root access or explicitly trusting every root-capable principal. No gateway config change/restart is performed here. Exact provisioning/context contract: `VAULT-API.md`.

On use transport timeout, acknowledgement loss or audit failure, command outcome may be unknown. Never retry automatically; Leo must verify target state first. `vault_outcome_unknown` is distinct from a proven pre-execution refusal. Agent transports have 16 bounded concurrent workers so slow use does not queue metadata calls or later use behind a long-running operation; the broker still admits only four uses at once. Root cannot claim exactly-once execution across a crash.
