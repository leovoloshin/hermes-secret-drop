# LBS vault broker and Hermes plugin

The broker is how LBS *uses* a stored secret without ever holding it. It is a
separate root process (`python3 -m lbs_vault.broker`) that runs one
root-approved, fixed command with the stored fields on that command's stdin and
returns only the exit status and redacted output.

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
        │        Store.resolve_for_use(owner, handle) → {kind, value, username?}
        │        (decrypts in the broker only) ── checks template.kind == stored kind
        ▼
fixed argv, fresh env, new session ◀── rendered stdin_template (+ "\n") on a stdin pipe
        │ stdout+stderr merged, bounded, redacted
        ▼
{template_id, handle, exit_code, timed_out, truncated, output, duration_ms}
```

## What the agent can and cannot do

The plugin registers four tools in toolset `lbs_vault`:

| Tool | Sends to agent socket | Returns |
|---|---|---|
| `vault_list` | `{"op":"list"}` | `{"secrets":[{handle,purpose,kind,username?,updated_at}], "templates":[{id,handle,kind,description,timeout_s}]}` (`username` only for `login` items; never a value) |
| `vault_request` | `{"op":"request","handle","purpose","kind","ttl_s"?}` | `{id,kind,handle,purpose,expires_at,status,link,next_step}`; LBS sends Leo one message: a plain sentence of what it is for and the single `Give it here` action for `link` (`tglens://vault?req=<id>`) |
| `vault_status` | `{"op":"status","id"}` | `{kind,handle,purpose,status}` |
| `vault_use` | `{"op":"use","template_id","handle"}` | the broker result above |

Errors come back as `{"error": code, "status": http_status}` (plugin-side
validation errors omit `status`; a missing or unknown `kind` returns
`{"error":"invalid_kind","hint":"kind must be secret or login"}` before socket access). There is no
get/read/export tool, no tool argument that carries a value or username, and no
environment injection into the agent shell. `vault_use` accepts only a template
id and the handle that template is bound to; it cannot add arguments,
environment, a working directory, or a command.

Secrets are asked for, never offered: the plugin prompt tells LBS to call
`vault_request` only when the current task needs a secret that is not stored.
`kind` is required: `secret` is one field (password, token or code); `login` is
username/email plus password, stored encrypted together under the one handle.
The username is metadata and may be shown back to Leo/LBS; the password never is.

## Templates (`templates.json`)

Path: `$LBS_VAULT_TEMPLATES`, default `$LBS_VAULT_DIR/templates.json`
(`/root/.hermes/lbs-vault/templates.json`). The broker re-reads it on every use,
so edits apply without a restart. It refuses every use (`503
template_config_insecure`) unless the file is a regular single-link file owned by
the broker's uid (root), not group/world-writable, not a symlink, inside a
directory with the same properties. Keep it `0600 root:root`.

Upgrade note: every existing template needs an explicit `kind`; no default is inferred. A missing kind anywhere makes the file invalid (`503 template_config_invalid`), including for `vault_list`. Root must review and annotate each approved template before installing this cutover. An empty list remains valid and refuses every use. This builder has not inspected or modified the installed template inventory.

```json
{
  "templates": [
    {
      "id": "example.sudo-uptime",
      "handle": "example.sudo",
      "kind": "secret",
      "argv": ["/usr/bin/ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/root/.ssh/known_hosts", "operator@example.invalid", "sudo", "-S", "-p", "", "uptime"],
      "description": "Example only: approved remote uptime with root-managed SSH configuration",
      "timeout_s": 30,
      "max_output_bytes": 65536
    },
    {
      "id": "example.portal-login",
      "handle": "example.portal",
      "kind": "login",
      "argv": ["/usr/local/sbin/example-portal-login"],
      "description": "Example only: root-reviewed wrapper reading username then password from stdin",
      "stdin_template": "{username}\n{secret}"
    }
  ]
}
```

| Field | Rule |
|---|---|
| `id` | `^[a-z0-9][a-z0-9._-]{1,63}$`, unique |
| `handle` | the one handle this template may use (same regex); a `use` naming another handle is `403 handle_mismatch` |
| `kind` | **required**, exactly `secret` or `login`; must equal the stored item's kind or the use is `403 kind_mismatch` before anything runs |
| `argv` | 1–64 fixed strings, normalized absolute executable; executable and lexical/canonical parents root/broker-owned, not group/other-writable (sticky ancestors only). Canonical executable is used with configured argv[0] preserved. Written/resolved shell/interpreter names refused. Direct shebang interpreter must also be protected and native ELF (no `/usr/bin/env`). Root reviewers must review helper code, ELF loaders, libraries and referenced config/data dependencies; file ownership is not a whole-program sandbox. |
| `description` | optional, ≤ 200 chars, shown to the agent |
| `timeout_s` | optional, 1–300, default 60 |
| `max_output_bytes` | optional, 1–262144, default 65536 |
| `cwd` | optional absolute root-trusted directory, checked like executable parents; **leaf may not be writable by group/other even if sticky**; default root's home (or `/`) |
| `env` | optional fixed `KEY: value` map (≤ 32 entries). `LD_*`, `PYTHON*`, `PERL*`, `RUBY*`, `NODE_*`, `BASH_*`, `GCONV_*`, `IFS`, `ENV`, `BASH_ENV`, `DISPLAY`, `SSH_ASKPASS`, `SUDO_ASKPASS` are refused. Never put a secret here. |
| `stdin_template` | optional string, 1–256 characters, default `"{secret}"`. Only `{secret}` (exactly once) and `{username}` (at most once, `login` templates only) are placeholders; `{{`/`}}` are literal braces. Format specs, conversions, attribute/index access, positional `{}` and any other name are refused. Literal text may contain `\n` and `\t`; other C0 controls, DEL and surrogates are refused. |
| `stdin_newline` | optional bool, default true: append `\n` after the rendered `stdin_template` |

`argv`, `env` and `cwd` are never templated: text such as `{username}` there is
passed through literally. Placeholders are substituted only into stdin.

The installed-code check below validates templates and prints only metadata.
A validation failure prints a fixed reason. Never run a root `python -m`
command from the user-owned checkout.

### Secret delivery: protected stdin only

The broker takes one decrypted snapshot (`Store.resolve_for_use`), checks its
shape (`{kind,value}` or `{kind,value,username}`) and that its kind equals the
template's, re-checks the fields (value 1–8192 UTF-8 bytes, username 1–256
characters, not whitespace-only, no C0 controls or surrogates), and renders the
pre-parsed `stdin_template` into one bounded byte payload (at most 256 template
characters plus the value, username and newline). Any snapshot or field
violation is `500 broker_error` and nothing runs. Legacy untyped items fail
closed in the store and must be requested again.

The payload is written to an anonymous stdin pipe and the write end is closed
after delivery. Targets retain the broker's trusted root uid.
No `run_as` field is accepted: another process under a general user's uid
could inspect that user's target stdin or control its SSH configuration.
Root processes remain trusted and can inspect root memory/files/pipes.
The value and username are never placed in argv, environment, a file, or an
askpass helper. A line-reading fake target works with the default `{secret}` plus
`stdin_newline:true`. A reviewed remote SSH target may feed that line to remote
`sudo -S`; this is not a claim that local privilege escalation works under the
unit's `NoNewPrivileges`/capability restrictions. Raw-key readers (for example
`cryptsetup --key-file=-`) require an explicitly reviewed
`stdin_newline:false` configuration, not the default trailing newline.
Neither field contains ASCII CR/LF/NUL. A two-field wrapper must split
`"{username}\n{secret}"` on ASCII LF only, not Unicode `splitlines()` semantics;
other Unicode line separators are permitted field data. Review the wrapper's
parsing and target binding. Never move either field into argv or env.

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
bytes and discards the rest while still draining the pipe. Only the password/secret
value is redacted; a `login` username is metadata and may appear in output. Redaction runs once,
over the buffered bytes, not per read chunk, so an occurrence split across reads
is still found. The extra `len(value) - 1` bytes cover occurrences crossing the
output limit when that lookahead is available. A deadline or descendant-drain
cutoff can stop earlier: every trailing proper prefix, even one byte, is
redacted at such abnormal cuts, including across the output limit. At natural
EOF, trailing prefixes of at least four bytes are redacted. Full and overlapping
occurrences collapse to `[REDACTED]`. The result is
then decoded as UTF-8 with replacement. The cap counts source bytes; redaction markers may expand the returned byte count. As a final check,
if the value still appears in the decoded output, the output is withheld
(`output: ""`, `output_withheld: true`).

Redaction covers the exact value. A program that transforms the value (base64,
hex, reversed, one character per line) defeats it, so only approve commands
that do not print their input.

## Audit

Every use appends one metadata line through `Store.audit` to
`$LBS_VAULT_DIR/audit.jsonl`: `actor` = owner, `handle`, `op: "use"`, and a
status of `exit:<code>`, `timeout`, `unknown_template`, `handle_mismatch`,
`kind_mismatch`, `not_found`, `template_exec_failed`, or another fixed error code. No argv,
output, exception text, or value is logged.

## Error codes from `use`

| Code | Status | Meaning |
|---|---|---|
| `bad_request` / `invalid_handle` | 400 | malformed owner, template id, or handle |
| `handle_mismatch` | 403 | template is bound to a different handle |
| `kind_mismatch` | 403 | template kind differs from the stored item's kind; nothing ran |
| `unknown_template` | 404 | no approved template with that id |
| `not_found` | 404 | handle not stored for this owner |
| `item_reissue_required` | 409 | untyped pre-cutover credential; enter it again through a typed request |
| `busy` | 429 | four uses already running |
| `template_exec_failed` | 502 | `argv[0]` could not be executed |
| `broker_error` | 500/502 | broker failed (including a malformed credential snapshot); details are never echoed |
| `broker_unavailable` | 503 | broker socket not reachable |
| `broker_timeout` | 504 | no broker reply within the client wait (default 300 s + grace) |
| `template_config_missing` / `_insecure` / `_invalid` / `_unreadable` | 503 | fix `templates.json` |
| `template_target_insecure` | 503 | executable/interpreter/cwd trust check failed |

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
`run_template(template, secret, username=None)` (keyword `username` required for `login`, refused for `secret`), `execute_use(store, owner, template_id, handle, templates_path)`,
`redact(buf, secret, limit, min_trailing_prefix=4)`, `make_broker_server(socket_path, store, templates_path)`
and the client `request_use(owner, template_id, handle, socket_path=..., timeout=...)`.

## Hermes plugin

Staged in `plugin/` (`plugin.yaml`, `__init__.py`); installed as
`/root/.hermes/plugins/lbs-vault/`. It registers the four tools with
`ctx.register_tool(name, toolset="lbs_vault", schema, handler)` — handlers take
`(args, **kwargs)` and return a JSON string — plus a system-prompt section
telling the model to call `vault_request` (with a required `kind`) only when a
task needs a secret, and never to ask for or invite secrets in chat.
It imports nothing from `lbs_vault` and reads `LBS_VAULT_SOCKET` at call time.

Activation needs `lbs-vault` in `plugins.enabled` in `/root/.hermes/config.yaml`
and a Hermes gateway restart (plugins load at startup). The installer stages the
files but does not edit `plugins.enabled` or restart the gateway.

## Limits

* Decryption creates Python strings and temporary copies, potentially including
  other items in the owner document. Mutable stdin buffers are overwritten on
  normal cleanup, but immutable strings, temporary copies and exceptional paths
  prevent a guarantee that every memory copy is wiped or ends with one use.
  Root process memory is trusted; no all-heap erasure claim is made.
* The child process receives the value by design. A template whose program
  echoes or transforms its stdin can leak it; the root operator approves each
  template.
* The broker trusts the `owner` field because only root can reach its socket;
  the service fills it from its root-owned configuration, never from the agent.

## Gateway owner binding

Before activation, provision the verified numeric owner user ID. Private `principals.json` and task-local sender ContextVars deny non-owner/group/unbound **plugin calls** only. Non-owners with root terminal/code/file tools can bypass the plugin via files/sockets. Three numeric general allowlist entries exist; supervisor must verify their identities and root-tool access. Gate real-secret onboarding on restricting/confining non-owner root access or explicitly trusting every root-capable principal. This task does not change/restart the gateway. Exact contract: `VAULT-API.md`.

A **plugin-to-agent** use transport/malformed-reply failure yields `vault_outcome_unknown`. Structured broker failures and post-execution audit failures retain their reported error codes and may also have uncertain outcomes. Never infer “nothing ran” from an error or retry automatically; Leo must verify target state. Bounded 16-worker agent transports avoid serialized use queues; broker separately admits four uses. No exactly-once guarantee across crashes/acknowledgement loss.
