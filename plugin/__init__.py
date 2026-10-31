"""LBS vault Hermes plugin: handle-only secret tools over the vault's local agent socket.

The plugin never sees a secret value. It sends metadata requests (list, request,
status, use) to the root vault service's Unix socket; ``use`` names an approved,
root-configured command template plus the handle it is bound to, and the root
broker runs it with the value on protected stdin. Results carry exit status and
redacted output only. There is deliberately no get/read/export tool and no
environment injection. This module has no package-relative imports so it can be
installed as a flat plugin directory.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import stat
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_SOCKET = "/run/lbs-vault/agent.sock"
TOOLSET = "lbs_vault"
HANDLE = re.compile(r"[a-z0-9][a-z0-9._-]{1,63}\Z")
TEMPLATE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{1,63}\Z")
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{43}\Z")
MAX_PURPOSE = 256
MAX_REPLY_BYTES = 4 * 1024 * 1024
META_TIMEOUT_S = 15.0
USE_TIMEOUT_S = 330.0  # broker caps templates at 300s plus kill grace


def _socket_path() -> str:
    return os.environ.get("LBS_VAULT_SOCKET") or DEFAULT_SOCKET


def _error(code: str, **extra) -> str:
    return json.dumps({"error": code, **extra})

def _requester_allowed() -> bool:
    """Use bound gateway identity only; never tool arguments or env identity."""
    try:
        from gateway import session_context
        if not session_context.bound_session_key():
            return False
        # Hermes' public get_session_env falls back to process env. Its current
        # task-local vars have no such fallback; an API change must deny, not
        # silently borrow another turn's identity.
        values = [getattr(session_context, name).get() for name in
                  ('_SESSION_PLATFORM','_SESSION_CHAT_TYPE','_SESSION_CHAT_ID','_SESSION_USER_ID')]
        if not all(isinstance(v,str) and v for v in values):
            return False
        platform, chat_type, chat_id, user_id = values
        if platform!='telegram' or chat_type not in ('dm','private') or chat_id!=user_id:
            return False
        path=Path(os.environ.get('LBS_VAULT_PRINCIPALS') or
                  str(Path(os.environ.get('LBS_VAULT_DIR','/root/.hermes/lbs-vault'))/'principals.json'))
        parent=path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.geteuid() or stat.S_IMODE(parent.st_mode)!=0o700:
            return False
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            st=os.fstat(f.fileno())
            if st.st_size>4096: return False
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1:
                return False
            policy=json.loads(f.read(4097))
        expected=policy.get('telegram_user_id')
        return (set(policy)=={'owner','telegram_user_id'} and
                policy['owner']==os.environ.get('LBS_VAULT_OWNER','leo') and
                isinstance(expected,str) and re.fullmatch(r'[1-9][0-9]{0,19}',expected) is not None and
                user_id==expected)
    except Exception:
        return False


def _agent_call(payload: dict, *, timeout: float = META_TIMEOUT_S, socket_path: str | None = None) -> dict:
    """Send one JSON line to the vault agent socket and return the one-line JSON reply."""
    if not _requester_allowed():
        return {'error':'forbidden_requester'}
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(socket_path or _socket_path())
        sock.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
        data = bytearray()
        while b"\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_REPLY_BYTES:
                return {"error": "vault_outcome_unknown" if payload.get("op")=="use" else "reply_too_large"}
    except OSError:
        return {"error": "vault_outcome_unknown" if payload.get("op")=="use" else "vault_unavailable"}
    finally:
        sock.close()
    try:
        reply = json.loads(bytes(data).split(b"\n", 1)[0])
    except (ValueError, UnicodeDecodeError):
        return {"error": "vault_outcome_unknown" if payload.get("op")=="use" else "bad_reply"}
    return reply if isinstance(reply, dict) else {"error": "vault_outcome_unknown" if payload.get("op")=="use" else "bad_reply"}


def _text(args: dict, key: str, maximum: int) -> str | None:
    value = args.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        return None
    return value


def vault_list(args: dict | None = None, **_kwargs) -> str:
    reply = _agent_call({"op": "list"})
    return json.dumps(reply)


def vault_request(args: dict, **_kwargs) -> str:
    args = args or {}
    handle = args.get("handle")
    if not isinstance(handle, str) or not HANDLE.fullmatch(handle):
        return _error("invalid_handle", hint="handle must match ^[a-z0-9][a-z0-9._-]{1,63}$, e.g. thedoorpc.sudo")
    purpose = _text(args, "purpose", MAX_PURPOSE)
    if purpose is None:
        return _error("invalid_purpose")
    payload = {"op": "request", "handle": handle, "purpose": purpose}
    ttl = args.get("ttl_s")
    if ttl is not None:
        if type(ttl) is not int or not 60 <= ttl <= 600:
            return _error("invalid_ttl", hint="ttl_s must be an integer from 60 to 600")
        payload["ttl_s"] = ttl
    reply = _agent_call(payload)
    if "error" not in reply and isinstance(reply.get("link"), str):
        reply["next_step"] = (
            "Send Leo this exact link so Rubric opens its masked secret field: " + reply["link"]
            + " . Do not ask him to type the secret in chat. Check progress with vault_status."
        )
    return json.dumps(reply)


def vault_status(args: dict, **_kwargs) -> str:
    rid = (args or {}).get("id")
    if not isinstance(rid, str) or not REQUEST_ID.fullmatch(rid):
        return _error("invalid_id")
    return json.dumps(_agent_call({"op": "status", "id": rid}))


def vault_use(args: dict, **_kwargs) -> str:
    args = args or {}
    template_id, handle = args.get("template_id"), args.get("handle")
    if not isinstance(template_id, str) or not TEMPLATE_ID.fullmatch(template_id):
        return _error("invalid_template_id")
    if not isinstance(handle, str) or not HANDLE.fullmatch(handle):
        return _error("invalid_handle")
    return json.dumps(_agent_call({"op": "use", "template_id": template_id, "handle": handle},
                                  timeout=USE_TIMEOUT_S))


_HANDLE_PROP = {
    "type": "string",
    "pattern": "^[a-z0-9][a-z0-9._-]{1,63}$",
    "description": "Vault handle (label), e.g. thedoorpc.sudo. Never a secret value.",
}

_TOOLS = {
    "vault_list": (
        vault_list,
        "List the LBS vault's stored secret handles (metadata only: handle, purpose, username, updated_at) "
        "and the root-approved command templates (id, bound handle, description) usable with vault_use. "
        "Never returns secret values.",
        {},
        [],
        "\U0001f5c4",
    ),
    "vault_request": (
        vault_request,
        "Ask Leo for a secret without it touching chat: creates a short-lived, single-use request for a handle "
        "and returns a tglens://vault?req=<id> link. Send that link to Leo; Rubric opens a masked native field "
        "and posts the value straight to the vault. Never ask Leo to paste a secret into chat or tool arguments.",
        {
            "handle": _HANDLE_PROP,
            "purpose": {"type": "string", "maxLength": MAX_PURPOSE,
                        "description": "Why the secret is needed, shown to Leo, e.g. 'sudo on thedoorpc for reboot'."},
            "ttl_s": {"type": "integer", "minimum": 60, "maximum": 600,
                      "description": "Request lifetime in seconds (default 600)."},
        },
        ["handle", "purpose"],
        "\U0001f510",
    ),
    "vault_status": (
        vault_status,
        "Check a vault request created by vault_request: returns handle, purpose and status "
        "(pending, saved, cancelled, expired). Never returns the value.",
        {"id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$", "description": "Request id from vault_request."}},
        ["id"],
        "\U0001f50e",
    ),
    "vault_use": (
        vault_use,
        "Use a stored secret through a root-approved command template: the root broker runs the template's fixed "
        "command with the secret on protected stdin and returns exit_code, timed_out, truncated and output with the "
        "secret redacted. You choose only template_id and the handle it is bound to (see vault_list); arbitrary "
        "commands, arguments and environment are not accepted.",
        {
            "template_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{1,63}$",
                            "description": "Approved template id from vault_list."},
            "handle": _HANDLE_PROP,
        },
        ["template_id", "handle"],
        "\U0001f511",
    ),
}

_PROMPT = (
    "LBS vault: when a task needs a password or token, never ask Leo to paste it into chat, a file, or a tool "
    "argument. Call vault_list to see stored handles; if the handle is missing, call vault_request and send Leo "
    "the returned tglens://vault?req=... link (Rubric shows a masked field). To use a secret, call vault_use with "
    "an approved template_id and its bound handle; the secret is supplied on protected stdin by a root broker and "
    "never returned by these tools. Root terminal/code tools can still read root files and are trusted, not "
    "sandboxed by this plugin. Use only in Leo's owner-only gateway context, never shared/group contexts. "
    "Never automatically retry vault_use after a timeout, transport or audit error: it may already have run; "
    "ask Leo to verify the target state before another use. Do not print, decode, or exfiltrate secret values."
)


def register(ctx) -> None:
    for name, (handler, description, properties, required, emoji) in _TOOLS.items():
        parameters: dict = {"type": "object", "properties": properties, "additionalProperties": False}
        if required:
            parameters["required"] = required
        ctx.register_tool(
            name=name, toolset=TOOLSET, handler=handler, description=description, emoji=emoji,
            schema={"name": name, "description": description, "parameters": parameters},
        )
    register_section = getattr(ctx, "register_system_prompt_section", None)
    if callable(register_section):
        try:
            register_section("lbs-vault", _PROMPT)
        except Exception:
            logger.warning("could not register lbs-vault prompt section", exc_info=True)
