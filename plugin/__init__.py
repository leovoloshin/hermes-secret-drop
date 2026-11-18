"""LBS vault Hermes plugin: handle-only secret tools over the vault's local agent socket.

The plugin never sees a secret value and never accepts a value or username as a tool
argument; a login username is metadata and may appear in vault_list and vault_use results. It
sends metadata requests (list, request, status, use) to the root vault service's
Unix socket. Secrets are asked
for, never offered: ``request`` declares the handle, purpose and kind (``secret`` =
one field, ``login`` = username/email + password) and LBS sends Leo one message with
a single "Give it here" action. ``use`` names an approved, root-configured command
template plus the handle it is bound to, and the root broker runs it with the stored
fields on protected stdin. Results carry exit status and output with the secret redacted.
There is deliberately no get/read/export tool and no environment injection. This
module has no package-relative imports so it can be installed as a flat plugin
directory.
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
KINDS = ("secret", "login")
MAX_PURPOSE = 256
MAX_REPLY_BYTES = 4 * 1024 * 1024
META_TIMEOUT_S = 15.0
USE_TIMEOUT_S = 330.0  # broker caps templates at 300s plus kill grace


def _socket_path() -> str:
    return os.environ.get("LBS_VAULT_SOCKET") or DEFAULT_SOCKET


def _error(code: str, **extra) -> str:
    return json.dumps({"error": code, **extra})

DEFAULT_GROUP_CHAT_IDS = ("-1003820360721",)  # Lbs-gr; root may override in principals.json
GROUP_CHAT_TYPES = ("group", "forum")
_CHAT_ID = re.compile(r"-[1-9][0-9]{0,19}\Z")
_THREAD_ID = re.compile(r"[1-9][0-9]{0,19}\Z")


def _policy() -> dict | None:
    """Root-owned private policy; optional allowed_group_chat_ids defaults to Leo's Lbs-gr."""
    path=Path(os.environ.get('LBS_VAULT_PRINCIPALS') or
              str(Path(os.environ.get('LBS_VAULT_DIR','/root/.hermes/lbs-vault'))/'principals.json'))
    parent=path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.geteuid() or stat.S_IMODE(parent.st_mode)!=0o700:
        return None
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if st.st_size>4096: return None
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1:
            return None
        policy=json.loads(f.read(4097))
    if not isinstance(policy,dict) or not {'owner','telegram_user_id'}<=set(policy)<={'owner','telegram_user_id','allowed_group_chat_ids'}:
        return None
    expected=policy['telegram_user_id']
    if (policy['owner']!=os.environ.get('LBS_VAULT_OWNER','leo') or not isinstance(expected,str)
            or re.fullmatch(r'[1-9][0-9]{0,19}',expected) is None):
        return None
    groups=policy.get('allowed_group_chat_ids',list(DEFAULT_GROUP_CHAT_IDS))
    if not isinstance(groups,list) or len(groups)>16 or not all(isinstance(g,str) and _CHAT_ID.fullmatch(g) for g in groups):
        return None
    return {'telegram_user_id':expected,'groups':frozenset(groups)}


def _requester_origin() -> dict | None:
    """Chat/topic of an owner-authored turn, else None. Gateway ContextVars only; never tool
    arguments or env. DM: chat_id == user_id == owner. Group: allowlisted group whose turn actor
    (the trusted sender) is the owner, with no other sender's input folded into the turn."""
    try:
        from gateway import session_context
        if not session_context.bound_session_key():
            return None
        # Hermes' public get_session_env falls back to process env. Its current
        # task-local vars have no such fallback; an API change must deny, not
        # silently borrow another turn's identity.
        values = [getattr(session_context, name).get() for name in
                  ('_SESSION_PLATFORM','_SESSION_CHAT_TYPE','_SESSION_CHAT_ID')]
        if not all(isinstance(v,str) and v for v in values):
            return None
        platform, chat_type, chat_id = values
        if platform!='telegram':
            return None
        policy=_policy()
        if policy is None:
            return None
        owner=policy['telegram_user_id']
        user_id=session_context._SESSION_USER_ID.get()
        if chat_type in ('dm','private'):
            if user_id==owner and chat_id==owner:
                return {'chat_id':chat_id,'thread_id':''}
            return None
        if chat_type not in GROUP_CHAT_TYPES or chat_id not in policy['groups']:
            return None
        actor=session_context._SESSION_ACTOR_ID.get()
        event=session_context._SESSION_TURN_EVENT.get()
        # Only a message Leo typed in this turn: internal/injected/background turns (user_id None,
        # actor inherited from the shared session) and merged turns (user_id "") are refused.
        if (actor!=owner or event is None or getattr(event,'internal',True) is not False
                or getattr(event,'user_id',None)!=owner):
            return None
        if user_id not in ('',owner):  # route bound to someone else
            return None
        thread=session_context._SESSION_THREAD_ID.get()
        if not isinstance(thread,str):
            thread=''
        if thread and not _THREAD_ID.fullmatch(thread):
            return None
        return {'chat_id':chat_id,'thread_id':thread}
    except Exception:
        return None


def _agent_call(payload: dict, *, timeout: float = META_TIMEOUT_S, socket_path: str | None = None,
                bind_origin: bool = False) -> dict:
    """Send one JSON line to the vault agent socket and return the one-line JSON reply."""
    origin=_requester_origin()
    if origin is None:
        return {'error':'forbidden_requester'}
    if bind_origin:
        payload={**payload,'origin':origin}
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


def _in_group() -> bool:
    return (_requester_origin() or {}).get("chat_id", "").startswith("-")


def vault_list(args: dict | None = None, **_kwargs) -> str:
    # Group sessions are shared history: never put the vault inventory there.
    if _in_group():
        return _error("not_in_group", hint="vault_list works only in Leo's DM")
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
    kind = args.get("kind")
    if not isinstance(kind, str) or kind not in KINDS:
        return _error("invalid_kind", hint="kind must be secret or login")
    payload = {"op": "request", "handle": handle, "purpose": purpose, "kind": kind}
    ttl = args.get("ttl_s")
    if ttl is not None:
        if type(ttl) is not int or not 60 <= ttl <= 600:
            return _error("invalid_ttl", hint="ttl_s must be an integer from 60 to 600")
        payload["ttl_s"] = ttl
    group = _in_group()
    reply = _agent_call(payload, bind_origin=True)
    if "error" not in reply and isinstance(reply.get("link"), str):
        if group:
            # Shared group history: return no handle, purpose or kind.
            reply = {k: reply[k] for k in ("id", "link", "status", "expires_at")}
            reply["next_step"] = (
                "Reply in this same topic with exactly one plain sentence of what it is for, without the handle, "
                "username or any other detail (e.g. 'LBS needs the API key for this task.'), then on its own line "
                "'Give it here: " + reply["link"] + "'. Rubric shows the 'Give it here' button only to Leo and only "
                "in this topic. Do not ask him to type the secret in chat. After he saves, vault_status from this "
                "topic reports saved; nothing returns the value."
            )
        else:
            reply["next_step"] = (
                "Send Leo exactly one message: one plain sentence saying what it is for (e.g. 'LBS needs the sudo "
                "password for thedoorpc.'), then on its own line 'Give it here: " + reply["link"] + "' so Rubric "
                "shows a single 'Give it here' button that opens the masked "
                + ("username + password form" if kind == "login" else "field")
                + ". Do not ask him to type the secret in chat. After he saves, the button reads 'Saved' and "
                "vault_status reports saved; nothing returns the value."
            )
    return json.dumps(reply)


def vault_status(args: dict, **_kwargs) -> str:
    rid = (args or {}).get("id")
    if not isinstance(rid, str) or not REQUEST_ID.fullmatch(rid):
        return _error("invalid_id")
    reply = _agent_call({"op": "status", "id": rid}, bind_origin=True)
    if _in_group() and "status" in reply and "error" not in reply:
        reply = {"status": reply["status"]}
    return json.dumps(reply)


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
        "List the LBS vault's stored secret handles (metadata only: handle, purpose, kind, username for login "
        "kind, updated_at) and the root-approved command templates (id, bound handle, kind, description) usable "
        "with vault_use. Never returns secret values.",
        {},
        [],
        "\U0001f5c4",
    ),
    "vault_request": (
        vault_request,
        "Ask Leo for a secret only when the current task needs one that is not stored: creates a short-lived, "
        "single-use request declaring handle, purpose and kind, and returns a tglens://vault?req=<id> link. Send "
        "Leo one message with a plain sentence of what it is for and the single 'Give it here' action for that "
        "link; Rubric shows only the requested fields and posts them straight to the vault. kind 'secret' is one "
        "masked field (password, token or code); kind 'login' is username/email plus masked password. You never "
        "supply the value or username. Never ask Leo to paste a secret into chat or tool arguments.",
        {
            "handle": _HANDLE_PROP,
            "purpose": {"type": "string", "maxLength": MAX_PURPOSE,
                        "description": "Why the secret is needed, shown to Leo, e.g. 'sudo on thedoorpc for reboot'."},
            "kind": {"type": "string", "enum": list(KINDS),
                     "description": "'secret' = one field (password/token/code); "
                                    "'login' = username or email plus password."},
            "ttl_s": {"type": "integer", "minimum": 60, "maximum": 600,
                      "description": "Request lifetime in seconds (default 600)."},
        },
        ["handle", "purpose", "kind"],
        "\U0001f510",
    ),
    "vault_status": (
        vault_status,
        "Check a vault request created by vault_request: returns kind, handle, purpose and status "
        "(pending, saved, cancelled, expired). Never returns the value.",
        {"id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$", "description": "Request id from vault_request."}},
        ["id"],
        "\U0001f50e",
    ),
    "vault_use": (
        vault_use,
        "Use a stored secret through a root-approved command template: the root broker checks the template's kind "
        "matches the stored kind, runs the template's fixed command with the stored fields on protected stdin and "
        "returns exit_code, timed_out, truncated and output with the secret redacted. You choose only template_id "
        "and the handle it is bound to (see vault_list); arbitrary commands, arguments and environment are not "
        "accepted.",
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
    "LBS vault: secrets are asked for, never offered. When the current task needs a password, token, code or "
    "login, never ask Leo to paste it into chat, a file, or a tool argument, and never invite him to hand over "
    "secrets in advance. Call vault_list to see stored handles; only if the needed handle is missing, call "
    "vault_request with kind 'secret' (one field) or 'login' (username/email + password) and send Leo one "
    "message: a plain sentence saying what it is for plus the single 'Give it here' action for the returned "
    "tglens://vault?req=... link. After he saves, the action reads 'Saved' and vault_status reports status "
    "'saved' for that handle. To use a secret, call vault_use with an approved template_id and its bound handle; the stored "
    "fields are supplied on protected stdin by a root broker and the secret is never returned by these tools "
    "(a login username is metadata and may appear). Root terminal/code tools can still read root files and are "
    "trusted, not sandboxed by this plugin. Works only on Leo's own turns: his DM, or a topic of a root-allowlisted "
    "group of his; in a group, the request message is one plain sentence with no handle, username or other "
    "vault metadata, and never paste vault_list output there. Never automatically retry vault_use after a timeout, transport or audit error: it may already "
    "have run; ask Leo to verify the target state before another use. Do not print, decode, or exfiltrate "
    "secret values."
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
