"""Root-owned secret-use broker.

The broker is a separate root process (``python3 -m lbs_vault.broker``) that
listens on a root-only Unix socket. The vault service forwards an agent's
``use`` request to it as ``{op: "use", owner, template_id, handle}``. The broker
looks the template up in a root-owned config, checks the template is bound to
exactly that handle, takes a decrypted snapshot of the stored credential itself,
checks the stored kind (``secret`` or ``login``) matches the template's kind, and
runs the template's fixed argv with the root-configured ``stdin_template``
rendered onto the child's stdin pipe. It never accepts argv, environment, or
shell text from a caller, never places the value or username in argv or
environment, and returns only exit status plus bounded, redacted output.
"""
from __future__ import annotations

import errno
import json
import os
import pwd
import re
import selectors
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .store import VaultError

DEFAULT_BASE = "/root/.hermes/lbs-vault"
DEFAULT_SOCKET = "/run/lbs-vault-broker/broker.sock"

TEMPLATE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{1,63}\Z")
HANDLE = re.compile(r"[a-z0-9][a-z0-9._-]{1,63}\Z")
OWNER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}\Z")
ENV_KEY = re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
KINDS = ("secret", "login")
STDIN_FIELDS = ("secret", "username")
DEFAULT_STDIN_TEMPLATE = (("field", "secret"),)
MAX_STDIN_TEMPLATE = 256
MAX_VALUE_BYTES = 8192
MAX_USERNAME = 256

# A template is one fixed program; launchers that turn data into a new program are refused.
REFUSED_PROGRAMS = {
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh", "busybox", "env",
    "perl", "ruby", "node", "nodejs", "php", "lua", "tclsh", "xargs", "eval", "exec",
}
REFUSED_ENV_PREFIXES = ("LD_", "PYTHON", "PERL", "RUBY", "NODE_", "BASH_", "GCONV_")
REFUSED_ENV_KEYS = {"SSH_ASKPASS", "SUDO_ASKPASS", "SSH_ASKPASS_REQUIRE", "IFS", "ENV", "BASH_ENV", "DISPLAY"}

DEFAULT_TIMEOUT_S = 60
MAX_TIMEOUT_S = 300
DEFAULT_MAX_OUTPUT = 65536
MAX_OUTPUT = 262144
MAX_REQUEST_BYTES = 16384
MAX_CONFIG_BYTES = 262144
MAX_CONCURRENT = 4
KILL_GRACE_S = 2.0
EXIT_DRAIN_S = 2.0
REDACTED = b"[REDACTED]"
MIN_TRAILING_PREFIX = 4
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def base_dir() -> Path:
    return Path(os.environ.get("LBS_VAULT_DIR") or DEFAULT_BASE)


def socket_path_default() -> str:
    return os.environ.get("LBS_VAULT_BROKER_SOCKET") or DEFAULT_SOCKET


def templates_path_default() -> Path:
    configured = os.environ.get("LBS_VAULT_TEMPLATES")
    return Path(configured) if configured else base_dir() / "templates.json"


@dataclass(frozen=True)
class Template:
    id: str
    handle: str
    kind: str
    argv: tuple[str, ...]
    executable: str
    description: str = ""
    timeout_s: int = DEFAULT_TIMEOUT_S
    max_output_bytes: int = DEFAULT_MAX_OUTPUT
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    # Pre-parsed root-configured stdin layout: ("text", literal) or ("field", "secret"|"username").
    stdin_template: tuple[tuple[str, str], ...] = DEFAULT_STDIN_TEMPLATE
    stdin_newline: bool = True

    def metadata(self) -> dict:
        return {"id": self.id, "handle": self.handle, "kind": self.kind, "description": self.description,
                "timeout_s": self.timeout_s}


def _invalid(reason: str) -> VaultError:
    # The reason is a fixed string chosen here, never caller- or config-supplied text.
    err = VaultError(503, "template_config_invalid")
    err.reason = reason
    return err


def _plain(value, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and "\x00" not in value


def _parse_stdin_template(text, kind: str) -> tuple[tuple[str, str], ...]:
    """Strictly parse ``{secret}``/``{username}`` placeholders; ``{{``/``}}`` are literal braces.

    No format specs, conversions, attribute/index access or positional fields: anything
    between braces other than exactly ``secret`` or ``username`` is refused.
    """
    if not isinstance(text, str) or not 0 < len(text) <= MAX_STDIN_TEMPLATE:
        raise _invalid("bad stdin_template")
    parts: list[tuple[str, str]] = []
    literal: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "{}":
            if text.startswith(ch * 2, i):
                literal.append(ch)
                i += 2
                continue
            end = text.find("}", i) if ch == "{" else -1
            if end == -1 or text[i + 1:end] not in STDIN_FIELDS:
                raise _invalid("stdin_template placeholders are only {secret} and {username}")
            if literal:
                parts.append(("text", "".join(literal)))
                literal = []
            parts.append(("field", text[i + 1:end]))
            i = end + 1
            continue
        code = ord(ch)
        if (code < 32 and ch not in "\n\t") or code == 0x7F or 0xD800 <= code <= 0xDFFF:
            raise _invalid("bad stdin_template character")
        literal.append(ch)
        i += 1
    if literal:
        parts.append(("text", "".join(literal)))
    fields = [name for part, name in parts if part == "field"]
    if fields.count("secret") != 1 or fields.count("username") > 1:
        raise _invalid("stdin_template needs exactly one {secret} and at most one {username}")
    if kind != "login" and "username" in fields:
        raise _invalid("{username} needs a login-kind template")
    return tuple(parts)


def _parse_template(raw) -> Template:
    if not isinstance(raw, dict):
        raise _invalid("template is not an object")
    allowed = {"id", "handle", "kind", "argv", "description", "timeout_s", "max_output_bytes",
               "cwd", "env", "stdin_template", "stdin_newline"}
    if set(raw) - allowed:
        raise _invalid("unknown template field")
    tid, handle, kind, argv = raw.get("id"), raw.get("handle"), raw.get("kind"), raw.get("argv")
    if not isinstance(tid, str) or not TEMPLATE_ID.fullmatch(tid):
        raise _invalid("bad template id")
    if not isinstance(handle, str) or not HANDLE.fullmatch(handle):
        raise _invalid("bad template handle")
    if not isinstance(kind, str) or kind not in KINDS:
        raise _invalid("bad template kind")
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 64
            or any(not isinstance(a, str) or len(a) > 4096 or "\x00" in a for a in argv)):
        raise _invalid("bad argv")
    program = argv[0]
    if not os.path.isabs(program) or os.path.normpath(program) != program:
        raise _invalid("argv[0] must be a normalized absolute path")
    written_name = os.path.basename(program)
    program = _trusted_path(program)
    for name in (written_name,os.path.basename(program)):
        if name in REFUSED_PROGRAMS or re.fullmatch(r'(python|perl|ruby|php|lua|tclsh|ksh|csh|bsd-csh|bash|dash|zsh|tcsh|mksh|node)[0-9.]*',name):
            raise _invalid("interpreter or shell launcher refused")
    _check_shebang(program)
    description = raw.get("description", "")
    if not isinstance(description, str) or len(description) > 200 or any(ord(c) < 32 for c in description):
        raise _invalid("bad description")
    timeout_s = raw.get("timeout_s", DEFAULT_TIMEOUT_S)
    if type(timeout_s) is not int or not 1 <= timeout_s <= MAX_TIMEOUT_S:
        raise _invalid("bad timeout_s")
    max_output = raw.get("max_output_bytes", DEFAULT_MAX_OUTPUT)
    if type(max_output) is not int or not 1 <= max_output <= MAX_OUTPUT:
        raise _invalid("bad max_output_bytes")
    cwd = raw.get("cwd")
    if cwd is not None and (not _plain(cwd, 4096) or not os.path.isabs(cwd)):
        raise _invalid("bad cwd")
    if cwd is not None: cwd = _trusted_path(cwd, directory=True)
    env = raw.get("env", {})
    if not isinstance(env, dict) or len(env) > 32:
        raise _invalid("bad env")
    for key, value in env.items():
        if (not isinstance(key, str) or not ENV_KEY.fullmatch(key) or key in REFUSED_ENV_KEYS
                or key.startswith(REFUSED_ENV_PREFIXES) or not isinstance(value, str)
                or len(value) > 4096 or "\x00" in value):
            raise _invalid("bad env entry")
    stdin_template = _parse_stdin_template(raw.get("stdin_template", "{secret}"), kind)
    stdin_newline = raw.get("stdin_newline", True)
    if type(stdin_newline) is not bool:
        raise _invalid("bad stdin_newline")
    return Template(id=tid, handle=handle, kind=kind, argv=tuple(argv), executable=program,
                    description=description, timeout_s=timeout_s, max_output_bytes=max_output, cwd=cwd,
                    env=dict(env), stdin_template=stdin_template, stdin_newline=stdin_newline)


def _check_owned(st: os.stat_result) -> None:
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise VaultError(503, "template_config_insecure")

def _trusted_path(path, *, directory=False):
    """Only the broker's trusted uid/root may control executable/cwd paths."""
    def check(candidate):
        for part in [*reversed(candidate.parents), candidate]:
            st = part.lstat()
            if st.st_uid not in (0, os.geteuid()):
                raise VaultError(503, 'template_target_insecure')
            # Root-owned sticky /tmp protects root-owned children from rename.
            sticky_dir = stat.S_ISDIR(st.st_mode) and bool(st.st_mode & stat.S_ISVTX)
            if not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022 and not sticky_dir:
                raise VaultError(503, 'template_target_insecure')
    try:
        original = Path(path)
        check(original)
        resolved = original.resolve(strict=True)
        check(resolved)
        st = resolved.stat()
        if not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)):
            raise VaultError(503, 'template_target_insecure')
        if directory and st.st_mode & 0o022:
            raise VaultError(503, 'template_target_insecure')
        return str(resolved)
    except (OSError, RuntimeError):
        raise VaultError(503, 'template_target_insecure') from None

def _check_shebang(program):
    """A reviewed helper must not delegate its secret to a user-owned interpreter."""
    try:
        with open(program,'rb') as f:
            first=f.readline(512)
        if not first.startswith(b'#!'):
            return
        parts=first[2:].strip().split()
        if not parts or not parts[0].startswith(b'/'):
            raise VaultError(503,'template_target_insecure')
        interpreter=_trusted_path(os.fsdecode(parts[0]))
        if Path(interpreter).name=='env':
            raise VaultError(503,'template_target_insecure')
        with open(interpreter,'rb') as f:
            if f.read(4)!=b'\x7fELF':
                raise VaultError(503,'template_target_insecure')
    except (OSError,UnicodeError):
        raise VaultError(503,'template_target_insecure') from None


def load_templates(path=None) -> dict[str, Template]:
    """Load and validate the root-configured templates file (owned by us, not group/world-writable)."""
    path = Path(path) if path is not None else templates_path_default()
    try:
        parent = os.lstat(path.parent)
        if not stat.S_ISDIR(parent.st_mode):
            raise VaultError(503, "template_config_insecure")
        _check_owned(parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise VaultError(503, "template_config_missing") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise VaultError(503, "template_config_insecure") from None
        raise VaultError(503, "template_config_unreadable") from None
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise VaultError(503, "template_config_insecure")
        _check_owned(st)
        data = handle.read(MAX_CONFIG_BYTES + 1)
    if len(data) > MAX_CONFIG_BYTES:
        raise _invalid("config too large")
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        raise _invalid("config is not JSON") from None
    if not isinstance(doc, dict) or set(doc) - {"templates"} or not isinstance(doc.get("templates"), list):
        raise _invalid("config must be {\"templates\": [...]}")
    templates: dict[str, Template] = {}
    for raw in doc["templates"]:
        tpl = _parse_template(raw)
        if tpl.id in templates:
            raise _invalid("duplicate template id")
        templates[tpl.id] = tpl
    return templates


def list_templates(path=None) -> list[dict]:
    """Template metadata only (id, handle, kind, description, timeout_s); never argv, env or stdin layout."""
    return [tpl.metadata() for tpl in sorted(load_templates(path).values(), key=lambda t: t.id)]


def redact(buf: bytes, secret: bytes, limit: int, *, min_trailing_prefix: int = MIN_TRAILING_PREFIX) -> tuple[bytes, bool]:
    """Redact full occurrences and trailing prefixes at every captured-buffer cut.

    Keep ``limit + len(secret) - 1`` bytes when available so full occurrences
    crossing the output limit are found. A deadline or drain cutoff can stop
    earlier: redact a trailing proper prefix of at least ``min_trailing_prefix``
    bytes, including when it crosses the output limit.
    The second return value reports source-byte truncation.
    """
    if not secret:
        raise ValueError("empty secret")
    truncated = len(buf) > limit
    covered = bytearray(len(buf))
    start = buf.find(secret)
    while start != -1 and start < limit:
        covered[start:start + len(secret)] = b"\x01" * len(secret)
        start = buf.find(secret, start + 1)
    for size in range(min(len(secret) - 1, len(buf)), min_trailing_prefix - 1, -1):
        if buf.endswith(secret[:size]):
            covered[len(buf) - size:] = b"\x01" * size
            break
    out = bytearray()
    i = 0
    while i < len(buf) and i < limit:
        if covered[i]:
            out += REDACTED
            while i < len(buf) and covered[i]:
                i += 1
        else:
            out.append(buf[i])
            i += 1
    return bytes(out), truncated


def _child_identity():
    """Keep the broker's trusted uid; another uid must never receive its pipe."""
    entry = pwd.getpwuid(os.geteuid())
    return entry.pw_dir, entry.pw_name


def _child_env(tpl: Template, home: str, user: str) -> dict[str, str]:
    env = {"PATH": SAFE_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": home,
           "USER": user, "LOGNAME": user}
    env.update(tpl.env)
    return env


def _exited_unreaped(pid: int) -> bool:
    """True once the leader exited; WNOWAIT keeps the zombie so its pgid cannot be reused yet."""
    try:
        info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return True
    return info is not None


def _kill_group(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _field_bytes(text, *, is_username: bool) -> bytearray:
    """Re-check one stored field against the store's rules and encode it; violations are a fixed error."""
    if (not isinstance(text, str) or not text or any(ord(c) < 32 for c in text)
            or (is_username and (len(text) > MAX_USERNAME or not text.strip()))):
        raise VaultError(500, "broker_error")
    try:
        data = bytearray(text.encode())
    except UnicodeEncodeError:  # unpaired surrogates
        raise VaultError(500, "broker_error") from None
    if not is_username and len(data) > MAX_VALUE_BYTES:
        data[:] = b"\x00" * len(data)
        raise VaultError(500, "broker_error")
    return data


def _render_stdin(tpl: Template, secret_bytes: bytearray, username_bytes: bytearray) -> bytearray:
    """Build the bounded stdin payload from the pre-parsed template; no str.format is involved."""
    payload = bytearray()
    for part, text in tpl.stdin_template:
        if part == "text":
            payload += text.encode()
        elif text == "secret":
            payload += secret_bytes
        else:
            payload += username_bytes
    if tpl.stdin_newline:
        payload += b"\n"
    return payload


def run_template(tpl: Template, secret: str, *, username: str | None = None) -> dict:
    """Run ``tpl`` with its rendered ``stdin_template`` on stdin only and return the redacted result.

    A ``secret`` template takes no username; a ``login`` template requires one. Only the
    secret value is redacted from output: the username is metadata, not a secret.
    """
    if tpl.kind not in KINDS or (tpl.kind == "secret" and username is not None):
        raise VaultError(500, "broker_error")
    home, user = _child_identity()
    cwd = _trusted_path(tpl.cwd or (home if os.path.isdir(home) else "/"), directory=True)
    username_bytes = _field_bytes(username, is_username=True) if tpl.kind == "login" else bytearray()
    secret_bytes = _field_bytes(secret, is_username=False)
    payload = _render_stdin(tpl, secret_bytes, username_bytes)
    cap = tpl.max_output_bytes + len(secret_bytes) - 1
    buf = bytearray()
    overflow = False
    timed_out = False
    output_cut = False
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            list(tpl.argv), executable=tpl.executable, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=_child_env(tpl, home, user), cwd=cwd, close_fds=True, start_new_session=True,
            umask=0o077,
        )
    except (OSError, subprocess.SubprocessError):
        secret_bytes[:] = b"\x00" * len(secret_bytes)
        payload[:] = b"\x00" * len(payload)
        raise VaultError(502, "template_exec_failed") from None
    deadline = started + tpl.timeout_s
    exit_seen_at = None
    out_fd, in_fd = proc.stdout.fileno(), proc.stdin.fileno()
    os.set_blocking(out_fd, False)
    os.set_blocking(in_fd, False)
    sel = selectors.DefaultSelector()
    sel.register(out_fd, selectors.EVENT_READ)
    sel.register(in_fd, selectors.EVENT_WRITE)
    written = 0
    try:
        while True:
            now = time.monotonic()
            if now >= deadline:
                timed_out = True
                output_cut = True
                break
            exited = _exited_unreaped(proc.pid)
            if exited and exit_seen_at is None:
                exit_seen_at = now
            if not sel.get_map():
                if exited:
                    break
                time.sleep(0.05)  # pipes closed but the leader still runs: wait for it until the deadline
                continue
            if exit_seen_at is not None and now - exit_seen_at >= EXIT_DRAIN_S:
                output_cut = True
                break  # leader is gone; leftover group members holding the pipe are killed below
            for key, _ in sel.select(min(deadline - now, 0.25)):
                if key.fd == in_fd:
                    try:
                        written += os.write(in_fd, payload[written:])
                    except BlockingIOError:
                        continue
                    except OSError:
                        written = len(payload)  # child closed stdin; nothing more to deliver
                    if written >= len(payload):
                        sel.unregister(in_fd)
                        proc.stdin.close()
                else:
                    try:
                        chunk = os.read(out_fd, 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        sel.unregister(out_fd)
                        continue
                    room = cap - len(buf)
                    if len(chunk) > room:
                        overflow = True
                        chunk = chunk[:max(room, 0)]
                    buf += chunk
    finally:
        sel.close()
        if timed_out:
            _kill_group(proc.pid, signal.SIGTERM)
            grace = time.monotonic() + KILL_GRACE_S
            while time.monotonic() < grace and not _exited_unreaped(proc.pid):
                time.sleep(0.05)
        # Kill anything left in the session (still pinned by the unreaped leader), then reap.
        _kill_group(proc.pid, signal.SIGKILL)
        proc.wait()
        for stream in (proc.stdin, proc.stdout):
            try:
                stream.close()
            except OSError:
                pass
        payload[:] = b"\x00" * len(payload)
    if overflow:
        # Guarantee the truncation flag even when the cap landed exactly on the limit.
        buf_for_redact = bytes(buf) + b"\x00"
    else:
        buf_for_redact = bytes(buf)
    clean, truncated = redact(buf_for_redact, bytes(secret_bytes), tpl.max_output_bytes,
                              min_trailing_prefix=1 if output_cut else MIN_TRAILING_PREFIX)
    output = clean.decode("utf-8", errors="replace")
    result = {
        "template_id": tpl.id,
        "handle": tpl.handle,
        "exit_code": None if timed_out else proc.returncode,
        "timed_out": timed_out,
        "truncated": truncated or overflow,
        "output": output,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
    if secret in output:
        # Defence in depth: byte-level redaction already ran; never return a value that slipped past it.
        result["output"] = ""
        result["output_withheld"] = True
    secret_bytes[:] = b"\x00" * len(secret_bytes)
    del buf_for_redact, buf
    return result


def execute_use(store, owner: str, template_id: str, handle: str, templates_path=None) -> dict:
    """Validate the request against the approved template, snapshot the credential, check kind, run, audit."""
    if not isinstance(owner, str) or not OWNER.fullmatch(owner):
        raise VaultError(400, "bad_request")
    if not isinstance(template_id, str) or not TEMPLATE_ID.fullmatch(template_id):
        raise VaultError(400, "bad_request")
    if not isinstance(handle, str) or not HANDLE.fullmatch(handle):
        raise VaultError(400, "invalid_handle")
    templates = load_templates(templates_path)
    tpl = templates.get(template_id)
    if tpl is None:
        store.audit(owner, handle, "use", "unknown_template")
        raise VaultError(404, "unknown_template")
    if tpl.handle != handle:
        store.audit(owner, handle, "use", "handle_mismatch")
        raise VaultError(403, "handle_mismatch")
    try:
        snapshot = store.resolve_for_use(owner, handle)
    except VaultError as exc:
        store.audit(owner, handle, "use", exc.code)
        raise
    try:
        kind = snapshot.get("kind") if isinstance(snapshot, dict) else None
        if kind not in KINDS or set(snapshot) != ({"kind", "value", "username"} if kind == "login"
                                                  else {"kind", "value"}):
            raise VaultError(500, "broker_error")
        if kind != tpl.kind:
            raise VaultError(403, "kind_mismatch")
        result = run_template(tpl, snapshot["value"], username=snapshot.get("username"))
    except VaultError as exc:
        store.audit(owner, handle, "use", exc.code)
        raise
    finally:
        del snapshot
    status = "timeout" if result["timed_out"] else f"exit:{result['exit_code']}"
    store.audit(owner, handle, "use", status)
    return result


# ---------------------------------------------------------------- socket server


def _peer_uid(sock: socket.socket) -> int:
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def _read_line(sock: socket.socket, limit: int = MAX_REQUEST_BYTES) -> bytes:
    data = bytearray()
    while b"\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise VaultError(413, "request_too_large")
    return bytes(data.split(b"\n", 1)[0])


def _send(sock: socket.socket, obj: dict) -> None:
    try:
        sock.sendall(json.dumps(obj, separators=(",", ":")).encode() + b"\n")
    except OSError:
        pass


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: BrokerServer = self.server  # type: ignore[assignment]
        sock: socket.socket = self.request
        sock.settimeout(5.0)
        try:
            if _peer_uid(sock) not in server.allowed_uids:
                _send(sock, {"error": "forbidden", "status": 403})
                return
            try:
                req = json.loads(_read_line(sock))
            except (ValueError, UnicodeDecodeError, OSError):
                raise VaultError(400, "bad_request") from None
            if not isinstance(req, dict):
                raise VaultError(400, "bad_request")
            op = req.get("op")
            if op == "ping":
                _send(sock, {"ok": True})
                return
            if op != "use" or set(req) != {"op", "owner", "template_id", "handle"}:
                raise VaultError(400, "bad_request")
            if not server.slots.acquire(blocking=False):
                raise VaultError(429, "busy")
            try:
                result = execute_use(server.store, req["owner"], req["template_id"], req["handle"],
                                     server.templates_path)
            finally:
                server.slots.release()
            _send(sock, result)
        except VaultError as exc:
            _send(sock, {"error": exc.code, "status": exc.status})
        except Exception:
            # Never echo exception text: it could carry process or store details.
            _send(sock, {"error": "broker_error", "status": 500})


class BrokerServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, socket_path, store, templates_path=None):
        self.store = store
        self.templates_path = Path(templates_path) if templates_path is not None else templates_path_default()
        self.allowed_uids = {0, os.geteuid()}
        self.slots = threading.BoundedSemaphore(MAX_CONCURRENT)
        path = Path(socket_path)
        if not path.parent.exists():
            path.parent.mkdir(mode=0o700, parents=True)
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise VaultError(500, "unsafe_permissions")
        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode):
                raise VaultError(500, "unsafe_permissions")
            path.unlink()
        old = os.umask(0o177)
        try:
            super().__init__(str(path), _Handler)
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        self.socket_path = path

    def server_close(self) -> None:
        super().server_close()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass


def make_broker_server(socket_path=None, store=None, templates_path=None) -> BrokerServer:
    if store is None:
        from .store import Store
        store = Store(base_dir())
    return BrokerServer(socket_path or socket_path_default(), store, templates_path)


# ---------------------------------------------------------------- client (used by the vault service)


def request_use(owner: str, template_id: str, handle: str, *, socket_path=None, timeout=None) -> dict:
    """Ask the broker to run ``template_id`` with ``handle``. Returns the redacted result dict."""
    path = socket_path or socket_path_default()
    wait = timeout if timeout is not None else MAX_TIMEOUT_S + KILL_GRACE_S + EXIT_DRAIN_S + 10
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(wait)
        try:
            sock.connect(str(path))
            sock.sendall(json.dumps({"op": "use", "owner": owner, "template_id": template_id,
                                     "handle": handle}, separators=(",", ":")).encode() + b"\n")
            line = _read_line(sock, MAX_OUTPUT * 8 + 65536)
        except VaultError:
            raise VaultError(502, "broker_error") from None
        except TimeoutError:
            raise VaultError(504, "broker_timeout") from None
        except OSError:
            raise VaultError(503, "broker_unavailable") from None
    finally:
        sock.close()
    try:
        reply = json.loads(line)
    except (ValueError, UnicodeDecodeError):
        raise VaultError(502, "broker_error") from None
    if not isinstance(reply, dict):
        raise VaultError(502, "broker_error")
    if "error" in reply:
        status = reply.get("status")
        code = reply.get("error")
        raise VaultError(status if type(status) is int else 502,
                         code if isinstance(code, str) and len(code) <= 64 else "broker_error")
    return reply


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="python3 -m lbs_vault.broker",
                                     description="Root-owned LBS vault secret-use broker.")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="listen on the broker socket (default)")
    sub.add_parser("check", help="validate templates.json and print template metadata")
    args = parser.parse_args(argv)
    if args.cmd == "check":
        try:
            print(json.dumps({"templates": list_templates()}, indent=2))
        except VaultError as exc:
            reason = getattr(exc, "reason", "")
            print(json.dumps({"error": exc.code, "reason": reason}))
            return 1
        return 0
    server = make_broker_server()
    stop = threading.Event()

    def _stop(*_):
        if not stop.is_set():
            stop.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
