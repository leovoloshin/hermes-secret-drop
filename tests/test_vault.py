"""Behaviour tests for the LBS vault: store, owner HTTP API, agent sockets, broker, plugin.

Every secret is a freshly generated fake canary (``CANARY-<hex>``); login usernames are
generated ``user-<hex>@example.invalid`` placeholders. The tests assert that passwords never
appear in HTTP responses, tool results, the audit log, files next to the encrypted store,
captured stdout/stderr/logging, request URLs, or any process argv/environment while a
template runs. Usernames are owner-visible metadata, but still never reach disk in
plaintext, URLs, argv or environment.

Values are only ever accepted against a pending, owner-bound, kind-typed request: there is
no proactive save.

Everything runs as the invoking user in private temporary directories; nothing
touches /root, /run, systemd, tailscale or the Hermes gateway.
"""

from __future__ import annotations

import hashlib
import http.client
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
import types
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]

import sys  # noqa: E402

sys.path.insert(0, str(ROOT))

from lbs_vault import broker as broker_mod  # noqa: E402
from lbs_vault import service as service_mod  # noqa: E402
from lbs_vault import store as store_mod  # noqa: E402
from lbs_vault.store import Store, VaultError  # noqa: E402

OWNER = "leo"
HANDLE = "fake.sudo"
PURPOSE = "fake maintenance login for tests"
LOGIN_HANDLE = "fake.mail"
LOGIN_PURPOSE = "fake mail login for tests"
PUBLIC_HOST = service_mod.HOST
ID_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
AUDIT_KEYS = {"time", "actor", "handle", "op", "status"}
REQUEST_KEYS = {"id", "handle", "purpose", "kind", "expires_at", "status", "link"}
SECRET_ITEM_KEYS = {"handle", "purpose", "kind", "updated_at"}
LOGIN_ITEM_KEYS = SECRET_ITEM_KEYS | {"username"}
TEMPLATE_KEYS = {"id", "handle", "kind", "description", "timeout_s"}
UNSET = object()


def new_canary() -> str:
    return "CANARY-" + secrets.token_hex(16)


def new_username() -> str:
    return "user-" + secrets.token_hex(8) + "@example.invalid"


def _load_plugin():
    spec = importlib.util.spec_from_file_location("lbs_vault_plugin", ROOT / "plugin" / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = _load_plugin()


# --------------------------------------------------------------------------- fixtures


class Vault:
    """One isolated vault deployment: store, HTTP server, agent sockets, broker."""

    def __init__(self, root: Path):
        self.root = root
        self.base = root / "vault"
        self.run = root / "run"
        self.run.mkdir(mode=0o700)
        self.templates = root / "templates.json"
        self.bin = root / "bin"
        self.bin.mkdir(mode=0o700)
        self.canary = new_canary()
        self.login_user = new_username()
        self.login_password = new_canary()
        self.passwords = {self.canary, self.login_password}
        self.usernames = {self.login_user}
        self.token = secrets.token_urlsafe(32)
        self.other_token = secrets.token_urlsafe(32)
        self.expired_token = secrets.token_urlsafe(32)
        self.devices = [
            self._device("rubric-test", OWNER, self.token, time.time() + 3600),
            self._device("other-owner", "mallory", self.other_token, time.time() + 3600),
            self._device("expired", OWNER, self.expired_token, time.time() - 1),
        ]
        self.responses: list[bytes] = []
        self.tool_results: list[str] = []
        self.urls: list[str] = []
        self._threads: list[tuple[object, threading.Thread]] = []
        self.store = Store(self.base)
        self.fake_target = self._write_fake_target()
        self.fake_login = self._write_fake_login()
        self.write_templates(self.default_templates())
        self.start()

    @staticmethod
    def _device(device_id, owner, token, expires_at):
        return {"id": device_id, "owner": owner, "expires_at": expires_at,
                "token_sha256": hashlib.sha256(token.encode()).hexdigest()}

    # -- fake targets: consumers that read their credential from stdin -------------------
    def _write_fake_target(self) -> Path:
        expected = hashlib.sha256(self.canary.encode()).hexdigest()
        script = self.bin / "fake-sudo"
        # Shell builtins only touch the value (read/printf/echo): it never reaches an argv.
        script.write_text(
            "#!/bin/sh\n"
            "IFS= read -r pw || { echo 'fake-sudo: no password on stdin'; exit 3; }\n"
            "got=$(printf '%s' \"$pw\" | sha256sum | cut -d' ' -f1)\n"
            "sleep 1\n"
            f"if [ \"$got\" = \"{expected}\" ]; then\n"
            "  echo 'fake-sudo: authenticated'\n"
            "  echo \"careless target echoes: $pw\"\n"
            "  exit 0\n"
            "fi\n"
            "echo 'fake-sudo: wrong password'\n"
            "exit 1\n"
        )
        script.chmod(0o700)
        return script

    def _write_fake_login(self) -> Path:
        """A two-field consumer: username line then password line on stdin, checked by hash only."""
        user_hash = hashlib.sha256(self.login_user.encode()).hexdigest()
        pw_hash = hashlib.sha256(self.login_password.encode()).hexdigest()
        script = self.bin / "fake-login"
        script.write_text(
            "#!/bin/sh\n"
            "IFS= read -r user || { echo 'fake-login: no username on stdin'; exit 3; }\n"
            "IFS= read -r pw || { echo 'fake-login: no password on stdin'; exit 3; }\n"
            "u=$(printf '%s' \"$user\" | sha256sum | cut -d' ' -f1)\n"
            "p=$(printf '%s' \"$pw\" | sha256sum | cut -d' ' -f1)\n"
            "printf 'fake-login: args=%s env=%s\\n' \"$*\" \"${FAKE_LOGIN_USER-}\"\n"
            "sleep 1\n"
            f"if [ \"$u\" = \"{user_hash}\" ] && [ \"$p\" = \"{pw_hash}\" ]; then\n"
            "  echo 'fake-login: authenticated'; exit 0\n"
            "fi\n"
            f"if [ \"$u\" = \"{user_hash}\" ]; then echo 'fake-login: wrong password'; exit 1; fi\n"
            "echo 'fake-login: unknown user'\n"
            "exit 2\n"
        )
        script.chmod(0o700)
        return script

    def marker_target(self, name="marker-target") -> tuple[Path, Path]:
        """A target that only proves whether it was executed."""
        marker = self.root / (name + ".ran")
        script = self.bin / name
        script.write_text(f"#!/bin/sh\n: > '{marker}'\ncat >/dev/null\n")
        script.chmod(0o700)
        return script, marker

    def default_templates(self) -> list[dict]:
        cat = shutil.which("cat")
        return [
            {"id": "fake.sudo-check", "handle": HANDLE, "kind": "secret", "argv": [str(self.fake_target)],
             "description": "fake sudo consumer", "timeout_s": 20},
            {"id": "fake.echo", "handle": HANDLE, "kind": "secret", "argv": [cat], "timeout_s": 10},
            {"id": "fake.slow", "handle": HANDLE, "kind": "secret", "argv": [shutil.which("sleep"), "30"],
             "timeout_s": 1},
            {"id": "other.check", "handle": "other.thing", "kind": "secret", "argv": [str(self.fake_target)],
             "timeout_s": 10},
            # argv/env carry the literal text "{username}": only stdin_template is ever rendered.
            {"id": "fake.login-check", "handle": LOGIN_HANDLE, "kind": "login",
             "argv": [str(self.fake_login), "--user={username}"], "env": {"FAKE_LOGIN_USER": "{username}"},
             "stdin_template": "{username}\n{secret}", "description": "fake login consumer", "timeout_s": 20},
            {"id": "fake.login-echo", "handle": LOGIN_HANDLE, "kind": "login", "argv": [cat],
             "stdin_template": "{username}\n{secret}", "timeout_s": 10},
        ]

    def write_templates(self, templates: list[dict], mode: int = 0o600) -> None:
        tmp = self.templates.with_suffix(".tmp")
        tmp.write_text(json.dumps({"templates": templates}))
        tmp.chmod(mode)
        os.replace(tmp, self.templates)

    # -- servers --------------------------------------------------------------------------
    def _serve(self, server) -> None:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self._threads.append((server, thread))

    def start(self) -> None:
        self.http = service_mod.make_server(self.store, host="127.0.0.1", port=0, devices=self.devices)
        self._serve(self.http)
        self.agent_sock = self.run / "agent.sock"
        self.agent = service_mod.AgentServer(str(self.agent_sock), service_mod.AgentHandler)
        os.chmod(self.agent_sock, 0o600)
        self.agent.store = self.store
        self.agent.owner = OWNER
        self._serve(self.agent)
        self.local = service_mod.local_request_server(self.run / "requests.sock", self.store, OWNER)
        self._serve(self.local)
        # The broker is a separate process in production: give it its own Store instance.
        self.broker = broker_mod.make_broker_server(str(self.run / "broker.sock"), Store(self.base),
                                                    str(self.templates))
        self._serve(self.broker)

    def stop(self) -> None:
        for server, thread in reversed(self._threads):
            server.shutdown()
            server.server_close()
            thread.join(5)
        self._threads.clear()

    def restart(self) -> None:
        """Simulate a service restart: new processes, new Store objects, same disk."""
        self.stop()
        for leftover in ("agent.sock", "requests.sock"):
            (self.run / leftover).unlink(missing_ok=True)
        self.store = Store(self.base)
        self.start()

    # -- clients --------------------------------------------------------------------------
    def call(self, method, path, body=None, *, token="__default__", host=None, origin=None,
             raw=None, content_type="application/json", reset_limits=True, headers=None):
        if reset_limits:
            self.http.limiter.buckets.clear()
        token = self.token if token == "__default__" else token
        conn = http.client.HTTPConnection("127.0.0.1", self.http.server_port, timeout=10)
        sent = {"Host": host or f"127.0.0.1:{self.http.server_port}"}
        if token is not None:
            sent["Authorization"] = "Bearer " + token
        if origin is not None:
            sent["Origin"] = origin
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if data is not None:
            sent["Content-Type"] = content_type
            sent["Content-Length"] = str(len(data))
        sent.update(headers or {})
        self.urls.append(path)
        try:
            conn.request(method, path, body=data, headers=sent)
            resp = conn.getresponse()
            payload = resp.read()
            assert resp.getheader("Cache-Control") == "no-store"
        finally:
            conn.close()
        self.responses.append(payload)
        return resp.status, (json.loads(payload) if payload else None)

    def agent_call(self, obj, sock=None) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(30)
            s.connect(str(sock or self.agent_sock))
            s.sendall(json.dumps(obj).encode() + b"\n")
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        self.responses.append(data)
        return json.loads(data)

    def local_http(self, method, path, body: bytes, content_type="application/json"):
        """Raw HTTP/1.1 over the root-only requests.sock Unix socket."""
        request = (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(str(self.run / "requests.sock"))
            s.sendall(request)
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        self.responses.append(data)
        head, _, payload = data.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1])
        return status, json.loads(payload)

    def tool(self, fn, args=None) -> dict:
        out = fn(args or {})
        assert isinstance(out, str)
        self.tool_results.append(out)
        return json.loads(out)

    def request(self, handle=HANDLE, purpose=PURPOSE, kind="secret", ttl_s=None) -> dict:
        """LBS asks for a credential over the agent socket (the only way a request is created)."""
        body = {"op": "request", "handle": handle, "purpose": purpose, "kind": kind}
        if ttl_s is not None:
            body["ttl_s"] = ttl_s
        reply = self.agent_call(body)
        assert "error" not in reply, reply
        return reply

    def save(self, value=None, handle=HANDLE, purpose=PURPOSE, kind="secret", request_id=None,
             username=UNSET, **kw):
        """POST exactly the given fields; no request is created here (no hidden pre-emption)."""
        value = self.canary if value is None else value
        if isinstance(value, str) and value.startswith("CANARY-"):
            self.passwords.add(value)
        body = {"handle": handle, "purpose": purpose, "value": value}
        if kind is not UNSET:
            body["kind"] = kind
        if request_id is not None:
            body["request_id"] = request_id
        if username is not UNSET:
            body["username"] = username
        return self.call("POST", "/lbs-vault/secrets", body, **kw)

    def save_login(self, request_id=None, value=None, username=UNSET, handle=LOGIN_HANDLE,
                   purpose=LOGIN_PURPOSE, **kw):
        return self.save(value=self.login_password if value is None else value, handle=handle,
                         purpose=purpose, kind="login", request_id=request_id,
                         username=self.login_user if username is UNSET else username, **kw)

    def give(self, kind="secret", handle=None, purpose=None, value=None, username=UNSET, owner=OWNER, **kw):
        """Store a credential the only supported way: a matching request, then the owner's answer."""
        login = kind == "login"
        handle = handle or (LOGIN_HANDLE if login else HANDLE)
        purpose = purpose or (LOGIN_PURPOSE if login else PURPOSE)
        if owner != OWNER:
            kw.setdefault("token", self.other_token)
        req = self.store.request(owner, handle, purpose, kind)
        if login:
            return self.save_login(request_id=req["id"], value=value, username=username, handle=handle,
                                   purpose=purpose, **kw)
        return self.save(value=value, handle=handle, purpose=purpose, kind=kind, request_id=req["id"], **kw)

    def status(self, rid, **kw):
        return self.call("GET", f"/lbs-vault/requests/{rid}", **kw)

    def listed(self) -> list[dict]:
        return self.agent_call({"op": "list"})["secrets"]

    def audit_events(self) -> list[dict]:
        path = self.base / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def assert_canary_absent_everywhere(self, extra: str = "") -> None:
        """Passwords: nowhere observable. Usernames: metadata, but never on disk, in URLs or logs."""
        files = [p.read_bytes() for p in self.root.rglob("*") if p.is_file() and not p.is_symlink()]
        for password in self.passwords:
            needle = password.encode()
            for blob in self.responses:
                assert needle not in blob
            for out in self.tool_results:
                assert password not in out
            for url in self.urls:
                assert password not in url
            assert password not in extra
            assert all(needle not in blob for blob in files), "password found on disk"
        for username in self.usernames:
            for url in self.urls:
                assert username not in url
            assert username not in extra
            assert all(username.encode() not in blob for blob in files), "username found on disk in plaintext"


@pytest.fixture
def vault(monkeypatch):
    root = Path(tempfile.mkdtemp(prefix="lbsv-"))  # short: AF_UNIX paths max 108 bytes
    os.chmod(root, 0o700)
    monkeypatch.setenv("LBS_VAULT_DIR", str(root / "vault"))
    monkeypatch.setenv("LBS_VAULT_TEMPLATES", str(root / "templates.json"))
    monkeypatch.setenv("LBS_VAULT_BROKER_SOCKET", str(root / "run" / "broker.sock"))
    monkeypatch.setenv("LBS_VAULT_SOCKET", str(root / "run" / "agent.sock"))
    v = Vault(root)
    from contextvars import ContextVar
    context = types.ModuleType("gateway.session_context")
    context._SESSION_KEY = ContextVar('fake-key', default=None)
    context._SESSION_KEY.set('telegram:dm:10001')
    context.bound_session_key = lambda: context._SESSION_KEY.get() or ''
    for name, value in (('_SESSION_PLATFORM', 'telegram'), ('_SESSION_CHAT_TYPE', 'dm'),
                        ('_SESSION_CHAT_ID', '10001'), ('_SESSION_USER_ID', '10001')):
        var = ContextVar(name, default=None)
        var.set(value)
        setattr(context, name, var)
    gateway = types.ModuleType('gateway')
    gateway.session_context = context
    monkeypatch.setitem(sys.modules, 'gateway', gateway)
    monkeypatch.setitem(sys.modules, 'gateway.session_context', context)
    monkeypatch.setenv('LBS_VAULT_OWNER', OWNER)
    policy = v.base / 'principals.json'
    policy.write_text(json.dumps({'owner': OWNER, 'telegram_user_id': '10001'}))
    policy.chmod(0o600)
    v.context = context
    try:
        yield v
    finally:
        v.stop()
        shutil.rmtree(root, ignore_errors=True)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


# --------------------------------------------------------------------------- store at rest


def test_store_files_are_private_and_ciphertext(vault):
    assert vault.give() == (200, {"saved": HANDLE})
    assert vault.give("login") == (200, {"saved": LOGIN_HANDLE})
    assert _mode(vault.base) == 0o700
    assert _mode(vault.base / "keys") == 0o700
    for path in (vault.base/"keys/vault.key", vault.store.path, vault.base/"audit.jsonl", vault.base/".lock"):
        assert _mode(path) == 0o600
    blob = vault.store.path.read_bytes()
    for plain in (vault.canary, vault.login_password, vault.login_user):
        assert plain.encode() not in blob
    # It really is Fernet ciphertext under the separate key file, both login fields included.
    key = (vault.base / "keys" / "vault.key").read_bytes()
    document = Fernet(key).decrypt(blob).decode()
    assert vault.canary in document and vault.login_password in document and vault.login_user in document
    vault.assert_canary_absent_everywhere()


def test_restart_persistence_keeps_key_items_kinds_and_request_state(vault):
    req = vault.request()
    login_req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login")
    pending = vault.request("later.token", "still pending after restart", "secret")
    assert vault.save(request_id=req["id"])[0] == 200
    assert vault.save_login(request_id=login_req["id"])[0] == 200
    key_before = (vault.base / "keys" / "vault.key").read_bytes()
    vault.restart()
    assert (vault.base / "keys" / "vault.key").read_bytes() == key_before
    listed = {s["handle"]: s for s in vault.listed()}
    assert set(listed) == {HANDLE, LOGIN_HANDLE}
    assert listed[HANDLE]["kind"] == "secret" and "username" not in listed[HANDLE]
    assert listed[LOGIN_HANDLE]["kind"] == "login" and listed[LOGIN_HANDLE]["username"] == vault.login_user
    # Consumed requests stay consumed after restart (no replay window), with their kind.
    assert vault.save(request_id=req["id"]) == (409, {"error": "consumed"})
    assert vault.save_login(request_id=login_req["id"], value=new_canary()) == (409, {"error": "consumed"})
    assert vault.status(req["id"])[1] == {"handle": HANDLE, "purpose": PURPOSE, "kind": "secret", "status": "saved"}
    assert vault.status(login_req["id"])[1]["kind"] == "login"
    # A pending request survives the restart and is still answerable exactly once.
    assert vault.status(pending["id"])[1] == {"handle": "later.token", "purpose": "still pending after restart",
                                              "kind": "secret", "status": "pending"}
    assert vault.save(handle="later.token", purpose="still pending after restart",
                      request_id=pending["id"])[0] == 200
    # And the persisted values still decrypt for the broker as typed snapshots.
    fresh = Store(vault.base)
    assert fresh.resolve_for_use(OWNER, HANDLE) == {"kind": "secret", "value": vault.canary}
    assert fresh.resolve_for_use(OWNER, LOGIN_HANDLE) == {"kind": "login", "value": vault.login_password,
                                                          "username": vault.login_user}
    vault.assert_canary_absent_everywhere()


def test_missing_key_is_refused_not_regenerated(vault):
    vault.give()
    (vault.base / "keys" / "vault.key").unlink()
    with pytest.raises(VaultError) as err:
        Store(vault.base)
    assert err.value.code == "missing_key"
    assert not (vault.base / "keys" / "vault.key").exists()


@pytest.mark.parametrize("target,mode", [("document", 0o644), ("keys/vault.key", 0o640), ("audit.jsonl", 0o604)])
def test_loose_file_permissions_fail_closed(vault, target, mode):
    vault.give()
    os.chmod(vault.store.path if target == "document" else vault.base/target, mode)
    with pytest.raises(VaultError) as err:
        s = Store(vault.base)
        req = s.request(OWNER, "another.handle", PURPOSE, "secret")
        s.save(OWNER, "another.handle", PURPOSE, "secret", new_canary(), request_id=req["id"])
    assert err.value.code == "unsafe_permissions"


def test_loose_store_directory_is_refused(vault):
    os.chmod(vault.base, 0o755)
    with pytest.raises(VaultError) as err:
        Store(vault.base)
    assert err.value.code == "unsafe_permissions"


def test_symlinked_store_file_is_refused(vault):
    vault.give()
    enc = vault.store.path
    moved = vault.root / "elsewhere.enc"
    os.replace(enc, moved)
    enc.symlink_to(moved)
    with pytest.raises((VaultError, OSError)):  # O_NOFOLLOW: fails closed either way
        Store(vault.base).list(OWNER)


def test_audit_log_is_metadata_only(vault):
    req = vault.request()
    vault.save(request_id=req["id"])
    login_req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login")
    vault.save_login(request_id=login_req["id"])
    assert vault.save(handle="proactive.token")[0] == 403
    events = vault.audit_events()
    assert [(e["op"], e["handle"], e["status"]) for e in events if e["status"] in ("pending", "saved")] == [
        ("request", HANDLE, "pending"), ("save", HANDLE, "saved"),
        ("request", LOGIN_HANDLE, "pending"), ("save", LOGIN_HANDLE, "saved")]
    for event in events:
        assert set(event) == AUDIT_KEYS
        assert event["actor"] == OWNER
    vault.assert_canary_absent_everywhere()


def test_resolve_for_use_returns_typed_snapshots_only(vault):
    assert not hasattr(Store, "resolve")  # the untyped getter is gone, not aliased
    vault.give()
    vault.give("login")
    assert vault.store.resolve_for_use(OWNER, HANDLE) == {"kind": "secret", "value": vault.canary}
    assert vault.store.resolve_for_use(OWNER, LOGIN_HANDLE) == {
        "kind": "login", "value": vault.login_password, "username": vault.login_user}
    for owner, handle in ((OWNER, "missing.handle"), ("mallory", HANDLE)):
        with pytest.raises(VaultError) as err:
            vault.store.resolve_for_use(owner, handle)
        assert (err.value.status, err.value.code) == (404, "not_found")


def test_store_api_enforces_request_kind_and_fields(vault):
    s = vault.store
    for kind in (None, "", "password", "Secret", 1):
        with pytest.raises(VaultError) as err:
            s.request(OWNER, HANDLE, PURPOSE, kind)
        assert (err.value.status, err.value.code) == (400, "invalid_kind")
    req = s.request(OWNER, HANDLE, PURPOSE, "secret")
    assert set(req) == REQUEST_KEYS and req["kind"] == "secret"
    # No proactive save, whatever the kind.
    with pytest.raises(VaultError) as err:
        s.save(OWNER, HANDLE, PURPOSE, "secret", new_canary())
    assert (err.value.status, err.value.code) == (403, "request_required")
    for username in (None, "", "someone"):
        with pytest.raises(VaultError) as err:
            s.save(OWNER, HANDLE, PURPOSE, "secret", new_canary(), request_id=req["id"], username=username)
        assert (err.value.status, err.value.code) == (400, "invalid_fields")
    with pytest.raises(VaultError) as err:
        s.save(OWNER, HANDLE, PURPOSE, "login", new_canary(), request_id=req["id"], username="someone")
    assert (err.value.status, err.value.code) == (400, "request_kind_mismatch")
    assert s.status(OWNER, req["id"]) == {"handle": HANDLE, "purpose": PURPOSE, "kind": "secret",
                                          "status": "pending"}
    assert s.save(OWNER, HANDLE, PURPOSE, "secret", vault.canary, request_id=req["id"]) == {"saved": HANDLE}
    login = s.request(OWNER, LOGIN_HANDLE, LOGIN_PURPOSE, "login")
    with pytest.raises(VaultError) as err:
        s.save(OWNER, LOGIN_HANDLE, LOGIN_PURPOSE, "login", vault.login_password, request_id=login["id"])
    assert (err.value.status, err.value.code) == (400, "invalid_fields")
    assert s.save(OWNER, LOGIN_HANDLE, LOGIN_PURPOSE, "login", vault.login_password, request_id=login["id"],
                  username=vault.login_user) == {"saved": LOGIN_HANDLE}
    by_handle = {item["handle"]: item for item in s.list(OWNER)}
    assert set(by_handle[HANDLE]) == SECRET_ITEM_KEYS and set(by_handle[LOGIN_HANDLE]) == LOGIN_ITEM_KEYS
    vault.assert_canary_absent_everywhere()


def _write_legacy(vault, item_username=None):
    """Write the pre-kind on-disk layout: an untyped item and untyped requests (pending and saved)."""
    legacy_value = new_canary()
    vault.passwords.add(legacy_value)
    pending, saved = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = time.time()
    with vault.store.transaction(OWNER) as d:
        d["items"][OWNER + ":legacy.item"] = dict(owner=OWNER, handle="legacy.item", purpose=PURPOSE,
                                                  username=item_username, updated_at=now, value=legacy_value)
        d["requests"][pending] = dict(owner=OWNER, handle="legacy.req", purpose=PURPOSE,
                                      expires_at=now + 600, status="pending")
        d["requests"][saved] = dict(owner=OWNER, handle="legacy.item", purpose=PURPOSE,
                                    expires_at=now + 600, status="saved")
        vault.store.persist(d, OWNER)
    return pending, saved


def test_legacy_untyped_items_and_requests_fail_closed_until_reissued(vault):
    legacy_user = new_username()
    vault.usernames.add(legacy_user)
    pending, saved = _write_legacy(vault, item_username=legacy_user)
    script, marker = vault.marker_target()
    vault.write_templates([{"id": "legacy.use", "handle": "legacy.item", "kind": "secret", "argv": [str(script)]}])
    # Metadata stays visible but never guesses a kind or shows the old username/value.
    [entry] = [s for s in vault.listed() if s["handle"] == "legacy.item"]
    assert set(entry) == {"handle", "purpose", "kind", "requires_request", "updated_at"}
    assert entry["kind"] is None and entry["requires_request"] is True
    assert legacy_user not in json.dumps(vault.listed())
    with pytest.raises(VaultError) as err:
        vault.store.resolve_for_use(OWNER, "legacy.item")
    assert (err.value.status, err.value.code) == (409, "item_reissue_required")
    assert vault.tool(plugin.vault_use, {"template_id": "legacy.use", "handle": "legacy.item"}) == \
        {"error": "item_reissue_required", "status": 409}
    assert not marker.exists()
    # Untyped requests, whatever their status, cannot be read, answered or cancelled.
    for rid, handle in ((pending, "legacy.req"), (saved, "legacy.item")):
        assert vault.status(rid) == (409, {"error": "request_reissue_required"})
        assert vault.agent_call({"op": "status", "id": rid}) == {"error": "request_reissue_required", "status": 409}
        assert vault.save(handle=handle, request_id=rid, value=new_canary()) == \
            (409, {"error": "request_reissue_required"})
        assert vault.call("POST", f"/requests/{rid}/cancel", {}) == (409, {"error": "request_reissue_required"})
    # A freshly typed request replaces the legacy item.
    assert vault.give(handle="legacy.item") == (200, {"saved": "legacy.item"})
    [entry] = [s for s in vault.listed() if s["handle"] == "legacy.item"]
    assert set(entry) == SECRET_ITEM_KEYS and entry["kind"] == "secret"
    assert vault.store.resolve_for_use(OWNER, "legacy.item") == {"kind": "secret", "value": vault.canary}
    vault.assert_canary_absent_everywhere()


# --------------------------------------------------------------------------- owner HTTP API


@pytest.mark.parametrize("kind,handle,purpose", [("secret", HANDLE, PURPOSE), ("login", LOGIN_HANDLE, LOGIN_PURPOSE)])
def test_request_save_flow_with_link_and_metadata_only_status(vault, kind, handle, purpose):
    req = vault.request(handle, purpose, kind)
    assert set(req) == REQUEST_KEYS
    assert ID_RE.fullmatch(req["id"])
    assert req["link"] == "tglens://vault?req=" + req["id"]
    assert req["kind"] == kind and req["handle"] == handle and req["purpose"] == purpose
    assert req["status"] == "pending" and req["expires_at"] - time.time() <= 600
    # Both the published (/lbs-vault prefixed) and Serve-stripped paths work.
    for path in (f"/lbs-vault/requests/{req['id']}", f"/requests/{req['id']}"):
        assert vault.call("GET", path) == (200, {"handle": handle, "purpose": purpose, "kind": kind,
                                                 "status": "pending"})
    if kind == "login":
        assert vault.save_login(request_id=req["id"]) == (200, {"saved": handle})
    else:
        assert vault.save(request_id=req["id"]) == (200, {"saved": handle})
    assert vault.call("GET", f"/requests/{req['id']}")[1] == {"handle": handle, "purpose": purpose, "kind": kind,
                                                              "status": "saved"}
    [item] = vault.listed()
    assert set(item) == (LOGIN_ITEM_KEYS if kind == "login" else SECRET_ITEM_KEYS)
    assert item["kind"] == kind
    if kind == "login":
        assert item["username"] == vault.login_user
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("kind", ["secret", "login"])
def test_proactive_save_without_request_is_refused(vault, kind):
    extra = {"username": vault.login_user} if kind == "login" else {}
    assert vault.save(handle="proactive.token", purpose="owner initiated", kind=kind, **extra) == \
        (403, {"error": "request_required"})
    assert vault.listed() == []
    assert not any(e["op"] == "save" and e["status"] == "saved" for e in vault.audit_events())
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("username", [None, "", "   ", "someone@example.invalid"])
def test_secret_kind_rejects_any_username_field(vault, username):
    req = vault.request()
    assert vault.save(request_id=req["id"], username=username) == (400, {"error": "invalid_fields"})
    assert vault.status(req["id"])[1]["status"] == "pending"
    assert vault.listed() == []
    assert vault.save(request_id=req["id"]) == (200, {"saved": HANDLE})
    vault.assert_canary_absent_everywhere()


def test_login_kind_requires_username_field(vault):
    req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login")
    assert vault.save(handle=LOGIN_HANDLE, purpose=LOGIN_PURPOSE, kind="login", request_id=req["id"],
                      value=vault.login_password) == (400, {"error": "invalid_fields"})
    assert vault.status(req["id"])[1]["status"] == "pending"
    assert vault.listed() == []
    assert vault.save_login(request_id=req["id"]) == (200, {"saved": LOGIN_HANDLE})
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("username", [
    None, "", "   ", "a\nb", "a\x00b", "a\x1fb", "x" * 257, 123, ["user"], "bad\ud800",
])
def test_login_kind_rejects_invalid_usernames(vault, username):
    req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login")
    assert vault.save_login(request_id=req["id"], username=username) == (400, {"error": "invalid_username"})
    assert vault.status(req["id"])[1]["status"] == "pending"
    assert vault.listed() == []
    # Longest allowed username, with non-ASCII text, is accepted against the same request.
    longest = "ü" * 256
    assert vault.save_login(request_id=req["id"], username=longest) == (200, {"saved": LOGIN_HANDLE})
    [item] = vault.listed()
    assert item["username"] == longest and item["kind"] == "login"
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("kind", [UNSET, None, "", "password", "Secret", "LOGIN", 1, ["secret"]])
def test_missing_or_unknown_kind_is_rejected(vault, kind):
    req = vault.request()
    assert vault.save(request_id=req["id"], kind=kind) == (400, {"error": "invalid_kind"})
    assert vault.status(req["id"])[1]["status"] == "pending"
    assert vault.listed() == []
    assert vault.save(request_id=req["id"]) == (200, {"saved": HANDLE})
    vault.assert_canary_absent_everywhere()


def test_wrong_kind_for_request_is_rejected_without_consuming_it(vault):
    secret_req = vault.request()
    login_req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login")
    # A login answer to a secret request, and a single value to a login request.
    assert vault.save_login(handle=HANDLE, purpose=PURPOSE, request_id=secret_req["id"]) == \
        (400, {"error": "request_kind_mismatch"})
    assert vault.save(handle=LOGIN_HANDLE, purpose=LOGIN_PURPOSE, value=vault.login_password,
                      request_id=login_req["id"]) == (400, {"error": "request_kind_mismatch"})
    assert vault.status(secret_req["id"])[1]["status"] == "pending"
    assert vault.status(login_req["id"])[1]["status"] == "pending"
    assert vault.listed() == []
    assert vault.save(request_id=secret_req["id"])[0] == 200
    assert vault.save_login(request_id=login_req["id"])[0] == 200
    assert [e["status"] for e in vault.audit_events() if e["op"] == "save"] == ["saved", "saved"]
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("kind,extra", [
    ("secret", {"extra": 1}), ("secret", {"owner": "mallory"}), ("secret", {"password": "x"}),
    ("login", {"password": "x"}), ("login", {"email": "x@example.invalid"}), ("login", {"owner": "mallory"}),
])
def test_extra_fields_are_rejected(vault, kind, extra):
    login = kind == "login"
    req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login") if login else vault.request()
    body = {"request_id": req["id"], "kind": kind, "handle": req["handle"], "purpose": req["purpose"],
            "value": vault.login_password if login else vault.canary, **extra}
    if login:
        body["username"] = vault.login_user
    assert vault.call("POST", "/lbs-vault/secrets", body) == (400, {"error": "malformed"})
    assert vault.status(req["id"])[1]["status"] == "pending"
    assert vault.listed() == []
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("kind", ["secret", "login"])
def test_replayed_request_is_rejected(vault, kind):
    if kind == "login":
        req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login")
        assert vault.save_login(request_id=req["id"])[0] == 200
        assert vault.save_login(request_id=req["id"], value=new_canary(), username=new_username()) == \
            (409, {"error": "consumed"})
        expected = {"kind": "login", "value": vault.login_password, "username": vault.login_user}
        handle = LOGIN_HANDLE
    else:
        req = vault.request()
        assert vault.save(request_id=req["id"])[0] == 200
        assert vault.save(value=new_canary(), request_id=req["id"]) == (409, {"error": "consumed"})
        expected, handle = {"kind": "secret", "value": vault.canary}, HANDLE
    assert Store(vault.base).resolve_for_use(OWNER, handle) == expected
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("kind", ["secret", "login"])
def test_wrong_handle_or_purpose_does_not_consume_request(vault, kind):
    if kind == "login":
        req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login")
        send = vault.save_login
    else:
        req = vault.request()
        send = vault.save
    assert send(handle="other.handle", purpose=req["purpose"], request_id=req["id"]) == \
        (400, {"error": "request_mismatch"})
    assert send(handle=req["handle"], purpose="different purpose", request_id=req["id"]) == \
        (400, {"error": "request_mismatch"})
    assert vault.status(req["id"])[1]["status"] == "pending"
    assert vault.listed() == []
    assert send(handle=req["handle"], purpose=req["purpose"], request_id=req["id"])[0] == 200
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("kind", ["secret", "login"])
def test_cancel_then_save_is_rejected(vault, kind):
    login = kind == "login"
    req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login") if login else vault.request()
    assert vault.call("POST", f"/lbs-vault/requests/{req['id']}/cancel", {}) == (200, {"status": "cancelled"})
    assert vault.call("GET", f"/requests/{req['id']}")[1] == {"handle": req["handle"], "purpose": req["purpose"],
                                                              "kind": kind, "status": "cancelled"}
    reply = vault.save_login(request_id=req["id"]) if login else vault.save(request_id=req["id"])
    assert reply == (409, {"error": "consumed"})
    assert vault.call("POST", f"/requests/{req['id']}/cancel", {}) == (409, {"error": "consumed"})
    assert vault.call("POST", f"/requests/{req['id']}/cancel", {"x": 1})[0] == 400
    assert vault.listed() == []
    assert [e["op"] for e in vault.audit_events()] == ["request", "cancel"]
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("kind", ["secret", "login"])
def test_expired_request_times_out(vault, monkeypatch, kind):
    login = kind == "login"
    req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login", ttl_s=60) if login else vault.request(ttl_s=60)
    real = time.time
    monkeypatch.setattr(store_mod, "time", types.SimpleNamespace(time=lambda: real() + 61))
    assert vault.call("GET", f"/requests/{req['id']}")[1] == {"handle": req["handle"], "purpose": req["purpose"],
                                                              "kind": kind, "status": "expired"}
    reply = vault.save_login(request_id=req["id"]) if login else vault.save(request_id=req["id"])
    assert reply == (410, {"error": "expired"})
    assert vault.call("POST", f"/requests/{req['id']}/cancel", {}) == (410, {"error": "expired"})
    assert vault.listed() == []
    vault.assert_canary_absent_everywhere()


def test_ttl_is_bounded_to_ten_minutes(vault):
    for ttl in (0, 601, "60", 60.5):
        reply = vault.agent_call({"op": "request", "handle": HANDLE, "purpose": PURPOSE, "kind": "secret",
                                  "ttl_s": ttl})
        assert reply == {"error": "invalid_ttl", "status": 400}


def test_agent_request_requires_a_known_kind(vault):
    base = {"op": "request", "handle": HANDLE, "purpose": PURPOSE}
    assert vault.agent_call(base) == {"error": "invalid_kind", "status": 400}
    for kind in (None, "", "password", "Login", 1):
        assert vault.agent_call({**base, "kind": kind}) == {"error": "invalid_kind", "status": 400}
    assert vault.agent_call({**base, "kind": "login", "username": "x"})["status"] == 400
    assert vault.agent_call({**base, "kind": "secret", "value": "x"})["status"] == 400
    # Missing core fields are malformed requests, not internal errors.
    for missing in ("handle", "purpose"):
        body = {**base, "kind": "secret"}
        del body[missing]
        assert vault.agent_call(body) == {"error": "malformed", "status": 400}
    assert [e for e in vault.audit_events() if e["op"] == "request"] == []
    assert vault.request(kind="login")["kind"] == "login"


@pytest.mark.parametrize("kind", ["secret", "login"])
def test_request_ids_are_owner_bound(vault, kind):
    login = kind == "login"
    req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login") if login else vault.request()
    assert vault.call("GET", f"/requests/{req['id']}", token=vault.other_token) == (404, {"error": "not_found"})
    reply = (vault.save_login(request_id=req["id"], token=vault.other_token) if login
             else vault.save(request_id=req["id"], token=vault.other_token))
    assert reply == (404, {"error": "not_found"})
    assert vault.call("POST", f"/requests/{req['id']}/cancel", {}, token=vault.other_token)[0] == 404
    assert vault.call("GET", f"/requests/{req['id']}")[1]["status"] == "pending"
    assert vault.store.list("mallory") == [] and vault.listed() == []
    # Unknown and malformed ids are indistinguishable 404s.
    assert vault.call("GET", "/requests/" + "A" * 43) == (404, {"error": "not_found"})
    assert vault.call("GET", "/requests/short") == (404, {"error": "not_found"})
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("token", [None, "", "wrong-token", "__expired__", "__basic__"])
def test_bad_device_bearer_is_401(vault, token):
    headers = None
    if token == "__expired__":
        token = vault.expired_token
    elif token == "__basic__":
        token, headers = None, {"Authorization": "Basic " + vault.token}
    req = vault.request()
    body = {"request_id": req["id"], "kind": "secret", "handle": HANDLE, "purpose": PURPOSE, "value": vault.canary}
    for method, path, payload in (("GET", f"/lbs-vault/requests/{req['id']}", None),
                                  ("POST", "/lbs-vault/secrets", body)):
        assert vault.call(method, path, payload, token=token, headers=headers) == (401, {"error": "unauthorized"})
    assert vault.listed() == []
    assert vault.status(req["id"])[1]["status"] == "pending"
    vault.assert_canary_absent_everywhere()


def test_token_in_url_is_never_accepted(vault):
    status, _ = vault.call("GET", f"/lbs-vault/requests/{'A' * 43}?token={vault.token}", token=None)
    assert status == 400
    # A value smuggled in a query string is rejected before anything is stored.
    req = vault.request()
    status, _ = vault.call("POST", "/lbs-vault/secrets?value=x", {"request_id": req["id"], "kind": "secret",
                                                                   "handle": HANDLE, "purpose": PURPOSE,
                                                                   "value": vault.canary})
    assert status == 400
    assert vault.listed() == []
    assert vault.status(req["id"])[1]["status"] == "pending"


@pytest.mark.parametrize("host,origin,expected", [
    ("evil.example", None, 403),
    ("127.0.0.1:1", None, 403),
    (PUBLIC_HOST + ".evil.example", None, 403),
    (None, "https://evil.example", 403),
    (None, "http://" + PUBLIC_HOST, 403),
    (None, "null", 403),
    (PUBLIC_HOST, None, 200),
    (PUBLIC_HOST, "https://" + PUBLIC_HOST, 200),
])
def test_host_and_origin_checks(vault, host, origin, expected):
    status, body = vault.give(host=host, origin=origin)
    assert status == expected, body
    saved = [s["handle"] for s in vault.listed()]
    assert saved == ([HANDLE] if expected == 200 else [])
    vault.assert_canary_absent_everywhere()


def test_public_request_creation_is_agent_only(vault):
    for kind in ("secret", "login"):
        body = {"handle": HANDLE, "purpose": PURPOSE, "kind": kind}
        assert vault.call("POST", "/lbs-vault/requests", body) == (403, {"error": "agent_only"})
        assert vault.call("POST", "/requests", body)[0] == 403
    assert [e for e in vault.audit_events() if e["op"] == "request"] == []


def test_local_unix_http_request_creation(vault):
    for kind, handle in (("secret", HANDLE), ("login", LOGIN_HANDLE)):
        status, body = vault.local_http("POST", "/lbs-vault/requests", json.dumps(
            {"handle": handle, "purpose": PURPOSE, "kind": kind, "ttl_s": 120}).encode())
        assert status == 200 and body["link"] == "tglens://vault?req=" + body["id"]
        assert set(body) == REQUEST_KEYS and body["kind"] == kind
        assert vault.call("GET", f"/requests/{body['id']}")[1] == {"handle": handle, "purpose": PURPOSE,
                                                                   "kind": kind, "status": "pending"}
    assert _mode(vault.run / "requests.sock") == 0o600
    # Strict body: kind required and known, no owner override, no unknown fields, no other routes.
    for bad, code in (({"handle": HANDLE, "purpose": PURPOSE}, "invalid_kind"),
                      ({"handle": HANDLE, "purpose": PURPOSE, "kind": "password"}, "invalid_kind"),
                      ({"handle": HANDLE, "purpose": PURPOSE, "kind": "secret", "owner": "mallory"}, "malformed"),
                      ({"handle": HANDLE, "purpose": PURPOSE, "kind": "login", "username": "x"}, "malformed")):
        assert vault.local_http("POST", "/lbs-vault/requests", json.dumps(bad).encode()) == (400, {"error": code})
    assert vault.local_http("POST", "/lbs-vault/secrets", json.dumps(
        {"handle": HANDLE, "purpose": PURPOSE, "kind": "secret", "value": vault.canary}).encode())[0] == 404
    assert vault.listed() == []
    assert len([e for e in vault.audit_events() if e["op"] == "request"]) == 2
    vault.assert_canary_absent_everywhere()


# Each raw body carries a real pending request id (RID) and a valid kind, so every rejection
# below is caused by the named defect, not pre-empted by a missing kind or request.
@pytest.mark.parametrize("raw,content_type,code", [
    ('{not json', "application/json", "malformed"),
    ('[]', "application/json", "malformed"),
    ('{"request_id":RID,"kind":"secret","handle":"fake.sudo","handle":"x.yz","purpose":"p","value":"v"}',
     "application/json", "malformed"),
    ('{"request_id":RID,"kind":"secret","kind":"secret","handle":"fake.sudo","purpose":"p","value":"v"}',
     "application/json", "malformed"),
    ('{"request_id":RID,"kind":"secret","handle":"fake.sudo","purpose":"p","value":"v","extra":1}',
     "application/json", "malformed"),
    ('{"request_id":RID,"kind":"secret","handle":"fake.sudo","purpose":"p"}', "application/json", "malformed"),
    ('{"request_id":RID,"kind":"secret","purpose":"p","value":"v"}', "application/json", "malformed"),
    ('{"request_id":RID,"kind":"secret","handle":"fake.sudo","value":"v"}', "application/json", "malformed"),
    ('{"request_id":RID,"kind":"secret","handle":"Bad Handle","purpose":"p","value":"v"}',
     "application/json", "invalid_handle"),
    ('{"request_id":RID,"kind":"secret","handle":"a","purpose":"p","value":"v"}', "application/json",
     "invalid_handle"),
    ('{"request_id":RID,"kind":"secret","handle":"fake.sudo","purpose":"p","value":""}', "application/json",
     "malformed"),
    ('{"request_id":RID,"kind":"secret","handle":"fake.sudo","purpose":"p","value":"a\\nb"}', "application/json",
     "malformed"),
    ('{"request_id":RID,"kind":"secret","handle":"fake.sudo","purpose":"p","value":"a\\u0000b"}',
     "application/json", "malformed"),
    ('{"request_id":RID,"kind":"secret","handle":"fake.sudo","purpose":"p","value":"v"}', "text/plain",
     "malformed"),
])
def test_malformed_bodies_are_rejected(vault, raw, content_type, code):
    req = vault.request(purpose="p")
    status, body = vault.call("POST", "/lbs-vault/secrets", raw=raw.replace("RID", json.dumps(req["id"])).encode(),
                              content_type=content_type)
    assert (status, body) == (400, {"error": code})
    assert vault.listed() == []
    assert vault.status(req["id"])[1]["status"] == "pending"
    # The same request still accepts the well-formed answer.
    assert vault.save(purpose="p", request_id=req["id"]) == (200, {"saved": HANDLE})


def test_oversized_body_and_value_are_rejected(vault):
    req = vault.request()
    # Declared length over the cap is refused before the body is read.
    assert vault.call("POST", "/lbs-vault/secrets", raw=b"{}", headers={"Content-Length": "20000"}) == \
        (413, {"error": "body_too_large"})
    assert vault.save(value="x" * 8193, request_id=req["id"])[0] == 400
    # 4097 x 2-byte chars: body under the 16 KiB cap, value over the 8192 UTF-8 byte cap.
    raw = json.dumps({"request_id": req["id"], "kind": "secret", "handle": HANDLE, "purpose": PURPOSE,
                      "value": "é" * 4097}, ensure_ascii=False).encode()
    assert len(raw) < 16384
    assert vault.call("POST", "/lbs-vault/secrets", raw=raw)[0] == 400
    assert vault.listed() == []
    assert vault.status(req["id"])[1]["status"] == "pending"
    raw = json.dumps({"request_id": req["id"], "kind": "secret", "handle": HANDLE, "purpose": PURPOSE,
                      "value": "é" * 4096}, ensure_ascii=False).encode()
    assert vault.call("POST", "/lbs-vault/secrets", raw=raw) == (200, {"saved": HANDLE})


def test_errors_never_echo_submitted_value(vault):
    req = vault.request()
    login_req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login")
    vault.save(handle="Bad Handle", request_id=req["id"])
    vault.save(request_id=req["id"], handle="other.handle")
    vault.save(request_id="A" * 43)
    vault.save(request_id=req["id"], kind="login", username=vault.canary)
    vault.save(request_id=req["id"], username=vault.canary)
    vault.save(request_id=req["id"], kind=vault.canary)
    vault.save_login(request_id=login_req["id"], username="bad\n" + vault.canary)
    vault.save(handle=LOGIN_HANDLE, purpose=LOGIN_PURPOSE, request_id=login_req["id"], username=vault.canary)
    vault.save()
    vault.call("POST", "/lbs-vault/secrets", raw=json.dumps({"value": vault.canary, "bogus": 1}).encode())
    vault.save(request_id=req["id"], origin="https://evil.example")
    vault.save(request_id=req["id"], token="wrong")
    assert vault.listed() == []
    vault.assert_canary_absent_everywhere()


def test_unknown_routes_and_methods(vault):
    assert vault.call("GET", "/lbs-vault/secrets")[0] == 404
    assert vault.call("GET", "/lbs-vault/secrets/" + HANDLE)[0] == 404
    assert vault.call("GET", "/")[0] == 404
    for method in ("PUT", "DELETE", "PATCH"):
        assert vault.call(method, "/lbs-vault/secrets", {})[0] == 405


def test_failed_auth_is_rate_limited_without_locking_out_the_owner(vault):
    vault.http.limiter.buckets.clear()
    codes = [vault.call("GET", "/requests/" + "A" * 43, token="wrong", reset_limits=False)[0] for _ in range(125)]
    assert codes[:120] == [401] * 120 and codes[120:] == [429] * 5
    # The owner's device has its own budget: unauthenticated floods cannot block it.
    req = vault.request()
    assert vault.call("GET", f"/requests/{req['id']}", reset_limits=False)[0] == 200
    assert vault.save(request_id=req["id"], reset_limits=False) == (200, {"saved": HANDLE})
    vault.assert_canary_absent_everywhere()


def test_authenticated_device_is_rate_limited(vault):
    vault.http.limiter.buckets.clear()
    codes = [vault.call("GET", "/requests/" + "A" * 43, reset_limits=False)[0] for _ in range(62)]
    assert codes[:60] == [404] * 60 and codes[60:] == [429] * 2


# --------------------------------------------------------------------------- agent socket + plugin


def test_agent_socket_has_no_plaintext_read_and_no_owner_override(vault):
    vault.give()
    vault.give("login")
    for bad in ({"op": "get", "handle": HANDLE}, {"op": "read", "handle": HANDLE},
                {"op": "resolve", "handle": HANDLE}, {"op": "resolve_for_use", "handle": LOGIN_HANDLE},
                {"op": "export"}, {"op": "list", "owner": "mallory"},
                {"op": "status", "id": "A" * 43, "owner": "mallory"},
                {"op": "use", "template_id": "fake.sudo-check", "handle": HANDLE, "argv": ["/bin/id"]},
                {"op": "use", "template_id": "fake.login-check", "handle": LOGIN_HANDLE, "username": "x"}):
        reply = vault.agent_call(bad)
        assert reply.get("status") == 400, (bad, reply)
    listed = vault.agent_call({"op": "list"})
    assert set(listed) == {"secrets", "templates"}
    by_handle = {s["handle"]: s for s in listed["secrets"]}
    assert set(by_handle[HANDLE]) == SECRET_ITEM_KEYS and by_handle[HANDLE]["kind"] == "secret"
    assert set(by_handle[LOGIN_HANDLE]) == LOGIN_ITEM_KEYS and by_handle[LOGIN_HANDLE]["kind"] == "login"
    assert by_handle[LOGIN_HANDLE]["username"] == vault.login_user
    assert {t["id"]: t["kind"] for t in listed["templates"]} == {
        "fake.sudo-check": "secret", "fake.echo": "secret", "fake.slow": "secret", "other.check": "secret",
        "fake.login-check": "login", "fake.login-echo": "login"}
    assert all(set(t) == TEMPLATE_KEYS for t in listed["templates"])
    assert _mode(vault.agent_sock) == 0o600
    vault.assert_canary_absent_everywhere()


class _FakeCtx:
    def __init__(self):
        self.tools, self.sections = {}, {}

    def register_tool(self, *, name, toolset, handler, description, emoji, schema):
        self.tools[name] = (toolset, handler, schema)

    def register_system_prompt_section(self, name, text):
        self.sections[name] = text


def test_registered_plugin_tools_are_handle_only(vault):
    ctx = _FakeCtx()
    plugin.register(ctx)
    assert set(ctx.tools) == {"vault_list", "vault_request", "vault_status", "vault_use"}
    for toolset, _handler, schema in ctx.tools.values():
        params = schema["parameters"]
        assert toolset == "lbs_vault" and params["additionalProperties"] is False
        assert not {"value", "password", "secret", "username", "argv", "command", "env"} & set(params["properties"])
    request_params = ctx.tools["vault_request"][2]["parameters"]
    assert sorted(request_params["properties"]["kind"]["enum"]) == ["login", "secret"]
    assert {"handle", "purpose", "kind"} <= set(request_params["required"])
    vault.give()
    vault.give("login")
    # Through the registered handlers the model only ever gets metadata and redacted output.
    listed = json.loads(ctx.tools["vault_list"][1]({}))
    assert {s["handle"]: s["kind"] for s in listed["secrets"]} == {HANDLE: "secret", LOGIN_HANDLE: "login"}
    used = json.loads(ctx.tools["vault_use"][1]({"template_id": "fake.echo", "handle": HANDLE,
                                                 "argv": ["/bin/id"], "value": "x"}))
    assert used["output"].strip() == "[REDACTED]"
    vault.tool_results += [json.dumps(listed), json.dumps(used)]
    vault.assert_canary_absent_everywhere()


def test_plugin_reports_unavailable_vault(vault, monkeypatch, tmp_path):
    monkeypatch.setenv("LBS_VAULT_SOCKET", str(tmp_path / "missing.sock"))
    assert json.loads(plugin.vault_list({})) == {"error": "vault_unavailable"}


def test_plugin_validates_before_calling(vault):
    base = {"handle": HANDLE, "purpose": PURPOSE, "kind": "secret"}
    assert vault.tool(plugin.vault_request, {**base, "handle": "BAD"})["error"] == "invalid_handle"
    assert vault.tool(plugin.vault_request, {**base, "purpose": "a\nb"})["error"] == "invalid_purpose"
    assert vault.tool(plugin.vault_request, {"handle": HANDLE, "purpose": PURPOSE})["error"] == "invalid_kind"
    for kind in (None, "", "password", "Secret", 1, ["login"]):
        assert vault.tool(plugin.vault_request, {**base, "kind": kind})["error"] == "invalid_kind"
    assert vault.tool(plugin.vault_status, {"id": "nope"})["error"] == "invalid_id"
    assert vault.tool(plugin.vault_use, {"template_id": "x y", "handle": HANDLE})["error"] == "invalid_template_id"
    assert [e["op"] for e in vault.audit_events()] == []


@pytest.mark.parametrize("kind,handle", [("secret", HANDLE), ("login", LOGIN_HANDLE)])
def test_plugin_request_declares_kind_and_offers_give_it_here(vault, kind, handle):
    req = vault.tool(plugin.vault_request, {"handle": handle, "purpose": PURPOSE, "kind": kind})
    assert req["kind"] == kind and req["handle"] == handle and req["status"] == "pending"
    assert req["link"] == "tglens://vault?req=" + req["id"]
    assert "Give it here" in req["next_step"] and req["link"] in req["next_step"]
    assert vault.tool(plugin.vault_status, {"id": req["id"]}) == {"handle": handle, "purpose": PURPOSE,
                                                                 "kind": kind, "status": "pending"}
    assert [(e["op"], e["handle"]) for e in vault.audit_events()] == [("request", handle)]


# --------------------------------------------------------------------------- broker


def _scan_proc(needles: list[bytes], marker: bytes, hits: list, seen: list, stop: threading.Event) -> None:
    while not stop.is_set():
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            for name in ("cmdline", "environ"):
                try:
                    data = Path("/proc", pid, name).read_bytes()
                except OSError:
                    continue
                for needle in needles:
                    if needle in data:
                        hits.append((pid, name))
                if name == "cmdline" and marker in data:
                    seen.append(pid)
        time.sleep(0.02)


def _use_watched(vault, args: dict, needles: list[str], marker: Path) -> dict:
    hits, seen, stop = [], [], threading.Event()
    watcher = threading.Thread(target=_scan_proc, args=([n.encode() for n in needles], str(marker).encode(),
                                                        hits, seen, stop), daemon=True)
    watcher.start()
    try:
        result = vault.tool(plugin.vault_use, args)
    finally:
        stop.set()
        watcher.join(5)
    assert seen, "the /proc scan never observed the fake target running"
    assert hits == []
    return result


def test_end_to_end_request_save_use_without_leaks(vault, capfd, caplog):
    caplog.set_level("DEBUG")
    # 1. LBS asks for the handle; the tool result is metadata plus the link.
    req = vault.tool(plugin.vault_request, {"handle": HANDLE, "purpose": PURPOSE, "kind": "secret", "ttl_s": 300})
    assert req["link"] == "tglens://vault?req=" + req["id"] and "next_step" in req
    # 2. Rubric re-fetches metadata by id and posts the value straight to the vault.
    assert vault.call("GET", f"/lbs-vault/requests/{req['id']}", host=PUBLIC_HOST,
                      origin="https://" + PUBLIC_HOST)[1] == {"handle": HANDLE, "purpose": PURPOSE,
                                                               "kind": "secret", "status": "pending"}
    assert vault.save(request_id=req["id"], host=PUBLIC_HOST) == (200, {"saved": HANDLE})
    # 3. LBS sees only the status and the handle.
    assert vault.tool(plugin.vault_status, {"id": req["id"]}) == {"handle": HANDLE, "purpose": PURPOSE,
                                                                 "kind": "secret", "status": "saved"}
    listed = vault.tool(plugin.vault_list)
    assert [(s["handle"], s["kind"]) for s in listed["secrets"]] == [(HANDLE, "secret")]
    # 4. LBS uses the handle through the broker while we watch every process argv/env.
    result = _use_watched(vault, {"template_id": "fake.sudo-check", "handle": HANDLE}, [vault.canary],
                          vault.fake_target)
    assert result["exit_code"] == 0 and result["timed_out"] is False
    assert "fake-sudo: authenticated" in result["output"]
    assert "careless target echoes: [REDACTED]" in result["output"]
    assert set(result) >= {"template_id", "handle", "exit_code", "timed_out", "truncated", "output", "duration_ms"}
    ops = [(e["op"], e["status"]) for e in vault.audit_events()]
    assert ops == [("request", "pending"), ("save", "saved"), ("use", "exit:0")]
    captured = capfd.readouterr()
    logs = "\n".join(r.getMessage() for r in caplog.records)
    vault.assert_canary_absent_everywhere(captured.out + captured.err + logs)


def test_end_to_end_login_pair_reaches_target_only_on_stdin(vault, capfd, caplog):
    caplog.set_level("DEBUG")
    req = vault.tool(plugin.vault_request, {"handle": LOGIN_HANDLE, "purpose": LOGIN_PURPOSE, "kind": "login"})
    assert vault.call("GET", f"/lbs-vault/requests/{req['id']}", host=PUBLIC_HOST,
                      origin="https://" + PUBLIC_HOST)[1] == {"handle": LOGIN_HANDLE, "purpose": LOGIN_PURPOSE,
                                                               "kind": "login", "status": "pending"}
    assert vault.save_login(request_id=req["id"], host=PUBLIC_HOST) == (200, {"saved": LOGIN_HANDLE})
    assert vault.tool(plugin.vault_status, {"id": req["id"]})["status"] == "saved"
    # The username is owner-visible metadata; the password is never listed.
    [item] = vault.tool(plugin.vault_list)["secrets"]
    assert item == {"handle": LOGIN_HANDLE, "purpose": LOGIN_PURPOSE, "kind": "login",
                    "username": vault.login_user, "updated_at": item["updated_at"]}
    # Neither field ever reaches any argv or environment, including the target's own.
    result = _use_watched(vault, {"template_id": "fake.login-check", "handle": LOGIN_HANDLE},
                          [vault.login_password, vault.login_user], vault.fake_login)
    assert result["exit_code"] == 0 and result["timed_out"] is False
    assert "fake-login: authenticated" in result["output"]
    # Fixed argv/env stay literal: no username substitution outside protected stdin.
    assert "fake-login: args=--user={username} env={username}" in result["output"]
    assert [(e["op"], e["status"]) for e in vault.audit_events()] == [
        ("request", "pending"), ("save", "saved"), ("use", "exit:0")]
    captured = capfd.readouterr()
    logs = "\n".join(r.getMessage() for r in caplog.records)
    vault.assert_canary_absent_everywhere(captured.out + captured.err + logs)


def test_login_use_with_wrong_password_or_user_reports_failure_only(vault):
    vault.give("login", value=new_canary())
    result = vault.tool(plugin.vault_use, {"template_id": "fake.login-check", "handle": LOGIN_HANDLE})
    assert result["exit_code"] == 1 and "fake-login: wrong password" in result["output"]
    stranger = new_username()
    vault.usernames.add(stranger)
    vault.give("login", username=stranger)
    result = vault.tool(plugin.vault_use, {"template_id": "fake.login-check", "handle": LOGIN_HANDLE})
    assert result["exit_code"] == 2 and "fake-login: unknown user" in result["output"]
    vault.assert_canary_absent_everywhere()


def test_login_output_redacts_password_but_not_username(vault):
    vault.give("login")
    result = vault.tool(plugin.vault_use, {"template_id": "fake.login-echo", "handle": LOGIN_HANDLE})
    assert result["exit_code"] == 0
    assert result["output"] == vault.login_user + "\n[REDACTED]\n"
    # stdin_newline=false: the rendered template is delivered without the trailing newline.
    templates = vault.default_templates()
    templates[-1]["stdin_newline"] = False
    vault.write_templates(templates)
    result = vault.tool(plugin.vault_use, {"template_id": "fake.login-echo", "handle": LOGIN_HANDLE})
    assert result["output"] == vault.login_user + "\n[REDACTED]"
    vault.assert_canary_absent_everywhere()


def test_secret_stdin_template_renders_literals_around_the_value(vault):
    vault.give()
    vault.write_templates([{"id": "fake.framed", "handle": HANDLE, "kind": "secret", "argv": [shutil.which("cat")],
                            "stdin_template": "pw={{username}}\t{secret};", "stdin_newline": False}])
    result = vault.tool(plugin.vault_use, {"template_id": "fake.framed", "handle": HANDLE})
    assert result["exit_code"] == 0 and result["output"] == "pw={username}\t[REDACTED];"
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("stored,template_kind", [("login", "secret"), ("secret", "login")])
def test_template_kind_must_match_stored_kind(vault, stored, template_kind):
    vault.give(stored)
    handle = LOGIN_HANDLE if stored == "login" else HANDLE
    script, marker = vault.marker_target()
    template = {"id": "kind.cross", "handle": handle, "kind": template_kind, "argv": [str(script)]}
    if template_kind == "login":
        template["stdin_template"] = "{username}\n{secret}"
    vault.write_templates([template])
    assert vault.tool(plugin.vault_use, {"template_id": "kind.cross", "handle": handle}) == \
        {"error": "kind_mismatch", "status": 403}
    assert not marker.exists()
    assert [e["status"] for e in vault.audit_events() if e["op"] == "use"] == ["kind_mismatch"]
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("change", [
    {"kind": None}, {"kind": ""}, {"kind": "password"}, {"kind": "Secret"}, {"kind": 1},
    {"stdin_template": "{username}\n{secret}"},          # secret templates cannot reference a username
    {"stdin_template": "{secret!r}"}, {"stdin_template": "{secret:>40}"}, {"stdin_template": "{secret.upper}"},
    {"stdin_template": "{secret[0]}"}, {"stdin_template": "{}"}, {"stdin_template": "{0}"},
    {"stdin_template": "{password}"}, {"stdin_template": "{secret"}, {"stdin_template": "secret}"},
    {"stdin_template": "no placeholder"}, {"stdin_template": "{secret}{secret}"},
    {"stdin_template": "{secret}\x01"}, {"stdin_template": "{secret}\x7f"}, {"stdin_template": "x" * 250 + "{secret}"},
    {"stdin_template": ""}, {"stdin_template": 1}, {"stdin_template": None}, {"stdin_template": ["{secret}"]},
    {"kind": "login", "stdin_template": "{username}"},  # a login template must still deliver the password
    {"kind": "login", "stdin_template": "{username}{username}\n{secret}"},
    {"kind": "login", "stdin_template": "{username!s}\n{secret}"},
])
def test_invalid_template_kinds_and_stdin_templates_are_refused(vault, change):
    vault.give()
    vault.give("login")
    template = {"id": "bad.template", "handle": HANDLE, "kind": "secret", "argv": [str(vault.fake_target)]}
    template.update(change)
    if template["kind"] is None:
        del template["kind"]
    if template.get("kind") == "login":
        template["handle"] = LOGIN_HANDLE
    vault.write_templates([template])
    reply = vault.tool(plugin.vault_use, {"template_id": "bad.template", "handle": template["handle"]})
    assert reply == {"error": "template_config_invalid", "status": 503}, change
    vault.assert_canary_absent_everywhere()


def test_use_with_wrong_value_reports_failure_only(vault):
    vault.give(value=new_canary())  # not what the fake target expects
    result = vault.tool(plugin.vault_use, {"template_id": "fake.sudo-check", "handle": HANDLE})
    assert result["exit_code"] == 1 and "wrong password" in result["output"]
    vault.assert_canary_absent_everywhere()


def test_command_output_echoing_the_secret_is_redacted(vault):
    vault.give()
    result = vault.tool(plugin.vault_use, {"template_id": "fake.echo", "handle": HANDLE})
    assert result["exit_code"] == 0
    assert result["output"].strip() == "[REDACTED]"
    vault.assert_canary_absent_everywhere()


def test_wrong_target_or_unknown_template_is_refused(vault):
    vault.give()
    vault.give(handle="other.thing", value=new_canary())
    # Template bound to another handle.
    assert vault.tool(plugin.vault_use, {"template_id": "other.check", "handle": HANDLE}) == \
        {"error": "handle_mismatch", "status": 403}
    assert vault.tool(plugin.vault_use, {"template_id": "fake.sudo-check", "handle": "other.thing"}) == \
        {"error": "handle_mismatch", "status": 403}
    assert vault.tool(plugin.vault_use, {"template_id": "no.such", "handle": HANDLE}) == \
        {"error": "unknown_template", "status": 404}
    # Template exists but nothing saved under its handle.
    vault.write_templates(vault.default_templates() + [
        {"id": "missing.check", "handle": "missing.handle", "kind": "secret", "argv": [str(vault.fake_target)]}])
    assert vault.tool(plugin.vault_use, {"template_id": "missing.check", "handle": "missing.handle"})["status"] == 404
    statuses = [e["status"] for e in vault.audit_events() if e["op"] == "use"]
    assert statuses == ["handle_mismatch", "handle_mismatch", "unknown_template", "not_found"]
    vault.assert_canary_absent_everywhere()


def test_use_timeout_kills_target(vault):
    vault.give()
    started = time.monotonic()
    result = vault.tool(plugin.vault_use, {"template_id": "fake.slow", "handle": HANDLE})
    assert result["timed_out"] is True and result["exit_code"] is None
    assert time.monotonic() - started < 10
    assert [e["status"] for e in vault.audit_events() if e["op"] == "use"] == ["timeout"]
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("mode", ["timeout", "drain"])
@pytest.mark.parametrize("padding,limit", [(4, 128), (254, 256)])
@pytest.mark.parametrize("short_prefix", [False, True])
def test_cut_output_never_returns_a_password_prefix(vault, mode, padding, limit, short_prefix):
    target = vault.bin / "partial-output"
    target.write_text(
        "#!/bin/sh\n"
        "IFS= read -r pw || exit 3\n"
        "printf '%*s' \"$1\" '' | tr ' ' x\n"
        "printf '%.*s' \"$3\" \"$pw\"\n"
        "if [ \"$2\" = drain ]; then sleep 10 & exit 0; fi\n"
        "sleep 10\n"
    )
    target.chmod(0o700)
    vault.write_templates(vault.default_templates() + [{
        "id": "fake.cut", "handle": HANDLE, "kind": "secret",
        "argv": [str(target), str(padding), mode, str(3 if short_prefix else len(vault.canary)-1)],
        "timeout_s": 1 if mode == "timeout" else 5,
        "max_output_bytes": limit,
    }])
    vault.give()
    result = vault.tool(plugin.vault_use, {"template_id": "fake.cut", "handle": HANDLE})
    assert result["timed_out"] is (mode == "timeout")
    assert result["truncated"] is (padding == 254)
    assert result["output"] == "x" * padding + "[REDACTED]"
    vault.assert_canary_absent_everywhere()


def test_insecure_or_invalid_templates_are_refused(vault):
    vault.give()
    vault.write_templates(vault.default_templates(), mode=0o622)
    reply = vault.tool(plugin.vault_use, {"template_id": "fake.sudo-check", "handle": HANDLE})
    assert reply == {"error": "template_config_insecure", "status": 503}
    for bad in ({"id": "shell.x", "handle": HANDLE, "kind": "secret", "argv": [shutil.which("sh"), "-c", "id"]},
                {"id": "py.x", "handle": HANDLE, "kind": "secret", "argv": [sys.executable, "-c", "0"]},
                {"id": "rel.x", "handle": HANDLE, "kind": "secret", "argv": ["fake-sudo"]},
                {"id": "env.x", "handle": HANDLE, "kind": "secret", "argv": [str(vault.fake_target)],
                 "env": {"LD_PRELOAD": "/x"}},
                {"id": "ask.x", "handle": HANDLE, "kind": "secret", "argv": [str(vault.fake_target)],
                 "env": {"SUDO_ASKPASS": "/x"}}):
        vault.write_templates([bad])
        reply = vault.tool(plugin.vault_use, {"template_id": bad["id"], "handle": HANDLE})
        assert reply == {"error": "template_config_invalid", "status": 503}, bad
    vault.assert_canary_absent_everywhere()


def test_broker_rejects_requests_it_does_not_understand(vault):
    for extra in ({"argv": ["/bin/id"]}, {"username": "x"}, {"kind": "login"}):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(str(vault.run / "broker.sock"))
            s.sendall(json.dumps({"op": "use", "owner": OWNER, "template_id": "fake.echo", "handle": HANDLE,
                                  **extra}).encode() + b"\n")
            reply = json.loads(s.recv(65536))
        assert reply == {"error": "bad_request", "status": 400}
    assert _mode(vault.run / "broker.sock") == 0o600


@pytest.mark.parametrize("buf,limit,expected", [
    (b"aa SECRETVAL bb", 100, b"aa [REDACTED] bb"),
    (b"SECRETVALSECRETVAL", 100, b"[REDACTED]"),
    (b"head SECRET", 100, b"head [REDACTED]"),          # trailing partial prefix
    (b"0123SECRETVALtail", 6, b"0123[REDACTED]"),       # occurrence spans the cap
])
def test_redact_covers_partial_and_spanning_occurrences(buf, limit, expected):
    out, _truncated = broker_mod.redact(buf, b"SECRETVAL", limit)
    assert out == expected


# --------------------------------------------------------------------------- installer source copier


INSTALL_SH = ROOT / "scripts" / "install.sh"


def _run_stage_copier(src: Path, dst: Path) -> subprocess.CompletedProcess:
    """Run install.sh's no-follow source copier as the test user (root-only fchown stubbed)."""
    text = INSTALL_SH.read_text()
    code = re.search(r"stage_tree\(\) \{\n[^\n]*<<'PYEOF'\n(.*?)\nPYEOF", text, re.S).group(1)
    wrapper = ("import os, sys\nos.fchown = lambda *a: None\n"
               "sys.argv = ['-'] + sys.argv[1:]\nexec(compile(sys.stdin.read(), 'stage_tree', 'exec'))\n")
    return subprocess.run([sys.executable, "-I", "-B", "-c", wrapper, str(src), str(dst), ".lbs-vault-installed"],
                          input=code, text=True, capture_output=True)


def test_installer_copier_copies_regular_tree(tmp_path):
    src = tmp_path / "src"
    (src / "pkg" / "__pycache__").mkdir(parents=True)
    (src / "pkg" / "mod.py").write_text("X = 1\n")
    (src / "pkg" / "__pycache__" / "mod.cpython-312.pyc").write_bytes(b"junk")
    (src / "top.py").write_text("Y = 2\n")
    dst = tmp_path / "stage" / "out"
    proc = _run_stage_copier(src, dst)
    assert proc.returncode == 0, proc.stderr
    assert (dst / "pkg" / "mod.py").read_text() == "X = 1\n"
    assert not (dst / "pkg" / "__pycache__").exists()
    assert _mode(dst / "top.py") == 0o644 and _mode(dst / "pkg") == 0o755 and _mode(dst) == 0o755
    assert (dst / ".lbs-vault-installed").is_file()


@pytest.mark.parametrize("kind", ["file_symlink", "dir_symlink", "hardlink", "fifo"])
def test_installer_copier_refuses_links_and_special_files(tmp_path, kind):
    canary = new_canary()
    outside = tmp_path / "root-secret"
    outside.write_text(canary)
    outside.chmod(0o600)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("ok\n")
    if kind == "file_symlink":
        (src / "evil.py").symlink_to(outside)
    elif kind == "dir_symlink":
        (src / "evil").symlink_to(tmp_path)
    elif kind == "hardlink":
        os.link(outside, src / "evil.py")
    else:
        os.mkfifo(src / "evil.py")
    dst = tmp_path / "stage" / "out"
    proc = _run_stage_copier(src, dst)
    assert proc.returncode != 0
    assert "refusing" in proc.stderr
    for path in dst.rglob("*") if dst.exists() else ():
        if path.is_file() and not path.is_symlink():
            assert canary not in path.read_text(errors="ignore")
    # The source root itself being a symlink is refused too.
    link_root = tmp_path / "linkroot"
    link_root.symlink_to(src)
    assert _run_stage_copier(link_root, tmp_path / "stage2" / "out").returncode != 0


def test_incomplete_headers_have_absolute_deadline_and_release_slots(vault):
    vault.http.request_deadline = 0.2
    clients = []
    stop = threading.Event()
    try:
        for _ in range(16):
            client = socket.create_connection(("127.0.0.1", vault.http.server_port), timeout=2)
            client.sendall(b"GET / HTTP/1.1\r\nX-Slow: ")
            clients.append(client)

        def trickle():
            while not stop.wait(0.02):
                for client in clients:
                    try:
                        client.sendall(b"x")
                    except OSError:
                        pass

        writer = threading.Thread(target=trickle, daemon=True)
        started = time.monotonic()
        writer.start()
        for client in clients:
            client.settimeout(2)
            assert client.recv(1) == b""
        assert time.monotonic() - started < 2
        stop.set()
        writer.join(2)
        vault.http.request_deadline = 5
        assert vault.give() == (200, {"saved": HANDLE})
    finally:
        stop.set()
        for client in clients:
            client.close()


def test_templates_cannot_deliver_stdin_to_another_uid(vault):
    vault.give()
    templates = vault.default_templates()
    templates[0]["run_as"] = "leo"
    vault.write_templates(templates)
    result = vault.tool(plugin.vault_use, {"template_id": templates[0]["id"], "handle": HANDLE})
    assert result == {"error": "template_config_invalid", "status": 503}


def test_root_daemon_refuses_unprotected_port_before_opening_storage(monkeypatch, tmp_path):
    monkeypatch.setenv("LBS_VAULT_PORT", "8738")
    forbidden_base = tmp_path / "must-not-be-created"
    monkeypatch.setenv("LBS_VAULT_DIR", str(forbidden_base))
    monkeypatch.setattr(service_mod.os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="kernel-protected privileged port"):
        service_mod.main()
    assert not forbidden_base.exists()


def test_funnel_marked_requests_are_refused_before_secret_save(vault):
    req = vault.request()
    status, body = vault.save(request_id=req["id"], headers={"Tailscale-Funnel-Request": "?1"})
    assert (status, body) == (403, {"error": "funnel_forbidden"})
    assert vault.store.list(OWNER) == []
    assert vault.status(req["id"])[1]["status"] == "pending"


def test_owner_item_quota_preserves_updates_and_other_owner(vault, monkeypatch):
    monkeypatch.setattr(store_mod, "MAX_ITEMS_PER_OWNER", 2)
    assert vault.give(handle="first.secret")[0] == 200
    assert vault.give("login", handle="second.login")[0] == 200
    req = vault.request(handle="third.secret")
    assert vault.save(handle="third.secret", request_id=req["id"]) == (429, {"error": "owner_quota"})
    assert vault.store.status(OWNER, req["id"])["status"] == "pending"
    assert vault.give(handle="first.secret", value=new_canary())[0] == 200
    assert vault.give(handle="third.secret", owner="mallory")[0] == 200
    assert len(vault.store.list(OWNER)) == 2
    vault.assert_canary_absent_everywhere()


def test_document_capacity_refusal_is_atomic(vault, monkeypatch):
    vault.give()
    req = vault.request(handle="another.secret")
    ciphertext_before = vault.store.path.read_bytes()
    monkeypatch.setattr(store_mod, "MAX_DOCUMENT_BYTES", 1)
    assert vault.save(handle="another.secret", request_id=req["id"]) == (413, {"error": "vault_capacity"})
    assert vault.store.path.read_bytes() == ciphertext_before
    assert [s["handle"] for s in vault.store.list(OWNER)] == [HANDLE]
    assert vault.store.status(OWNER, req["id"])["status"] == "pending"


def test_header_budget_rejects_large_input_before_authentication(vault):
    status, body = vault.call("GET", "/", token=None, headers={"X-Large": "x" * 9000})
    assert (status, body) == (431, {"error": "malformed"})
    assert vault.call("GET", "/"+"x"*9000, token=None) == (414, {"error": "malformed"})
    assert vault.give() == (200, {"saved": HANDLE})


@pytest.mark.parametrize("target", ["executable", "cwd"])
def test_untrusted_template_paths_are_refused(vault, target):
    vault.give()
    templates = vault.default_templates()
    if target == "executable":
        vault.fake_target.chmod(0o777)
    else:
        bad_cwd = vault.root / "untrusted"
        bad_cwd.mkdir(mode=0o777)
        bad_cwd.chmod(0o777)
        templates[0]["cwd"] = str(bad_cwd)
    vault.write_templates(templates)
    result = vault.tool(plugin.vault_use, {"template_id": templates[0]["id"], "handle": HANDLE})
    assert result == {"error": "template_target_insecure", "status": 503}


@pytest.mark.parametrize("field,value", [
    ("_SESSION_PLATFORM", "api_server"), ("_SESSION_CHAT_TYPE", "group"),
    ("_SESSION_CHAT_TYPE", "channel"), ("_SESSION_CHAT_ID", "20002"),
    ("_SESSION_USER_ID", "20002"), ("_SESSION_USER_ID", None),
    ("_SESSION_KEY", None),
])
def test_plugin_denies_non_owner_or_unbound_context(vault, monkeypatch, field, value):
    vault.give()
    getattr(vault.context, field).set(value)
    # Even plausible process env or model arguments must not grant authority.
    for key, val in {"PLATFORM": "telegram", "CHAT_TYPE": "dm", "CHAT_ID": "10001", "USER_ID": "10001"}.items():
        monkeypatch.setenv("HERMES_SESSION_"+key, val)
    reply = json.loads(plugin.vault_list({"user_id": "10001", "owner": OWNER}))
    assert reply == {"error": "forbidden_requester"}
    denied = json.loads(plugin.vault_request({"handle": LOGIN_HANDLE, "purpose": PURPOSE, "kind": "login"}))
    assert denied == {"error": "forbidden_requester"}
    assert [e for e in vault.audit_events() if e["handle"] == LOGIN_HANDLE] == []


@pytest.mark.parametrize("kind", ["missing", "wrong_owner", "wrong_sender", "loose_mode", "symlink"])
def test_plugin_owner_policy_is_required_and_private(vault, kind):
    path = vault.base/"principals.json"
    if kind == "missing":
        path.unlink()
    elif kind in ("wrong_owner", "wrong_sender"):
        policy = {'owner': "other" if kind == "wrong_owner" else OWNER,
                  'telegram_user_id': "20002" if kind == "wrong_sender" else "10001"}
        path.write_text(json.dumps(policy))
    elif kind == "loose_mode":
        path.chmod(0o644)
    else:
        real = vault.base/"real-policy.json"
        path.rename(real)
        path.symlink_to(real)
    assert json.loads(plugin.vault_list({})) == {"error": "forbidden_requester"}


def test_plugin_identity_is_task_local_not_process_environment(vault):
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context
    vault.give()
    with ThreadPoolExecutor(max_workers=1) as executor:
        denied = json.loads(executor.submit(plugin.vault_list, {}).result())
        permitted = json.loads(executor.submit(copy_context().run, plugin.vault_list, {}).result())
    assert denied == {"error": "forbidden_requester"}
    assert [s['handle'] for s in permitted['secrets']] == [HANDLE]


def test_audit_rotation_is_bounded_private_and_metadata_only(vault, monkeypatch):
    monkeypatch.setattr(store_mod, "MAX_AUDIT_BYTES", 512)
    for number in range(20):
        assert vault.give("login" if number % 2 else "secret", handle=f"rotation.{number:02}")[0] == 200
    current = vault.base/"audit.jsonl"
    previous = vault.base/"audit.previous.jsonl"
    for path in (current, previous):
        assert path.stat().st_size <= 512
        assert _mode(path) == 0o600
        for line in path.read_text().splitlines():
            assert set(json.loads(line)) == AUDIT_KEYS
    assert json.loads(current.read_text().splitlines()[-1])["handle"] == "rotation.19"
    assert "rotation.00" not in current.read_text()+previous.read_text()
    vault.assert_canary_absent_everywhere()


def test_one_owner_cannot_exhaust_another_owners_document(vault, monkeypatch):
    monkeypatch.setattr(store_mod, "MAX_DOCUMENT_BYTES", 1600)
    foreign_value = "\U0001f642"*200
    assert vault.give(handle="foreign.one", value=foreign_value, owner="mallory")[0] == 200
    assert vault.give(handle="foreign.two", value=foreign_value, owner="mallory") == \
        (413, {"error": "vault_capacity"})
    assert vault.give() == (200, {"saved": HANDLE})
    assert vault.store.resolve_for_use(OWNER, HANDLE) == {"kind": "secret", "value": vault.canary}
    assert len(vault.store.list("mallory")) == 1
    req = vault.request()
    assert vault.store.status(OWNER, req["id"])["status"] == "pending"


def test_missing_key_with_only_foreign_owner_data_is_not_regenerated(vault):
    vault.give(owner="mallory")
    assert not vault.store.path.exists()
    vault.store.key.unlink()
    with pytest.raises(VaultError) as err:
        Store(vault.base)
    assert err.value.code == "missing_key"
    assert not vault.store.key.exists()


def test_request_budget_is_separate_from_saved_values_and_prunes(vault, monkeypatch):
    monkeypatch.setattr(store_mod, "MAX_REQUESTS_PER_OWNER", 2)
    first = vault.request()
    vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login")
    assert vault.agent_call({"op": "request", "handle": HANDLE, "purpose": PURPOSE, "kind": "secret"}) == \
        {"error": "rate_limited", "status": 429}
    # Answering an outstanding request needs no new request budget.
    assert vault.save(request_id=first["id"]) == (200, {"saved": HANDLE})
    real = time.time
    monkeypatch.setattr(store_mod, "time", types.SimpleNamespace(time=lambda: real()+90000))
    req = vault.request()
    assert req["status"] == "pending"


@pytest.mark.parametrize("field,code", [("value", "malformed"), ("purpose", "malformed"),
                                        ("username", "invalid_username")])
def test_unpaired_unicode_surrogates_are_rejected(vault, field, code):
    req = vault.request(LOGIN_HANDLE, LOGIN_PURPOSE, "login")
    body = {"request_id": req["id"], "kind": "login", "handle": LOGIN_HANDLE, "purpose": LOGIN_PURPOSE,
            "username": vault.login_user, "value": vault.login_password}
    body[field] = "bad\ud800"
    assert vault.call("POST", "/lbs-vault/secrets", body) == (400, {"error": code})
    assert vault.status(req["id"])[1]["status"] == "pending"
    assert vault.listed() == []


def test_sticky_shared_directory_is_not_an_approved_cwd(vault):
    templates = vault.default_templates()
    templates[0]['cwd'] = tempfile.gettempdir()
    vault.write_templates(templates)
    assert vault.tool(plugin.vault_use, {'template_id': templates[0]['id'], 'handle': HANDLE}) == \
        {'error': 'template_target_insecure', 'status': 503}


@pytest.mark.parametrize("name", ["tclsh8.6", "ksh93", "bsd-csh"])
def test_interpreter_aliases_are_refused_after_resolution(vault, name):
    interpreter = vault.bin/name
    interpreter.write_text("#!/bin/sh\nexit 0\n")
    interpreter.chmod(0o700)
    alias = vault.bin/'alias-command'
    alias.symlink_to(interpreter)
    vault.write_templates([{'id': 'alias.command', 'handle': HANDLE, 'kind': 'secret', 'argv': [str(alias)]}])
    assert vault.tool(plugin.vault_use, {'template_id': 'alias.command', 'handle': HANDLE}) == \
        {'error': 'template_config_invalid', 'status': 503}


def test_user_writable_shebang_interpreter_is_refused(vault):
    interpreter = vault.bin/'unsafe-interpreter'
    interpreter.write_text("#!/bin/sh\nexit 0\n")
    interpreter.chmod(0o777)
    helper = vault.bin/'unsafe-helper'
    helper.write_text(f"#!{interpreter}\nignored\n")
    helper.chmod(0o700)
    vault.write_templates([{'id': 'unsafe.helper', 'handle': HANDLE, 'kind': 'secret', 'argv': [str(helper)]}])
    assert vault.tool(plugin.vault_use, {'template_id': 'unsafe.helper', 'handle': HANDLE}) == \
        {'error': 'template_target_insecure', 'status': 503}


def test_agent_metadata_is_not_queued_behind_secret_use(vault):
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context
    marker = vault.root/'started'
    helper = vault.bin/'blocking-helper'
    helper.write_text(f"#!/bin/sh\nIFS= read -r pw\n: > '{marker}'\nsleep 2\nprintf done\n")
    helper.chmod(0o700)
    vault.write_templates([{'id': 'blocking.helper', 'handle': HANDLE, 'kind': 'secret', 'argv': [str(helper)],
                            'timeout_s': 5}])
    vault.give()
    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(copy_context().run, vault.tool, plugin.vault_use,
                                  {'template_id': 'blocking.helper', 'handle': HANDLE})
        deadline = time.monotonic()+3
        while not marker.exists() and time.monotonic() < deadline:
            threading.Event().wait(0.01)
        assert marker.exists()
        started = time.monotonic()
        metadata = vault.tool(plugin.vault_list)
        assert time.monotonic()-started < 1
        assert [s['handle'] for s in metadata['secrets']] == [HANDLE]
        assert running.result(timeout=5)['exit_code'] == 0


def test_use_transport_loss_reports_unknown_not_safe_to_retry(vault, monkeypatch):
    path = vault.run/'lost-reply.sock'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)

    def lose_reply():
        connection, _ = listener.accept()
        with connection:
            connection.recv(16384)
    worker = threading.Thread(target=lose_reply, daemon=True)
    worker.start()
    try:
        monkeypatch.setenv('LBS_VAULT_SOCKET', str(path))
        assert json.loads(plugin.vault_use({'template_id': 'fake.sudo-check', 'handle': HANDLE})) == \
            {'error': 'vault_outcome_unknown'}
    finally:
        listener.close()
        worker.join(2)
