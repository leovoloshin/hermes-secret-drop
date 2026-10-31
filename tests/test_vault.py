"""Behaviour tests for the LBS vault: store, owner HTTP API, agent sockets, broker, plugin.

Every secret is a freshly generated fake canary (``CANARY-<hex>``). The tests assert
that the canary never appears in HTTP responses, tool results, the audit log, files
next to the encrypted store, captured stdout/stderr/logging, request URLs, or any
process argv/environment while a template runs.

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
PUBLIC_HOST = service_mod.HOST
ID_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
AUDIT_KEYS = {"time", "actor", "handle", "op", "status"}


def new_canary() -> str:
    return "CANARY-" + secrets.token_hex(16)


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
        self.write_templates(self.default_templates())
        self.start()

    @staticmethod
    def _device(device_id, owner, token, expires_at):
        return {"id": device_id, "owner": owner, "expires_at": expires_at,
                "token_sha256": hashlib.sha256(token.encode()).hexdigest()}

    # -- fake target: a sudo-like consumer that reads the password from stdin ----------
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

    def default_templates(self) -> list[dict]:
        return [
            {"id": "fake.sudo-check", "handle": HANDLE, "argv": [str(self.fake_target)],
             "description": "fake sudo consumer", "timeout_s": 20},
            {"id": "fake.echo", "handle": HANDLE, "argv": [shutil.which("cat")], "timeout_s": 10},
            {"id": "fake.slow", "handle": HANDLE, "argv": [shutil.which("sleep"), "30"], "timeout_s": 1},
            {"id": "other.check", "handle": "other.thing", "argv": [str(self.fake_target)], "timeout_s": 10},
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

    def request(self, handle=HANDLE, purpose=PURPOSE, ttl_s=None) -> dict:
        body = {"op": "request", "handle": handle, "purpose": purpose}
        if ttl_s is not None:
            body["ttl_s"] = ttl_s
        reply = self.agent_call(body)
        assert "error" not in reply, reply
        return reply

    def save(self, value=None, handle=HANDLE, purpose=PURPOSE, request_id=None, **kw):
        body = {"handle": handle, "purpose": purpose, "value": self.canary if value is None else value}
        if request_id is not None:
            body["request_id"] = request_id
        return self.call("POST", "/lbs-vault/secrets", body, **kw)

    def audit_events(self) -> list[dict]:
        path = self.base / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def assert_canary_absent_everywhere(self, extra: str = "") -> None:
        needle = self.canary.encode()
        for blob in self.responses:
            assert needle not in blob
        for out in self.tool_results:
            assert self.canary not in out
        for url in self.urls:
            assert self.canary not in url
        assert self.canary not in extra
        for path in self.root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                assert needle not in path.read_bytes(), f"canary found in {path}"


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
    context=types.ModuleType("gateway.session_context")
    context._SESSION_KEY=ContextVar('fake-key',default=None)
    context._SESSION_KEY.set('telegram:dm:10001')
    context.bound_session_key=lambda: context._SESSION_KEY.get() or ''
    for name,value in (('_SESSION_PLATFORM','telegram'),('_SESSION_CHAT_TYPE','dm'),
                       ('_SESSION_CHAT_ID','10001'),('_SESSION_USER_ID','10001')):
        var=ContextVar(name,default=None); var.set(value); setattr(context,name,var)
    gateway=types.ModuleType('gateway'); gateway.session_context=context
    monkeypatch.setitem(sys.modules,'gateway',gateway)
    monkeypatch.setitem(sys.modules,'gateway.session_context',context)
    monkeypatch.setenv('LBS_VAULT_OWNER',OWNER)
    policy=v.base/'principals.json'
    policy.write_text(json.dumps({'owner':OWNER,'telegram_user_id':'10001'}))
    policy.chmod(0o600)
    v.context=context
    try:
        yield v
    finally:
        v.stop()
        shutil.rmtree(root, ignore_errors=True)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


# --------------------------------------------------------------------------- store at rest


def test_store_files_are_private_and_ciphertext(vault):
    status, body = vault.save()
    assert (status, body) == (200, {"saved": HANDLE})
    assert _mode(vault.base) == 0o700
    assert _mode(vault.base / "keys") == 0o700
    for name in ("keys/vault.key", "vault.enc", "audit.jsonl", ".lock"):
        assert _mode(vault.base / name) == 0o600, name
    blob = (vault.base / "vault.enc").read_bytes()
    assert vault.canary.encode() not in blob
    # It really is Fernet ciphertext under the separate key file.
    key = (vault.base / "keys" / "vault.key").read_bytes()
    assert vault.canary in Fernet(key).decrypt(blob).decode()
    vault.assert_canary_absent_everywhere()


def test_restart_persistence_keeps_key_items_and_request_state(vault):
    req = vault.request()
    assert vault.save(request_id=req["id"])[0] == 200
    key_before = (vault.base / "keys" / "vault.key").read_bytes()
    vault.restart()
    assert (vault.base / "keys" / "vault.key").read_bytes() == key_before
    listed = vault.agent_call({"op": "list"})
    assert [s["handle"] for s in listed["secrets"]] == [HANDLE]
    # A consumed request is still consumed after restart (no replay window).
    assert vault.save(request_id=req["id"]) == (409, {"error": "consumed"})
    assert vault.call("GET", f"/lbs-vault/requests/{req['id']}")[1]["status"] == "saved"
    # And the persisted value still decrypts for the broker.
    assert Store(vault.base).resolve(OWNER, HANDLE) == vault.canary
    vault.assert_canary_absent_everywhere()


def test_missing_key_is_refused_not_regenerated(vault):
    vault.save()
    (vault.base / "keys" / "vault.key").unlink()
    with pytest.raises(VaultError) as err:
        Store(vault.base)
    assert err.value.code == "missing_key"
    assert not (vault.base / "keys" / "vault.key").exists()


@pytest.mark.parametrize("target,mode", [("vault.enc", 0o644), ("keys/vault.key", 0o640), ("audit.jsonl", 0o604)])
def test_loose_file_permissions_fail_closed(vault, target, mode):
    vault.save()
    os.chmod(vault.base / target, mode)
    with pytest.raises(VaultError) as err:
        s = Store(vault.base)
        s.save(OWNER, "another.handle", PURPOSE, new_canary())
    assert err.value.code == "unsafe_permissions"


def test_loose_store_directory_is_refused(vault):
    os.chmod(vault.base, 0o755)
    with pytest.raises(VaultError) as err:
        Store(vault.base)
    assert err.value.code == "unsafe_permissions"


def test_symlinked_store_file_is_refused(vault):
    vault.save()
    enc = vault.base / "vault.enc"
    moved = vault.root / "elsewhere.enc"
    os.replace(enc, moved)
    enc.symlink_to(moved)
    with pytest.raises((VaultError, OSError)):  # O_NOFOLLOW: fails closed either way
        Store(vault.base).list(OWNER)


def test_audit_log_is_metadata_only(vault):
    req = vault.request()
    vault.save(request_id=req["id"])
    vault.save(handle="proactive.token")
    events = vault.audit_events()
    assert [e["op"] for e in events] == ["request", "save", "save"]
    for event in events:
        assert set(event) == AUDIT_KEYS
        assert event["actor"] == OWNER
    vault.assert_canary_absent_everywhere()


# --------------------------------------------------------------------------- owner HTTP API


def test_request_save_flow_with_link_and_metadata_only_status(vault):
    req = vault.request()
    assert set(req) == {"id", "handle", "purpose", "expires_at", "status", "link"}
    assert ID_RE.fullmatch(req["id"])
    assert req["link"] == "tglens://vault?req=" + req["id"]
    assert req["status"] == "pending" and req["expires_at"] - time.time() <= 600
    # Both the published (/lbs-vault prefixed) and Serve-stripped paths work.
    for path in (f"/lbs-vault/requests/{req['id']}", f"/requests/{req['id']}"):
        assert vault.call("GET", path) == (200, {"handle": HANDLE, "purpose": PURPOSE, "status": "pending"})
    assert vault.save(request_id=req["id"]) == (200, {"saved": HANDLE})
    assert vault.call("GET", f"/requests/{req['id']}")[1]["status"] == "saved"
    vault.assert_canary_absent_everywhere()


def test_proactive_save_without_request(vault):
    assert vault.save(handle="proactive.token", purpose="owner initiated") == (200, {"saved": "proactive.token"})
    listed = vault.agent_call({"op": "list"})["secrets"]
    assert [(s["handle"], s["purpose"]) for s in listed] == [("proactive.token", "owner initiated")]
    vault.assert_canary_absent_everywhere()


def test_replayed_request_is_rejected(vault):
    req = vault.request()
    assert vault.save(request_id=req["id"])[0] == 200
    assert vault.save(value=new_canary(), request_id=req["id"]) == (409, {"error": "consumed"})
    assert Store(vault.base).resolve(OWNER, HANDLE) == vault.canary
    vault.assert_canary_absent_everywhere()


def test_wrong_handle_or_purpose_does_not_consume_request(vault):
    req = vault.request()
    assert vault.save(handle="other.handle", request_id=req["id"]) == (400, {"error": "request_mismatch"})
    assert vault.save(purpose="different purpose", request_id=req["id"]) == (400, {"error": "request_mismatch"})
    assert vault.call("GET", f"/requests/{req['id']}")[1]["status"] == "pending"
    assert vault.agent_call({"op": "list"})["secrets"] == []
    assert vault.save(request_id=req["id"])[0] == 200
    vault.assert_canary_absent_everywhere()


def test_cancel_then_save_is_rejected(vault):
    req = vault.request()
    assert vault.call("POST", f"/lbs-vault/requests/{req['id']}/cancel", {}) == (200, {"status": "cancelled"})
    assert vault.call("GET", f"/requests/{req['id']}")[1]["status"] == "cancelled"
    assert vault.save(request_id=req["id"]) == (409, {"error": "consumed"})
    assert vault.call("POST", f"/requests/{req['id']}/cancel", {}) == (409, {"error": "consumed"})
    assert vault.call("POST", f"/requests/{req['id']}/cancel", {"x": 1})[0] == 400
    assert vault.agent_call({"op": "list"})["secrets"] == []
    assert [e["op"] for e in vault.audit_events()] == ["request", "cancel"]
    vault.assert_canary_absent_everywhere()


def test_expired_request_times_out(vault, monkeypatch):
    req = vault.request(ttl_s=60)
    real = time.time
    monkeypatch.setattr(store_mod, "time", types.SimpleNamespace(time=lambda: real() + 61))
    assert vault.call("GET", f"/requests/{req['id']}")[1]["status"] == "expired"
    assert vault.save(request_id=req["id"]) == (410, {"error": "expired"})
    assert vault.call("POST", f"/requests/{req['id']}/cancel", {}) == (410, {"error": "expired"})
    assert vault.agent_call({"op": "list"})["secrets"] == []
    vault.assert_canary_absent_everywhere()


def test_ttl_is_bounded_to_ten_minutes(vault):
    for ttl in (0, 601, "60", 60.5):
        reply = vault.agent_call({"op": "request", "handle": HANDLE, "purpose": PURPOSE, "ttl_s": ttl})
        assert reply == {"error": "invalid_ttl", "status": 400}


def test_request_ids_are_owner_bound(vault):
    req = vault.request()
    assert vault.call("GET", f"/requests/{req['id']}", token=vault.other_token) == (404, {"error": "not_found"})
    assert vault.save(request_id=req["id"], token=vault.other_token) == (404, {"error": "not_found"})
    assert vault.call("POST", f"/requests/{req['id']}/cancel", {}, token=vault.other_token)[0] == 404
    assert vault.call("GET", f"/requests/{req['id']}")[1]["status"] == "pending"
    # Unknown and malformed ids are indistinguishable 404s.
    assert vault.call("GET", "/requests/" + "A" * 43) == (404, {"error": "not_found"})
    assert vault.call("GET", "/requests/short") == (404, {"error": "not_found"})


@pytest.mark.parametrize("token", [None, "", "wrong-token", "__expired__", "__basic__"])
def test_bad_device_bearer_is_401(vault, token):
    headers = None
    if token == "__expired__":
        token = vault.expired_token
    elif token == "__basic__":
        token, headers = None, {"Authorization": "Basic " + vault.token}
    for method, path, body in (("GET", "/lbs-vault/requests/" + "A" * 43, None),
                               ("POST", "/lbs-vault/secrets", {"handle": HANDLE, "purpose": PURPOSE,
                                                               "value": vault.canary})):
        assert vault.call(method, path, body, token=token, headers=headers) == (401, {"error": "unauthorized"})
    assert vault.agent_call({"op": "list"})["secrets"] == []
    vault.assert_canary_absent_everywhere()


def test_token_in_url_is_never_accepted(vault):
    status, _ = vault.call("GET", f"/lbs-vault/requests/{'A' * 43}?token={vault.token}", token=None)
    assert status == 400
    # A value smuggled in a query string is rejected before anything is stored.
    status, _ = vault.call("POST", "/lbs-vault/secrets?value=x", {"handle": HANDLE, "purpose": PURPOSE,
                                                                   "value": vault.canary})
    assert status == 400
    assert vault.agent_call({"op": "list"})["secrets"] == []


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
    status, body = vault.save(host=host, origin=origin)
    assert status == expected, body
    saved = [s["handle"] for s in vault.agent_call({"op": "list"})["secrets"]]
    assert saved == ([HANDLE] if expected == 200 else [])
    vault.assert_canary_absent_everywhere()


def test_public_request_creation_is_agent_only(vault):
    status, body = vault.call("POST", "/lbs-vault/requests", {"handle": HANDLE, "purpose": PURPOSE})
    assert (status, body) == (403, {"error": "agent_only"})
    assert vault.call("POST", "/requests", {"handle": HANDLE, "purpose": PURPOSE})[0] == 403


def test_local_unix_http_request_creation(vault):
    status, body = vault.local_http("POST", "/lbs-vault/requests",
                                    json.dumps({"handle": HANDLE, "purpose": PURPOSE, "ttl_s": 120}).encode())
    assert status == 200 and body["link"] == "tglens://vault?req=" + body["id"]
    assert vault.call("GET", f"/requests/{body['id']}")[1]["status"] == "pending"
    assert _mode(vault.run / "requests.sock") == 0o600
    # Strict body: no owner override, no unknown fields, no other routes.
    assert vault.local_http("POST", "/lbs-vault/requests",
                            json.dumps({"handle": HANDLE, "purpose": PURPOSE, "owner": "mallory"}).encode())[0] == 400
    assert vault.local_http("POST", "/lbs-vault/secrets",
                            json.dumps({"handle": HANDLE, "purpose": PURPOSE, "value": vault.canary}).encode())[0] == 404
    assert vault.agent_call({"op": "list"})["secrets"] == []
    vault.assert_canary_absent_everywhere()


@pytest.mark.parametrize("raw,content_type,expected", [
    (b"{not json", "application/json", 400),
    (b"[]", "application/json", 400),
    (b'{"handle":"fake.sudo","handle":"x.y","purpose":"p","value":"v"}', "application/json", 400),
    (b'{"handle":"fake.sudo","purpose":"p","value":"v","extra":1}', "application/json", 400),
    (b'{"handle":"fake.sudo","purpose":"p"}', "application/json", 400),
    (b'{"handle":"Bad Handle","purpose":"p","value":"v"}', "application/json", 400),
    (b'{"handle":"a","purpose":"p","value":"v"}', "application/json", 400),
    (b'{"handle":"fake.sudo","purpose":"p","value":""}', "application/json", 400),
    (b'{"handle":"fake.sudo","purpose":"p","value":"a\\nb"}', "application/json", 400),
    (b'{"handle":"fake.sudo","purpose":"p","value":"a\\u0000b"}', "application/json", 400),
    (b'{"handle":"fake.sudo","purpose":"p","value":"v"}', "text/plain", 400),
])
def test_malformed_bodies_are_rejected(vault, raw, content_type, expected):
    status, body = vault.call("POST", "/lbs-vault/secrets", raw=raw, content_type=content_type)
    assert status == expected
    assert set(body) == {"error"}
    assert vault.agent_call({"op": "list"})["secrets"] == []


def test_oversized_body_and_value_are_rejected(vault):
    # Declared length over the cap is refused before the body is read.
    assert vault.call("POST", "/lbs-vault/secrets", raw=b"{}", headers={"Content-Length": "20000"}) == \
        (413, {"error": "body_too_large"})
    assert vault.save(value="x" * 8193)[0] == 400
    # 4097 x 2-byte chars: body under the 16 KiB cap, value over the 8192 UTF-8 byte cap.
    raw = json.dumps({"handle": HANDLE, "purpose": PURPOSE, "value": "é" * 4097}, ensure_ascii=False).encode()
    assert len(raw) < 16384
    assert vault.call("POST", "/lbs-vault/secrets", raw=raw)[0] == 400
    assert vault.agent_call({"op": "list"})["secrets"] == []


def test_errors_never_echo_submitted_value(vault):
    req = vault.request()
    vault.save(handle="Bad Handle")
    vault.save(request_id=req["id"], handle="other.handle")
    vault.save(request_id="A" * 43)
    vault.call("POST", "/lbs-vault/secrets", raw=json.dumps({"value": vault.canary, "bogus": 1}).encode())
    vault.save(origin="https://evil.example")
    vault.save(token="wrong")
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
    vault.save()
    for bad in ({"op": "get", "handle": HANDLE}, {"op": "read", "handle": HANDLE},
                {"op": "resolve", "handle": HANDLE}, {"op": "export"},
                {"op": "list", "owner": "mallory"},
                {"op": "status", "id": "A" * 43, "owner": "mallory"},
                {"op": "use", "template_id": "fake.sudo-check", "handle": HANDLE, "argv": ["/bin/id"]}):
        reply = vault.agent_call(bad)
        assert reply.get("status") == 400, (bad, reply)
    listed = vault.agent_call({"op": "list"})
    assert set(listed) == {"secrets", "templates"}
    assert all("value" not in s for s in listed["secrets"])
    assert {t["id"] for t in listed["templates"]} == {"fake.sudo-check", "fake.echo", "fake.slow", "other.check"}
    assert all(set(t) == {"id", "handle", "description", "timeout_s"} for t in listed["templates"])
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
        assert not {"value", "password", "secret", "argv", "command", "env"} & set(params["properties"])
    vault.save()
    # Through the registered handlers the model only ever gets metadata and redacted output.
    listed = json.loads(ctx.tools["vault_list"][1]({}))
    assert [s["handle"] for s in listed["secrets"]] == [HANDLE]
    used = json.loads(ctx.tools["vault_use"][1]({"template_id": "fake.echo", "handle": HANDLE,
                                                 "argv": ["/bin/id"], "value": "x"}))
    assert used["output"].strip() == "[REDACTED]"
    vault.tool_results += [json.dumps(listed), json.dumps(used)]
    vault.assert_canary_absent_everywhere()


def test_plugin_reports_unavailable_vault(vault, monkeypatch, tmp_path):
    monkeypatch.setenv("LBS_VAULT_SOCKET", str(tmp_path / "missing.sock"))
    assert json.loads(plugin.vault_list({})) == {"error": "vault_unavailable"}


def test_plugin_validates_before_calling(vault):
    assert vault.tool(plugin.vault_request, {"handle": "BAD", "purpose": PURPOSE})["error"] == "invalid_handle"
    assert vault.tool(plugin.vault_request, {"handle": HANDLE, "purpose": "a\nb"})["error"] == "invalid_purpose"
    assert vault.tool(plugin.vault_status, {"id": "nope"})["error"] == "invalid_id"
    assert vault.tool(plugin.vault_use, {"template_id": "x y", "handle": HANDLE})["error"] == "invalid_template_id"
    assert [e["op"] for e in vault.audit_events()] == []


# --------------------------------------------------------------------------- broker


def _scan_proc(needle: bytes, marker: bytes, hits: list, seen: list, stop: threading.Event) -> None:
    while not stop.is_set():
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            for name in ("cmdline", "environ"):
                try:
                    data = Path("/proc", pid, name).read_bytes()
                except OSError:
                    continue
                if needle in data:
                    hits.append((pid, name))
                if name == "cmdline" and marker in data:
                    seen.append(pid)
        time.sleep(0.02)


def test_end_to_end_request_save_use_without_leaks(vault, capfd, caplog):
    caplog.set_level("DEBUG")
    # 1. LBS asks for the handle; the tool result is metadata plus the link.
    req = vault.tool(plugin.vault_request, {"handle": HANDLE, "purpose": PURPOSE, "ttl_s": 300})
    assert req["link"] == "tglens://vault?req=" + req["id"] and "next_step" in req
    # 2. Rubric re-fetches metadata by id and posts the value straight to the vault.
    assert vault.call("GET", f"/lbs-vault/requests/{req['id']}", host=PUBLIC_HOST,
                      origin="https://" + PUBLIC_HOST)[1] == {"handle": HANDLE, "purpose": PURPOSE,
                                                               "status": "pending"}
    assert vault.save(request_id=req["id"], host=PUBLIC_HOST) == (200, {"saved": HANDLE})
    # 3. LBS sees only the status and the handle.
    assert vault.tool(plugin.vault_status, {"id": req["id"]}) == {"handle": HANDLE, "purpose": PURPOSE,
                                                                 "status": "saved"}
    listed = vault.tool(plugin.vault_list)
    assert [s["handle"] for s in listed["secrets"]] == [HANDLE]
    # 4. LBS uses the handle through the broker while we watch every process argv/env.
    hits, seen, stop = [], [], threading.Event()
    watcher = threading.Thread(target=_scan_proc, args=(vault.canary.encode(), str(vault.fake_target).encode(),
                                                        hits, seen, stop), daemon=True)
    watcher.start()
    try:
        result = vault.tool(plugin.vault_use, {"template_id": "fake.sudo-check", "handle": HANDLE})
    finally:
        stop.set()
        watcher.join(5)
    assert seen, "the /proc scan never observed the fake target running"
    assert hits == []
    assert result["exit_code"] == 0 and result["timed_out"] is False
    assert "fake-sudo: authenticated" in result["output"]
    assert "careless target echoes: [REDACTED]" in result["output"]
    assert set(result) >= {"template_id", "handle", "exit_code", "timed_out", "truncated", "output", "duration_ms"}
    ops = [(e["op"], e["status"]) for e in vault.audit_events()]
    assert ops == [("request", "pending"), ("save", "saved"), ("use", "exit:0")]
    captured = capfd.readouterr()
    logs = "\n".join(r.getMessage() for r in caplog.records)
    vault.assert_canary_absent_everywhere(captured.out + captured.err + logs)


def test_use_with_wrong_value_reports_failure_only(vault):
    vault.save(value=new_canary())  # not what the fake target expects
    result = vault.tool(plugin.vault_use, {"template_id": "fake.sudo-check", "handle": HANDLE})
    assert result["exit_code"] == 1 and "wrong password" in result["output"]
    vault.assert_canary_absent_everywhere()


def test_command_output_echoing_the_secret_is_redacted(vault):
    vault.save()
    result = vault.tool(plugin.vault_use, {"template_id": "fake.echo", "handle": HANDLE})
    assert result["exit_code"] == 0
    assert result["output"].strip() == "[REDACTED]"
    vault.assert_canary_absent_everywhere()


def test_wrong_target_or_unknown_template_is_refused(vault):
    vault.save()
    vault.save(handle="other.thing", value=new_canary())
    # Template bound to another handle.
    assert vault.tool(plugin.vault_use, {"template_id": "other.check", "handle": HANDLE}) == \
        {"error": "handle_mismatch", "status": 403}
    assert vault.tool(plugin.vault_use, {"template_id": "fake.sudo-check", "handle": "other.thing"}) == \
        {"error": "handle_mismatch", "status": 403}
    assert vault.tool(plugin.vault_use, {"template_id": "no.such", "handle": HANDLE}) == \
        {"error": "unknown_template", "status": 404}
    # Template exists but nothing saved under its handle.
    vault.write_templates(vault.default_templates() + [
        {"id": "missing.check", "handle": "missing.handle", "argv": [str(vault.fake_target)]}])
    assert vault.tool(plugin.vault_use, {"template_id": "missing.check", "handle": "missing.handle"})["status"] == 404
    statuses = [e["status"] for e in vault.audit_events() if e["op"] == "use"]
    assert statuses == ["handle_mismatch", "handle_mismatch", "unknown_template", "not_found"]
    vault.assert_canary_absent_everywhere()


def test_use_timeout_kills_target(vault):
    vault.save()
    started = time.monotonic()
    result = vault.tool(plugin.vault_use, {"template_id": "fake.slow", "handle": HANDLE})
    assert result["timed_out"] is True and result["exit_code"] is None
    assert time.monotonic() - started < 10
    assert [e["status"] for e in vault.audit_events() if e["op"] == "use"] == ["timeout"]
    vault.assert_canary_absent_everywhere()


def test_insecure_or_invalid_templates_are_refused(vault):
    vault.save()
    vault.write_templates(vault.default_templates(), mode=0o622)
    reply = vault.tool(plugin.vault_use, {"template_id": "fake.sudo-check", "handle": HANDLE})
    assert reply == {"error": "template_config_insecure", "status": 503}
    for bad in ({"id": "shell.x", "handle": HANDLE, "argv": [shutil.which("sh"), "-c", "id"]},
                {"id": "py.x", "handle": HANDLE, "argv": [sys.executable, "-c", "0"]},
                {"id": "rel.x", "handle": HANDLE, "argv": ["fake-sudo"]},
                {"id": "env.x", "handle": HANDLE, "argv": [str(vault.fake_target)], "env": {"LD_PRELOAD": "/x"}},
                {"id": "ask.x", "handle": HANDLE, "argv": [str(vault.fake_target)], "env": {"SUDO_ASKPASS": "/x"}}):
        vault.write_templates([bad])
        reply = vault.tool(plugin.vault_use, {"template_id": bad["id"], "handle": HANDLE})
        assert reply == {"error": "template_config_invalid", "status": 503}, bad
    vault.assert_canary_absent_everywhere()


def test_broker_rejects_requests_it_does_not_understand(vault):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(str(vault.run / "broker.sock"))
        s.sendall(json.dumps({"op": "use", "owner": OWNER, "template_id": "fake.echo", "handle": HANDLE,
                              "argv": ["/bin/id"]}).encode() + b"\n")
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
        assert vault.save() == (200, {"saved": HANDLE})
    finally:
        stop.set()
        for client in clients:
            client.close()


def test_templates_cannot_deliver_stdin_to_another_uid(vault):
    vault.save()
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
    status, body = vault.save(headers={"Tailscale-Funnel-Request": "?1"})
    assert (status, body) == (403, {"error": "funnel_forbidden"})
    assert vault.store.list(OWNER) == []


def test_owner_item_quota_preserves_updates_and_other_owner(vault, monkeypatch):
    monkeypatch.setattr(store_mod, "MAX_ITEMS_PER_OWNER", 2)
    assert vault.save(handle="first.secret")[0] == 200
    assert vault.save(handle="second.secret")[0] == 200
    req = vault.request(handle="third.secret")
    assert vault.save(handle="third.secret", request_id=req["id"]) == (429, {"error": "owner_quota"})
    assert vault.store.status(OWNER, req["id"])["status"] == "pending"
    assert vault.save(handle="first.secret", value=new_canary())[0] == 200
    assert vault.save(handle="third.secret", token=vault.other_token)[0] == 200
    assert len(vault.store.list(OWNER)) == 2


def test_document_capacity_refusal_is_atomic(vault, monkeypatch):
    vault.save()
    ciphertext_before = (vault.base / "vault.enc").read_bytes()
    monkeypatch.setattr(store_mod, "MAX_DOCUMENT_BYTES", 1)
    assert vault.save(handle="another.secret") == (413, {"error": "vault_capacity"})
    assert (vault.base / "vault.enc").read_bytes() == ciphertext_before
    assert [s["handle"] for s in vault.store.list(OWNER)] == [HANDLE]


def test_header_budget_rejects_large_input_before_authentication(vault):
    status, body = vault.call("GET", "/", token=None, headers={"X-Large": "x" * 9000})
    assert (status, body) == (431, {"error": "malformed"})
    assert vault.call("GET", "/"+"x"*9000, token=None) == (414, {"error":"malformed"})
    assert vault.save() == (200, {"saved": HANDLE})


@pytest.mark.parametrize("target", ["executable", "cwd"])
def test_untrusted_template_paths_are_refused(vault, target):
    vault.save()
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
    ("_SESSION_PLATFORM","api_server"), ("_SESSION_CHAT_TYPE","group"),
    ("_SESSION_CHAT_TYPE","channel"), ("_SESSION_CHAT_ID","20002"),
    ("_SESSION_USER_ID","20002"), ("_SESSION_USER_ID",None),
    ("_SESSION_KEY",None),
])
def test_plugin_denies_non_owner_or_unbound_context(vault, monkeypatch, field, value):
    vault.save()
    getattr(vault.context,field).set(value)
    # Even plausible process env or model arguments must not grant authority.
    for key,val in {"PLATFORM":"telegram","CHAT_TYPE":"dm","CHAT_ID":"10001","USER_ID":"10001"}.items():
        monkeypatch.setenv("HERMES_SESSION_"+key,val)
    reply=json.loads(plugin.vault_list({"user_id":"10001","owner":OWNER}))
    assert reply == {"error":"forbidden_requester"}


@pytest.mark.parametrize("kind", ["missing","wrong_owner","wrong_sender","loose_mode","symlink"])
def test_plugin_owner_policy_is_required_and_private(vault, kind):
    path=vault.base/"principals.json"
    if kind=="missing":
        path.unlink()
    elif kind in ("wrong_owner","wrong_sender"):
        policy={'owner':"other" if kind=="wrong_owner" else OWNER,
                'telegram_user_id':"20002" if kind=="wrong_sender" else "10001"}
        path.write_text(json.dumps(policy))
    elif kind=="loose_mode":
        path.chmod(0o644)
    else:
        real=vault.base/"real-policy.json"
        path.rename(real); path.symlink_to(real)
    assert json.loads(plugin.vault_list({})) == {"error":"forbidden_requester"}


def test_plugin_identity_is_task_local_not_process_environment(vault):
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context
    vault.save()
    with ThreadPoolExecutor(max_workers=1) as executor:
        denied=json.loads(executor.submit(plugin.vault_list,{}).result())
        permitted=json.loads(executor.submit(copy_context().run,plugin.vault_list,{}).result())
    assert denied == {"error":"forbidden_requester"}
    assert [s['handle'] for s in permitted['secrets']] == [HANDLE]


def test_audit_rotation_is_bounded_private_and_metadata_only(vault, monkeypatch):
    monkeypatch.setattr(store_mod,"MAX_AUDIT_BYTES",512)
    for number in range(20):
        assert vault.save(handle=f"rotation.{number:02}")[0] == 200
    current=vault.base/"audit.jsonl"
    previous=vault.base/"audit.previous.jsonl"
    for path in (current,previous):
        assert path.stat().st_size<=512
        assert _mode(path)==0o600
        for line in path.read_text().splitlines():
            assert set(json.loads(line))==AUDIT_KEYS
    assert json.loads(current.read_text().splitlines()[-1])["handle"]=="rotation.19"
    assert "rotation.00" not in current.read_text()+previous.read_text()
    vault.assert_canary_absent_everywhere()
