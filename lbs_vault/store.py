"""Root-side Fernet store. Never import this module in the Hermes plugin."""
from __future__ import annotations
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from pathlib import Path
from cryptography.fernet import Fernet

HANDLE = re.compile(r"[a-z0-9][a-z0-9._-]{1,63}\Z")
ID = re.compile(r"[A-Za-z0-9_-]{43}\Z")
MAX_ITEMS_PER_OWNER = 128
MAX_REQUESTS_PER_OWNER = 128
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_AUDIT_BYTES = 4 * 1024 * 1024
KINDS = frozenset(("secret", "login"))
UNSET = object()

class VaultError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)

def text(value, maximum, empty=False):
    if not isinstance(value, str) or (not value and not empty) or len(value) > maximum or any(ord(c)<32 or 0xD800<=ord(c)<=0xDFFF for c in value):
        raise VaultError(400, "malformed")
    return value

def handle_valid(value):
    if not isinstance(value, str) or not HANDLE.fullmatch(value):
        raise VaultError(400, "invalid_handle")
    return value

def kind_valid(value):
    if not isinstance(value, str) or value not in KINDS:
        raise VaultError(400, "invalid_kind")
    return value

def private_dir(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o700:
        raise VaultError(500, "unsafe_permissions")
    return path

def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1:
            raise VaultError(500, "unsafe_permissions")
        if s.st_size > MAX_FILE_BYTES: raise VaultError(500, "store_too_large")
        data = f.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES: raise VaultError(500, "store_too_large")
        return data

def atomic(path, data):
    fd, name = tempfile.mkstemp(prefix='.write-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        with contextlib.suppress(FileNotFoundError): os.unlink(name)

class Store:
    def __init__(self, base):
        self.base = private_dir(base)
        self.keys = private_dir(self.base / 'keys')
        self.key = self.keys / 'vault.key'
        self.owner = text(os.environ.get('LBS_VAULT_OWNER','leo'),64)
        self.path = self.path_for(self.owner)
        self.lock = threading.RLock()
        with self.transaction() as data:
            pass

    def path_for(self, owner):
        text(owner,64)
        return self.base / ('owner-'+hashlib.sha256(owner.encode()).hexdigest()+'.enc')

    @contextlib.contextmanager
    def transaction(self, owner=None):
        with self.lock:
            path=self.path_for(self.owner if owner is None else owner)
            fd = os.open(self.base / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                s = os.fstat(fd)
                if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o600:
                    raise VaultError(500,'unsafe_permissions')
                fcntl.flock(fd, fcntl.LOCK_EX)
                if not self.key.exists():
                    if any(self.base.glob('owner-*.enc')): raise VaultError(500, 'missing_key')
                    atomic(self.key, Fernet.generate_key())
                self.crypto = Fernet(read_private(self.key))
                data = json.loads(self.crypto.decrypt(read_private(path))) if path.exists() else {'items':{}, 'requests':{}}
                data['requests']={k:v for k,v in data['requests'].items() if v['expires_at']>time.time()-86400}
                yield data
            finally:
                os.close(fd)

    def persist(self, data, owner):
        payload = json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode()
        if len(payload) > MAX_DOCUMENT_BYTES: raise VaultError(413, "vault_capacity")
        atomic(self.path_for(owner), self.crypto.encrypt(payload))

    def audit(self, owner, handle, op, status):
        # All arguments here are validated metadata, never caller exception text.
        event = json.dumps(dict(time=time.time(), actor=owner, handle=handle, op=op, status=status)).encode()+b'\n'
        def checked_open(path, flags):
            fd = os.open(path, flags|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CREAT, 0o600)
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600:
                os.close(fd)
                raise VaultError(500,'unsafe_permissions')
            return fd
        lock_fd = checked_open(self.base/'.audit.lock', os.O_RDWR)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            path = self.base/'audit.jsonl'
            fd = checked_open(path, os.O_WRONLY|os.O_APPEND)
            try:
                if os.fstat(fd).st_size+len(event)>MAX_AUDIT_BYTES:
                    os.replace(path,self.base/'audit.previous.jsonl')
                    os.close(fd)
                    fd = -1
                    fd = checked_open(path, os.O_WRONLY|os.O_APPEND)
                view=memoryview(event)
                while view:
                    written=os.write(fd,view)
                    if written<=0: raise OSError('audit write failed')
                    view=view[written:]
                os.fsync(fd)
            finally:
                if fd>=0: os.close(fd)
        finally: os.close(lock_fd)

    def request(self, owner, handle, purpose, kind, ttl=600):
        text(owner, 64); handle_valid(handle); text(purpose, 256); kind_valid(kind)
        if type(ttl) is not int or not 1 <= ttl <= 600:
            raise VaultError(400, "invalid_ttl")
        with self.transaction(owner) as d:
            if len(d["requests"]) >= MAX_REQUESTS_PER_OWNER:
                raise VaultError(429, "rate_limited")
            rid = secrets.token_urlsafe(32)
            r = dict(owner=owner, handle=handle, purpose=purpose, kind=kind,
                     expires_at=time.time()+ttl, status="pending")
            d["requests"][rid] = r
            self.persist(d, owner)
            self.audit(owner, handle, "request", "pending")
            return dict(id=rid, link="tglens://vault?req="+rid,
                        **{k: v for k, v in r.items() if k != "owner"})

    def _request(self, d, owner, rid):
        if not isinstance(rid, str) or not ID.fullmatch(rid):
            raise VaultError(404, "not_found")
        r = d["requests"].get(rid)
        if not r or r.get("owner") != owner:
            raise VaultError(404, "not_found")
        if r.get("kind") not in KINDS:
            raise VaultError(409, "request_reissue_required")
        return r

    @staticmethod
    def _pending(r):
        if r["expires_at"] <= time.time():
            raise VaultError(410, "expired")
        if r["status"] != "pending":
            raise VaultError(409, "consumed")

    def status(self, owner, rid):
        with self.transaction(owner) as d:
            r = self._request(d, owner, rid)
            status = "expired" if r["expires_at"] <= time.time() and r["status"] == "pending" else r["status"]
            return {k: r[k] for k in ("handle", "purpose", "kind")} | {"status": status}

    def cancel(self, owner, rid):
        with self.transaction(owner) as d:
            r = self._request(d, owner, rid)
            self._pending(r)
            r["status"] = "cancelled"
            self.persist(d, owner)
            self.audit(owner, r["handle"], "cancel", "cancelled")
            return {"status": "cancelled"}

    def save(self, owner, handle, purpose, kind, value, request_id=None, username=UNSET):
        kind_valid(kind)
        if kind == "secret":
            if username is not UNSET:
                raise VaultError(400, "invalid_fields")
        else:
            if username is UNSET:
                raise VaultError(400, "invalid_fields")
            try:
                text(username, 256)
            except VaultError:
                raise VaultError(400, "invalid_username") from None
            if not username.strip():
                raise VaultError(400, "invalid_username")
        text(owner, 64); handle_valid(handle); text(purpose, 256); text(value, 8192)
        if len(value.encode("utf-8")) > 8192:
            raise VaultError(400, "invalid_value")
        if request_id is None:
            raise VaultError(403, "request_required")
        with self.transaction(owner) as d:
            r = self._request(d, owner, request_id)
            self._pending(r)
            if r["kind"] != kind:
                raise VaultError(400, "request_kind_mismatch")
            if r["handle"] != handle or r["purpose"] != purpose:
                raise VaultError(400, "request_mismatch")
            key = owner+":"+handle
            if key not in d["items"] and len(d["items"]) >= MAX_ITEMS_PER_OWNER:
                raise VaultError(429, "owner_quota")
            item = dict(owner=owner, handle=handle, purpose=purpose, kind=kind,
                        updated_at=time.time(), value=value)
            if kind == "login":
                item["username"] = username
            d["items"][key] = item
            r["status"] = "saved"
            self.persist(d, owner)
            self.audit(owner, handle, "save", "saved")
            return {"saved": handle}

    def list(self, owner):
        with self.transaction(owner) as d:
            result = []
            for item in d["items"].values():
                metadata = {k: item[k] for k in ("handle", "purpose", "updated_at")}
                metadata["kind"] = item.get("kind") if item.get("kind") in KINDS else None
                if metadata["kind"] == "login":
                    metadata["username"] = item["username"]
                elif metadata["kind"] is None:
                    metadata["requires_request"] = True
                result.append(metadata)
            return result

    def resolve_for_use(self, owner, handle):
        """Return one atomic credential snapshot only to the private broker."""
        with self.transaction(owner) as d:
            item = d["items"].get(owner+":"+handle)
            if item is None:
                raise VaultError(404, "not_found")
            if item.get("kind") not in KINDS:
                raise VaultError(409, "item_reissue_required")
            result = {"kind": item["kind"], "value": item["value"]}
            if item["kind"] == "login":
                result["username"] = item["username"]
            return result
