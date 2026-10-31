"""Loopback HTTP owner entry and root-only agent metadata socket."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import socket
import socketserver
import stat
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import LineTooLong
from pathlib import Path
from .store import Store, VaultError, read_private, private_dir

HOST = 'spark-dd6e.tail4b7569.ts.net'
MAX_BODY = 16384
MAX_HEADERS = 8192

class HeaderReader:
    """Cap aggregate headers before the stdlib parser allocates a message."""
    def __init__(self, stream):
        self.stream=stream; self.remaining=MAX_HEADERS
    def readline(self, size=-1):
        limit=self.remaining+1
        line=self.stream.readline(min(size,limit) if size>=0 else limit)
        self.remaining-=len(line)
        if self.remaining<0: raise LineTooLong('header budget')
        return line
    def __getattr__(self,name):
        return getattr(self.stream,name)

class Limiter:
    def __init__(self): self.lock=threading.Lock(); self.buckets={}
    def check(self,key,limit):
        now=time.monotonic()
        with self.lock:
            self.buckets={k:v for k,v in self.buckets.items() if now-v[0]<60}
            start,count=self.buckets.get(key,(now,0))
            if count>=limit: raise VaultError(429,'rate_limited')
            self.buckets[key]=(start,count+1)

class Server(ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=16
    request_deadline=5.0
    def __init__(self,addr,store,devices):
        self.store=store; self.devices=devices; self.limiter=Limiter()
        # Bound worker count even against many partial request headers.
        self.slots=threading.BoundedSemaphore(16)
        super().__init__(addr,Handler)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False): request.close(); return
        try: super().process_request(request,address)
        except BaseException: self.slots.release(); raise
    def process_request_thread(self,request,address):
        try: super().process_request_thread(request,address)
        finally: self.slots.release()
    def handle_error(self,request,address): pass

def make_server(store,host='127.0.0.1',port=0,devices=None):
    if host!='127.0.0.1': raise ValueError('loopback required')
    if devices is None:
        devices=json.loads(read_private(store.base/'devices.json'))['devices']
    return Server((host,port),store,devices)

class Handler(BaseHTTPRequestHandler):
    server_version='LBSVault'
    sys_version=''
    def parse_request(self):
        if len(self.raw_requestline)>MAX_HEADERS:
            self.request_version='HTTP/1.0'
            self.requestline=''
            self.command=None
            self.send_error(414)
            return False
        self.rfile=HeaderReader(self.rfile)
        return super().parse_request()
    def setup(self):
        super().setup(); self.connection.settimeout(5)
        self.deadline=threading.Timer(getattr(self.server,'request_deadline',5.0),self.expire)
        self.deadline.daemon=True
        self.deadline.start()
    def expire(self):
        try: self.connection.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        self.connection.close()
    def finish(self):
        try: super().finish()
        finally: self.deadline.cancel()
    def log_message(self,*args): pass
    def send_result(self,status,obj):
        blob=json.dumps(obj,separators=(',',':')).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(blob)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Connection','close')
        self.end_headers(); self.wfile.write(blob); self.close_connection=True
    def send_error(self,code,message=None,explain=None):
        self.send_result(code,{'error':'malformed' if code in (400,414,431) else 'method_not_allowed'})
    def refuse(self,status,code):
        # Serve uses loopback for every peer. Failed auth must not exhaust an
        # authenticated device's independent budget.
        self.server.limiter.check('failed:'+self.client_address[0],120)
        raise VaultError(status,code)
    def auth(self):
        if self.headers.get_all('Tailscale-Funnel-Request'):
            self.refuse(403,'funnel_forbidden')
        # Reject duplicate authority/auth headers, query-bearing and absolute paths.
        for h in ('Host','Authorization','Origin','Content-Length','Content-Type'):
            if len(self.headers.get_all(h,[]))>1: self.refuse(400,'malformed')
        host=self.headers.get('Host','')
        if host not in (HOST,'127.0.0.1:'+str(self.server.server_port)): self.refuse(403,'forbidden_host')
        if self.headers.get('Origin') not in (None,'https://'+HOST): self.refuse(403,'forbidden_origin')
        if '?' in self.path or '#' in self.path or not self.path.startswith('/'): self.refuse(400,'malformed')
        auth=self.headers.get('Authorization','')
        if not auth.startswith('Bearer ') or len(auth)>256: self.refuse(401,'unauthorized')
        digest=hashlib.sha256(auth[7:].encode()).hexdigest()
        found=None
        for device in self.server.devices:
            if hmac.compare_digest(digest,device['token_sha256']) and device['expires_at']>time.time(): found=device
        if found is None: self.refuse(401,'unauthorized')
        self.server.limiter.check('device:'+found['id'],60)
        return found['owner']
    def body(self):
        if self.headers.get('Transfer-Encoding') is not None: raise VaultError(400,'malformed')
        if self.headers.get('Content-Type','').split(';')[0]!='application/json': raise VaultError(400,'malformed')
        try: n=int(self.headers.get('Content-Length','-1'))
        except ValueError: raise VaultError(400,'malformed') from None
        if n<0: raise VaultError(400,'malformed')
        if n>MAX_BODY: raise VaultError(413,'body_too_large')
        raw=self.rfile.read(n)
        if len(raw)!=n: raise VaultError(400,'malformed')
        try:
            def unique(pairs):
                d={}
                for k,v in pairs:
                    if k in d: raise ValueError()
                    d[k]=v
                return d
            obj=json.loads(raw,object_pairs_hook=unique)
        except (ValueError,UnicodeError): raise VaultError(400,'malformed') from None
        if not isinstance(obj,dict): raise VaultError(400,'malformed')
        return obj
    def route(self):
        owner=self.auth()
        path=self.path
        if path.startswith('/lbs-vault/'): path=path[len('/lbs-vault'):]
        if self.command=='POST' and path=='/requests': raise VaultError(403,'agent_only')
        if self.command=='POST' and path=='/secrets':
            b=self.body()
            if set(b)-{'request_id','handle','purpose','username','value'} or not {'handle','purpose','value'}<=set(b): raise VaultError(400,'malformed')
            return self.server.store.save(owner,**b)
        pieces=path.strip('/').split('/')
        if len(pieces)>=2 and pieces[0]=='requests':
            rid=pieces[1]
            if self.command=='GET' and len(pieces)==2: return self.server.store.status(owner,rid)
            if self.command=='POST' and len(pieces)==3 and pieces[2]=='cancel':
                if self.body(): raise VaultError(400,'malformed')
                return self.server.store.cancel(owner,rid)
        raise VaultError(404,'not_found')
    def dispatch(self):
        try: self.send_result(200,self.route())
        except VaultError as e: self.send_result(e.status,{'error':e.code})
        except (OSError,ValueError,TypeError,KeyError): self.send_result(400,{'error':'malformed'})
        except Exception: self.send_result(500,{'error':'internal_error'})
    do_GET=dispatch
    do_POST=dispatch
    def unsupported(self):
        self.send_result(405, {'error':'method_not_allowed'})
    do_PUT=unsupported
    do_DELETE=unsupported
    do_PATCH=unsupported
    do_OPTIONS=unsupported
    do_HEAD=unsupported

class AgentHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            uid=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
            if uid!=os.geteuid(): raise VaultError(403,'forbidden')
            raw=self.rfile.readline(MAX_BODY+1)
            if len(raw)>MAX_BODY or not raw.endswith(b'\n'): raise VaultError(400,'malformed')
            b=json.loads(raw)
            if not isinstance(b,dict): raise VaultError(400,'malformed')
            op=b.get('op'); owner=self.server.owner; store=self.server.store
            from .broker import list_templates, request_use
            if op=='list' and set(b)=={'op'}: result={'secrets':store.list(owner),'templates':list_templates()}
            elif op=='request' and set(b)<= {'op','handle','purpose','ttl_s'}: result=store.request(owner,b['handle'],b['purpose'],b.get('ttl_s',600))
            elif op=='status' and set(b)=={'op','id'}: result=store.status(owner,b['id'])
            elif op=='use' and set(b)=={'op','template_id','handle'}: result=request_use(owner,b['template_id'],b['handle'])
            else: raise VaultError(400,'malformed')
        except VaultError as e: result={'error':e.code,'status':e.status}
        except Exception: result={'error':'internal_error','status':500}
        self.wfile.write(json.dumps(result).encode()+b'\n')

class AgentServer(socketserver.UnixStreamServer):
    def handle_error(self,*a): pass

class LocalRequestHandler(Handler):
    """HTTP semantics on a root-only Unix socket, never a proxyable TCP route."""
    def route(self):
        uid=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
        if uid!=os.geteuid(): raise VaultError(403,'forbidden')
        if self.command!='POST' or self.path!='/lbs-vault/requests':
            raise VaultError(404,'not_found')
        b=self.body()
        if set(b)-{'handle','purpose','ttl_s'} or not {'handle','purpose'}<=set(b):
            raise VaultError(400,'malformed')
        return self.server.store.request(self.server.owner,b['handle'],b['purpose'],b.get('ttl_s',600))

def local_request_server(path,store,owner='leo'):
    path=Path(path)
    private_dir(path.parent)
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode): raise RuntimeError('unsafe socket')
        path.unlink()
    server=AgentServer(str(path),LocalRequestHandler)
    os.chmod(path,0o600)
    server.store=store; server.owner=owner
    return server

def main():
    os.umask(0o077)
    port=int(os.environ.get('LBS_VAULT_PORT','938'))
    if os.geteuid()==0:
        cutoff=int(Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text())
        if not 1<=port<min(cutoff,1024):
            raise RuntimeError('vault requires a kernel-protected privileged port')
    base=Path(os.environ.get('LBS_VAULT_DIR','/root/.hermes/lbs-vault'))
    store=Store(base)
    sock=Path(os.environ.get('LBS_VAULT_SOCKET','/run/lbs-vault/agent.sock'))
    private_dir(sock.parent)
    if sock.exists():
        if not stat.S_ISSOCK(sock.lstat().st_mode): raise RuntimeError('unsafe socket')
        sock.unlink()
    agent=AgentServer(str(sock),AgentHandler)
    os.chmod(sock,0o600)
    agent.store=store; agent.owner=os.environ.get('LBS_VAULT_OWNER','leo')
    local_path=sock.with_name('requests.sock')
    local=local_request_server(local_path,store,agent.owner)
    threading.Thread(target=local.serve_forever,daemon=True).start()
    threading.Thread(target=agent.serve_forever,daemon=True).start()
    http=make_server(store,port=port)
    try: http.serve_forever()
    finally:
        http.server_close(); agent.shutdown(); agent.server_close(); sock.unlink(missing_ok=True)
        local.shutdown(); local.server_close(); local_path.unlink(missing_ok=True)

if __name__=='__main__': main()
