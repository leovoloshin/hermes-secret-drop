# Root step required: disposable live canary fixture

Run **only the setup block now**, as root. It adds one disposable test device in an isolated fake owner namespace and one fake stdin template. It restarts **only `lbs-vault.service`** to load the test device. Broker templates reload per use. Only vault fixture metadata is edited: no Hermes config.yaml, gateway restart, plugin activation, Tailscale/Funnel change, Telegram operation, or real target.

Probe ID: `20261031-200f6a5bf966`.

Builder-generated private input: `/home/leo/lbs-secret-vault/work/live-probe-20261031-200f6a5bf966/canary.txt` (0600 in 0700 directory). Do not cat it or put canary/bearer values into chat, argv, environment or output. Review this inline block; it imports installed root-owned code only. Do not blindly rerun a partial setup. The separate failure cleanup below is limited to this probe.

## Setup — run now

```sh
sudo /usr/bin/python3 -I -B - <<'PY'
import hashlib, json, os, pwd, re, stat, subprocess, sys, time
from pathlib import Path

if os.geteuid() != 0:
    raise SystemExit('root required')
probe = '20261031-200f6a5bf966'
owner = device = 'probe-' + probe
handle = template_id = 'canary.' + probe
base = Path('/root/.hermes/lbs-vault')
out = Path('/home/leo/lbs-secret-vault/work/live-probe-' + probe)
private = Path('/root/lbs-vault-live-probe-' + probe)
helper_parent = Path('/opt/lbs-vault/probes')
helper_dir = helper_parent / probe
helper = helper_dir / 'fake-stdin-target'
leo = pwd.getpwnam('leo')
env = {'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'HOME':'/root','LANG':'C.UTF-8',
       'LBS_VAULT_DIR':str(base),'LBS_VAULT_OWNER':owner}
os.environ.clear(); os.environ.update(env)
sys.path.insert(0, '/opt/lbs-vault/lib')
from lbs_vault.store import Store, atomic, read_private
from lbs_vault.broker import load_templates

# Pin the actual handoff directory; do not resolve it again for privileged I/O.
out_fd = os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
st = os.fstat(out_fd)
assert st.st_uid == leo.pw_uid and stat.S_IMODE(st.st_mode) == 0o700
fd = os.open('canary.txt',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=out_fd)
with os.fdopen(fd,'rb') as f:
    st = os.fstat(f.fileno())
    assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == leo.pw_uid and stat.S_IMODE(st.st_mode) == 0o600
    canary = f.read(128)
assert re.fullmatch(rb'CANARY-[0-9a-f]{48}\n',canary)
expected_digest = hashlib.sha256(canary.rstrip(b'\n')).hexdigest()
for name in ('bearer.header','root-ready.json'):
    try:
        os.stat(name,dir_fd=out_fd,follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError('handoff already exists; do not rerun blindly')
assert not private.exists() and not helper_dir.exists()
# Refuse a wrong installation path; never create a replacement vault/key.
key_stat = (base/'keys/vault.key').lstat()
assert stat.S_ISREG(key_stat.st_mode) and key_stat.st_uid == 0 and stat.S_IMODE(key_stat.st_mode) == 0o600
assert not os.path.lexists(base/('owner-'+hashlib.sha256(owner.encode()).hexdigest()+'.enc'))
store = Store(base)  # THIS operator process defaults to the fake owner, not leo.
with store.transaction(owner):
    devices = json.loads(read_private(base/'devices.json'))
    templates = json.loads(read_private(base/'templates.json'))
    assert not any(d['id'] == device or d['owner'] == owner for d in devices['devices'])
    assert not any(t['id'] == template_id for t in templates['templates'])

private.mkdir(mode=0o700)
atomic(private/'probe.json',json.dumps({'probe_id':probe,'owner':owner}).encode())
helper_parent.mkdir(mode=0o700,exist_ok=True)
st = helper_parent.lstat()
assert stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
helper_dir.mkdir(mode=0o700)
program = ('#!/usr/bin/python3 -I\nimport hashlib,sys\n'
           'value=sys.stdin.buffer.readline().rstrip(b"\\n")\n'
           f'if hashlib.sha256(value).hexdigest() != "{expected_digest}":\n'
           '    print("unexpected-canary"); raise SystemExit(7)\n'
           'sys.stdout.buffer.write(b"accepted:"+value+b"\\n")\n')
fd = os.open(helper,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
with os.fdopen(fd,'w') as f:
    f.write(program); f.flush(); os.fsync(f.fileno())
fixture = {'id':template_id,'handle':handle,'argv':[str(helper)],
           'description':'Disposable canary-only local stdin target; no real hosts',
           'timeout_s':5,'max_output_bytes':4096}
candidate = dict(templates,templates=[*templates['templates'],fixture])
payload = json.dumps(candidate).encode()
assert len(payload) <= 262144
atomic(private/'templates.candidate.json',payload)
load_templates(private/'templates.candidate.json')  # Validate every entry BEFORE provisioning/writing live config.

# No --telegram-owner-id: principals.json / real owner mapping remain untouched.
subprocess.run(['/usr/bin/python3','-I','-B','-c',
 'import sys; sys.path.insert(0,"/opt/lbs-vault/lib"); from lbs_vault.provision import main; main()',
 '--device',device,'--owner',owner,'--days','1','--output',str(private/'device.token')],
 env=env,check=True,stdout=subprocess.DEVNULL)
with store.transaction(owner):
    current = json.loads(read_private(base/'templates.json'))
    assert not any(t['id'] == template_id for t in current['templates'])
    current['templates'].append(fixture)
    atomic(private/'templates.candidate.json',json.dumps(current).encode())
    load_templates(private/'templates.candidate.json')
    atomic(base/'templates.json',read_private(private/'templates.candidate.json'))

bearer = read_private(private/'device.token').strip()
assert re.fullmatch(rb'[A-Za-z0-9_-]{43}',bearer)
header = b'Authorization: Bearer '+bearer+b'\n'
atomic(private/'bearer.header',header)
subprocess.run(['/usr/bin/systemctl','restart','lbs-vault.service'],env=env,check=True)
# Root curl reads a ROOT-owned header, not a leo-replaceable path; -q disables .curlrc.
ready = False
for attempt in range(20):
    result = subprocess.run(['/usr/bin/curl','-q','--silent','--show-error','--max-time','3',
        '--output',str(private/'auth-check.json'),'--write-out','%{http_code}',
        '--header','@'+str(private/'bearer.header'),
        'https://spark-dd6e.tail4b7569.ts.net/lbs-vault/requests/'+'A'*43],
        env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
    if result.returncode == 0 and result.stdout == b'404':
        ready = True; break
    time.sleep(0.25)
assert ready, 'test device not ready; do not print bearer or response bodies'
# Handoff only after readiness. O_EXCL, pinned directory fd, 0600, no value output.
fd = os.open('bearer.header',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=out_fd)
with os.fdopen(fd,'wb') as f:
    os.fchown(f.fileno(),leo.pw_uid,leo.pw_gid)
    f.write(header); f.flush(); os.fsync(f.fileno())
metadata = {'probe_id':probe,'device_id':device,'owner':owner,'handle':handle,
            'template_id':template_id,'helper':str(helper),'private_dir':str(private),
            'authenticated_unknown_request_http':404}
fd = os.open('root-ready.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=out_fd)
with os.fdopen(fd,'w') as f:
    os.fchown(f.fileno(),leo.pw_uid,leo.pw_gid)
    json.dump(metadata,f); f.flush(); os.fsync(f.fileno())
os.close(out_fd)
print('LBS-VAULT-CANARY-FIXTURE-READY: 20261031-200f6a5bf966; authenticated unknown request -> 404')
PY
```

Then tell the builder the setup result. It will use the private header/body files to run the authenticated served-URL matrix and save the fake canary. A subsequent root step will call the installed broker with only this fake owner/template/handle, perform exact-canary-only ciphertext/audit/journal/state.db scans, and revoke/remove only this fixture. **Do not run the failure block after successful handoff or while builder probes are active.**

## Failure cleanup — only if setup failed, before builder save/probes

Do not blindly delete paths. This block requires this setup's private marker, refuses a ready handoff, and guards device/template identity. It removes the template BEFORE its helper, revokes only the test device, and restarts only the HTTP vault service. No message/database cleanup and no unrelated entries are removed. If it refuses, report that and preserve the files for inspection.

```sh
sudo /usr/bin/python3 -I -B - <<'PY'
import hashlib,json,os,pwd,stat,subprocess,sys
from pathlib import Path
assert os.geteuid() == 0
probe = '20261031-200f6a5bf966'
owner = device = 'probe-'+probe
handle = template_id = 'canary.'+probe
base = Path('/root/.hermes/lbs-vault')
private = Path('/root/lbs-vault-live-probe-'+probe)
helper_dir = Path('/opt/lbs-vault/probes')/probe
helper = helper_dir/'fake-stdin-target'
out = Path('/home/leo/lbs-secret-vault/work/live-probe-'+probe)
env = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8',
       'LBS_VAULT_DIR':str(base),'LBS_VAULT_OWNER':owner}
os.environ.clear(); os.environ.update(env)
sys.path.insert(0,'/opt/lbs-vault/lib')
from lbs_vault.store import Store,atomic,read_private
assert (base/'keys/vault.key').is_file()
assert json.loads(read_private(private/'probe.json')) == {'probe_id':probe,'owner':owner}
out_fd = os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
st = os.fstat(out_fd)
leo = pwd.getpwnam('leo')
assert st.st_uid == leo.pw_uid and stat.S_IMODE(st.st_mode) == 0o700
try:
    os.stat('root-ready.json',dir_fd=out_fd,follow_symlinks=False)
except FileNotFoundError:
    pass
else:
    raise RuntimeError('handoff exists: do not run setup-failure cleanup')
store = Store(base)
with store.transaction(owner):
    templates = json.loads(read_private(base/'templates.json'))
    matches = [t for t in templates['templates'] if t['id'] == template_id]
    assert all(t['handle'] == handle and t['argv'] == [str(helper)] for t in matches)
    devices = json.loads(read_private(base/'devices.json'))
    matches_device = [d for d in devices['devices'] if d['id'] == device]
    if matches_device:
        digest = hashlib.sha256(read_private(private/'device.token').strip()).hexdigest()
        assert all(d['owner'] == owner and d['token_sha256'] == digest for d in matches_device)
    templates['templates'] = [t for t in templates['templates'] if t['id'] != template_id]
    atomic(base/'templates.json',json.dumps(templates).encode())
    devices['devices'] = [d for d in devices['devices'] if d['id'] != device]
    atomic(base/'devices.json',json.dumps(devices).encode())
# Remove only owned fixture artifacts; never rm -rf a prefix.
if helper.exists():
    st = helper.lstat(); assert stat.S_ISREG(st.st_mode) and st.st_uid == 0
    helper.unlink()
if helper_dir.exists(): helper_dir.rmdir()
subprocess.run(['/usr/bin/systemctl','restart','lbs-vault.service'],env=env,check=True)
try: os.unlink('bearer.header',dir_fd=out_fd)
except FileNotFoundError: pass
os.close(out_fd)
for name in ('auth-check.json','templates.candidate.json','bearer.header','device.token','probe.json'):
    path = private/name
    if path.exists():
        st = path.lstat(); assert stat.S_ISREG(st.st_mode) and st.st_uid == 0
        path.unlink()
private.rmdir()
print('LBS-VAULT-CANARY-SETUP-ROLLED-BACK: 20261031-200f6a5bf966')
PY
```

## Checks already observed by the builder

| Request | Observed HTTP |
|---|---:|
| Served GET without bearer | 401 |
| Served malformed JSON without bearer | 401 (auth precedes parsing) |
| Served GET with client-supplied Funnel marker, no bearer | 401 (proxy strips client marker) |
| Direct loopback GET with Funnel marker, no bearer | 403 |

This marker check is not actual Funnel traffic and does not close the audit's Funnel deployment caveat. Authenticated malformed/oversized checks await this disposable device. No root setup or failure cleanup has been executed by the builder.
