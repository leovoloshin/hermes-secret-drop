# Next root step: broker proof, exact-canary scans, scoped revocation

Setup completed by LBS. **Do not rerun setup or its old failure-cleanup block.** Builder completed the authenticated served-URL matrix and saved the fake canary successfully. Probe: `20261031-200f6a5bf966`.

Run the single block below as root after review. It:

1. Uses only the installed broker socket with the isolated fake owner/template/handle (no gateway tool/plugin activation).
2. Verifies the helper exit/output without printing a secret-bearing reply.
3. Immediately revokes only this test template/device, restarts only `lbs-vault.service`, and verifies the old bearer now gets 401, so a later scan failure does not leave a live credential.
4. Greps only the exact canary via a protected pattern file in the fake ciphertext, audit, **all exported journal fields** since setup, and required state.db plus optional WAL/SHM. No matching lines/message contents are displayed. Only after successful scans does it remove fake ciphertext/helper/private credentials; real owners, key, principals, gateway and Serve/Funnel remain untouched.

Failures stop before further cleanup and produce a sanitized metadata-only failure report. If execution outcome is uncertain, inspect that report; do not blindly rerun. The original private canary and status-only evidence remain in the ignored leo probe directory for LBS verification. No real owner device is provisioned.

```sh
sudo /usr/bin/python3 -I -B - <<'PY'
import hashlib,json,os,pwd,re,stat,subprocess,sys,time
from pathlib import Path
from datetime import datetime,timezone
assert os.geteuid() == 0
probe = '20261031-200f6a5bf966'
owner = device = 'probe-'+probe
handle = template_id = 'canary.'+probe
base = Path('/root/.hermes/lbs-vault')
private = Path('/root/lbs-vault-live-probe-'+probe)
helper_parent = Path('/opt/lbs-vault/probes')
helper_dir = helper_parent/probe
helper = helper_dir/'fake-stdin-target'
out = Path('/home/leo/lbs-secret-vault/work/live-probe-'+probe)
env = {'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'HOME':'/root','LANG':'C.UTF-8','LBS_VAULT_DIR':str(base),'LBS_VAULT_OWNER':owner}
os.environ.clear(); os.environ.update(env)
sys.path.insert(0,'/opt/lbs-vault/lib')
from lbs_vault.store import Store,atomic,read_private
from lbs_vault.broker import request_use
leo = pwd.getpwnam('leo')
out_fd = os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
st = os.fstat(out_fd)
assert st.st_uid == leo.pw_uid and stat.S_IMODE(st.st_mode) == 0o700
try:
    os.stat('root-proof.json',dir_fd=out_fd,follow_symlinks=False)
except FileNotFoundError:
    pass
else:
    raise RuntimeError('root proof already exists; do not rerun blindly')
fd = os.open('canary.txt',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=out_fd)
with os.fdopen(fd,'rb') as f:
    st = os.fstat(f.fileno())
    assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == leo.pw_uid and stat.S_IMODE(st.st_mode) == 0o600
    pattern = f.read(128)
assert re.fullmatch(rb'CANARY-[0-9a-f]{48}\n',pattern)
canary = pattern.rstrip(b'\n')
expected_digest = hashlib.sha256(canary).hexdigest()
marker = private/'probe.json'
assert json.loads(read_private(marker)) == {'probe_id':probe,'owner':owner}
# This root-owned marker predates ALL live saves; do not derive the journal start
# from a directory timestamp that creating the scan file would change.
journal_since = '@'+str(int(marker.stat().st_mtime)-2)
st = helper.lstat()
assert stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700 and st.st_nlink == 1
fd = os.open(helper,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as f: helper_source = f.read(4096)
match = re.search(rb'hexdigest\(\) != "([0-9a-f]{64})"',helper_source)
assert match and match.group(1).decode('ascii') == expected_digest
bearer = read_private(private/'device.token').strip()
assert re.fullmatch(rb'[A-Za-z0-9_-]{43}',bearer)
assert read_private(private/'bearer.header') == b'Authorization: Bearer '+bearer+b'\n'
assert (base/'keys/vault.key').is_file()
store = Store(base)  # Only the fake owner's document is opened in this process.
ciphertext = store.path_for(owner)
assert ciphertext.is_file(), 'fake canary save is required before this step'
fixture = {'id':template_id,'handle':handle,'argv':[str(helper)],
           'description':'Disposable canary-only local stdin target; no real hosts',
           'timeout_s':5,'max_output_bytes':4096}

def verify_fixture(templates,devices):
    assert [t for t in templates['templates'] if t['id'] == template_id] == [fixture]
    matches = [d for d in devices['devices'] if d['id'] == device]
    assert len(matches) == 1 and matches[0]['owner'] == owner
    assert matches[0]['token_sha256'] == hashlib.sha256(bearer).hexdigest()

report = {'probe_id':probe,'status':'running','scans':{},'cleanup':{},
          'started_at':datetime.now(timezone.utc).isoformat()}
phase = 'fixture_identity'
try:
    with store.transaction(owner):
        verify_fixture(json.loads(read_private(base/'templates.json')),
                       json.loads(read_private(base/'devices.json')))
    phase = 'broker_use'
    used = request_use(owner,template_id,handle)
    # NEVER print raw broker output on a mismatch.
    assert canary not in json.dumps(used).encode() and bearer not in json.dumps(used).encode()
    assert type(used.get('exit_code')) is int and used['exit_code'] == 0
    assert used.get('timed_out') is False and used.get('output') == 'accepted:[REDACTED]\n'
    report['broker'] = {'exit_code':0,'timed_out':False,'output':'accepted:[REDACTED]\n'}
    phase = 'scoped_revoke'
    with store.transaction(owner):
        templates = json.loads(read_private(base/'templates.json'))
        devices = json.loads(read_private(base/'devices.json'))
        verify_fixture(templates,devices)
        templates['templates'] = [t for t in templates['templates'] if t['id'] != template_id]
        devices['devices'] = [d for d in devices['devices'] if d['id'] != device]
        # Template removed before helper; unrelated entries are preserved.
        phase = 'remove_test_template'
        atomic(base/'templates.json',json.dumps(templates).encode())
        report['cleanup']['test_template_removed'] = True
        phase = 'remove_test_device'
        atomic(base/'devices.json',json.dumps(devices).encode())
        report['cleanup']['test_device_removed'] = True
    # Revoke the loaded device immediately, before deleting helper/private files.
    phase = 'reload_device_registry'
    subprocess.run(['/usr/bin/systemctl','restart','lbs-vault.service'],env=env,check=True)
    report['cleanup']['http_service_restarted'] = True
    phase = 'verify_revoked_bearer'
    revoked = False
    for attempt in range(20):
        result = subprocess.run(['/usr/bin/curl','-q','--silent','--show-error','--max-time','3',
            '--output',str(private/'revoke-check.json'),'--write-out','%{http_code}',
            '--header','@'+str(private/'bearer.header'),
            'https://spark-dd6e.tail4b7569.ts.net/lbs-vault/requests/x'],
            env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        if result.returncode == 0 and result.stdout == b'401':
            revoked = True; break
        time.sleep(0.25)
    assert revoked, 'revocation not observed; preserve fixture and investigate'
    subprocess.run(['/usr/bin/systemctl','is-active','--quiet','lbs-vault.service'],env=env,check=True)
    report['cleanup']['revoked_bearer_http'] = 401

    phase = 'exact_canary_scans'
    # Root-owned immutable-to-leo copy: grep cannot be redirected by a swapped
    # leo-owned pattern file. Pattern bytes never enter argv or environment.
    pattern_file = private/'canary.pattern'
    assert not os.path.lexists(pattern_file)
    atomic(pattern_file,pattern)
    def scan(label,path,required=False):
        global phase
        phase = 'scan:'+label
        if not path.exists():
            report['scans'][label] = 'file_not_present'
            assert not required, 'required scan file missing'
            return
        result = subprocess.run(['/usr/bin/grep','-F','-q','-f',str(pattern_file),'--',str(path)],
            env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=120)
        if result.returncode == 0: raise RuntimeError('canary_detected_'+label)
        if result.returncode != 1: raise RuntimeError('scan_failed_'+label)
        report['scans'][label] = 'canary_absent_raw_bytes'
    scan('fake_owner_ciphertext',ciphertext,True)
    scan('audit_current',base/'audit.jsonl',True)
    scan('audit_previous',base/'audit.previous.jsonl')
    scan('state.db',Path('/root/.hermes/state.db'),True)
    for name in ('state.db-wal','state.db-shm'):
        scan(name,Path('/root/.hermes')/name)
    report['scan_method'] = 'exact fixed-pattern raw bytes; no SQL row reconstruction'
    phase = 'scan:journal_since_setup'
    journal = subprocess.Popen(['/usr/bin/journalctl','--since',journal_since,'--output=export','--no-pager'],
        env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    try:
        grep = subprocess.run(['/usr/bin/grep','-F','-q','-f',str(pattern_file)],
            stdin=journal.stdout,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env,timeout=120)
        journal.stdout.close()
        journal.wait(timeout=20)
        if grep.returncode == 0: raise RuntimeError('canary_detected_journal')
        if grep.returncode != 1 or journal.returncode != 0: raise RuntimeError('journal_scan_failed')
        report['scans']['journal_since_setup'] = 'canary_absent_export_bytes_all_fields'
    finally:
        if journal.poll() is None:
            journal.kill(); journal.wait()

    phase = 'remove_fake_namespace'
    with store.transaction(owner) as data:
        assert set(data['items']) == {owner+':'+handle}
        assert all(item['owner'] == owner and item['handle'] == handle for item in data['items'].values())
        assert not data['requests'], 'unexpected fixture records; preserve for review'
        ciphertext.unlink()  # Exact isolated owner hash path only; never a glob.
    report['cleanup']['fake_owner_ciphertext_removed'] = True
    phase = 'remove_helper'
    helper.unlink(); report['cleanup']['helper_removed'] = True
    helper_dir.rmdir(); report['cleanup']['helper_directory_removed'] = True
    if not any(helper_parent.iterdir()): helper_parent.rmdir()
    phase = 'remove_leo_bearer_handoff'
    try: os.unlink('bearer.header',dir_fd=out_fd)
    except FileNotFoundError: pass
    report['cleanup']['leo_bearer_handoff_removed'] = True
    # Only known root-private fixture files; never recursive prefix deletion.
    allowed = {'auth-check.json','templates.candidate.json','bearer.header','device.token',
               'probe.json','canary.pattern','revoke-check.json'}
    assert {p.name for p in private.iterdir()} <= allowed, 'unexpected private files; preserve for review'
    for name in allowed:
        phase = 'remove_private:'+name
        path = private/name
        if path.exists():
            st = path.lstat()
            assert stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
            path.unlink()
    phase = 'remove_private_directory'
    private.rmdir()
    report['cleanup']['private_credentials_removed'] = True
    assert store.key.is_file() and not ciphertext.exists()
    report['cleanup']['vault_key_retained'] = True
    report['probe_scope'] = 'no gateway/plugin/principal/Serve modification by this block'
    report['status'] = 'passed'
except Exception as error:
    # No raw exception/reply/matching lines: only a fixed phase and class.
    report.update(status='failed',failed_phase=phase,error_class=type(error).__name__)
report['completed_at'] = datetime.now(timezone.utc).isoformat()
encoded = json.dumps(report,indent=2).encode()
assert canary not in encoded and bearer not in encoded
fd = os.open('root-proof.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=out_fd)
with os.fdopen(fd,'wb') as f:
    os.fchown(f.fileno(),leo.pw_uid,leo.pw_gid)
    f.write(encoded+b'\n'); f.flush(); os.fsync(f.fileno())
os.close(out_fd)
print(encoded.decode())  # Sanitized status/metadata only.
if report['status'] != 'passed': raise SystemExit(1)
print('LBS-VAULT-CANARY-ROOT-PROBE-COMPLETE: 20261031-200f6a5bf966')
PY
```

Return the safe result (or point the builder at `work/live-probe-20261031-200f6a5bf966/root-proof.json`). Do not print the original canary, bearer/header files, matching journal/DB lines, or raw failed broker output. On any failure, preserve remaining fixtures/evidence and report the sanitized failed phase; do not enable the plugin or restart the gateway to troubleshoot.

`file_not_present` is permitted only for optional audit archives/WAL/SHM; primary state.db must exist. Results explicitly describe exact raw-byte grep, not reconstructed SQLite rows or detection of encoded/compressed values. Journal export covers all fields and is filtered directly into quiet grep. No state DB/WAL/SHM or journal is modified. The original private canary/client metadata remain intentional ignored test evidence. This is a finite canary check, not a blanket absence guarantee for every representation.
