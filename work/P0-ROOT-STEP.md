# P0 root step — install group/topic support and pair Leo's iPhone + Mac

**For LBS to review and run as root, once. The vault owner does not run it.**

Source commit: `@COMMIT@` (pushed).
Private, git-ignored archive: `/home/leo/lbs-secret-vault/work/live-probe-p0-go-live/release-@SHORT@.tar` (0600 leo, parent 0700).
SHA-256: `@DIGEST@`.

Reproduce as leo before running (fresh bare clone, pinned settings; must print the digest above):

```sh
repro=$(mktemp -d /home/leo/lbs-secret-vault/work/live-probe-p0-go-live/independent.XXXXXX)
git -c core.hooksPath=/dev/null clone --bare --no-hardlinks /home/leo/lbs-secret-vault "$repro/repro.git"
git --git-dir="$repro/repro.git" -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null -c tar.umask=0002 archive --format=tar --output="$repro/release.tar" @COMMIT@ lbs_vault plugin scripts/install.sh scripts/uninstall.sh scripts/pair-device.sh systemd
sha256sum "$repro/release.tar"
```

What it does, in order (same verified-archive pattern as the reviewed kinds update):
1. Reads the archive through one no-follow descriptor, checks digest and git commit comment, extracts exactly the twelve expected files into a fresh `/root/lbs-vault-p0-*` directory. Never runs root code from the leo checkout.
2. Preflight: data tree root-owned 0700/0600, units match the reviewed render, templates parse, gateway/Serve snapshots.
3. `scripts/install.sh --no-serve` from the extracted copy. Only `lbs-vault.service` and `lbs-vault-broker.service` restart. The plugin bytes under `/root/.hermes/plugins/lbs-vault/` update, but **Hermes loads them only at the next gateway `/restart`, which is Leo's**. This step does not restart, stop or signal the gateway.
4. Verify: principals/key/config/templates unchanged, device registry unchanged by install, gateway identity/state unchanged, Serve/Funnel unchanged, installed bytes match, unauthenticated local + served 401.
5. Pair: runs the extracted `scripts/pair-device.sh rubric-iphone` then `rubric-mac`. Each provisions with the installed code, restarts only `lbs-vault.service`, stages the bearer as leo at `/home/leo/.lbs-vault-pair/<device>.token` (0600) and shreds the root copy. The script then checks that `devices.json` gained exactly those two IDs and nothing else changed, both staged files are 0600 leo, no root copy is left, the gateway is unchanged, and unauthenticated requests still get 401.

No token, header or config content is printed. The proof `work/live-probe-p0-go-live/root-p0.json` (0600 leo, metadata only) is created exclusively, so it blocks a blind rerun. If the outcome is failed or uncertain, **do not rerun**: report the error code and stage, and keep the private root log.

After `LBS-VAULT-P0-ROOT-COMPLETE`, as leo: `scripts/deliver-device-token.sh rubric-iphone` (waits for lbm to see the phone) and `scripts/deliver-device-token.sh rubric-mac`.

```sh
/usr/bin/python3 -I -B - <<'PY'
import hashlib, io, json, os, pwd, signal, stat, subprocess, sys, tarfile, tempfile
from pathlib import Path, PurePosixPath

COMMIT = '@COMMIT@'
DIGEST = '@DIGEST@'
HANDOFF = Path('/home/leo/lbs-secret-vault/work/live-probe-p0-go-live')
ARCHIVE = 'release-@SHORT@.tar'
BASE = Path('/root/.hermes/lbs-vault')
PAIR = ('rubric-iphone', 'rubric-mac')
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'HOME':'/root', 'LC_ALL':'C'}
FILES = {
    'lbs_vault/__init__.py', 'lbs_vault/store.py', 'lbs_vault/service.py',
    'lbs_vault/broker.py', 'lbs_vault/provision.py',
    'plugin/__init__.py', 'plugin/plugin.yaml',
    'scripts/install.sh', 'scripts/uninstall.sh', 'scripts/pair-device.sh',
    'systemd/lbs-vault.service', 'systemd/lbs-vault-broker.service',
}
DIRS = {'lbs_vault','plugin','scripts','systemd'}
ERROR_CODES = {
    'root_required','required_file_missing','unsafe_protected_file',
    'unsafe_handoff_directory','unsafe_source_archive','source_changed_or_digest_mismatch',
    'unsafe_archive_member','unexpected_archive_directory','unexpected_archive_file',
    'incomplete_source_archive','archive_size_mismatch','archive_commit_mismatch',
    'unsafe_data_tree','installed_unit_drift_needs_review','protected_metadata_changed',
    'unit_runtime_drift_needs_review','device_already_registered',
    'vault_unit_identity_unchanged','install_interrupted_requires_review',
    'serve_or_funnel_changed','gateway_identity_or_state_changed',
    'installed_code_mismatch','unauthenticated_probe_not_401',
    'pair_registry_unexpected','pair_stage_unsafe','pair_root_copy_left',
}
result = {'status':'failed','stage':'preflight','source_commit':COMMIT}
private = None
handoff_fd = proof_fd = None


def note_interrupt(_signum, _frame):
    result['interrupt_during_mutation'] = True


def metadata(path, required=False):
    try:
        s = path.lstat()
    except FileNotFoundError:
        if required:
            raise RuntimeError('required_file_missing') from None
        return None
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1:
        raise RuntimeError('unsafe_protected_file')
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,
            stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid,s.st_nlink]


def device_ids():
    return [d['id'] for d in json.loads((BASE/'devices.json').read_bytes())['devices']]


def capture(label, args, log):
    result['last_command'] = label
    p = subprocess.run(args, env=ENV, cwd='/', stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=log, timeout=15, check=True)
    return p.stdout


def mutate(label, args, log, cwd='/'):
    """Run a mutating child to completion; signals are recorded, never used to kill it."""
    result['last_command'] = label
    for sig in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT):
        signal.signal(sig,note_interrupt)
    try:
        child = subprocess.Popen(args, env=ENV, cwd=cwd, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=log, start_new_session=True)
        code = child.wait()
    finally:
        for sig in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT):
            signal.signal(sig,interrupted)
    if code != 0:
        raise subprocess.CalledProcessError(code,[label])


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def unauth_401(log):
    for url in ('http://127.0.0.1:938/lbs-vault/requests/x',
                'https://spark-dd6e.tail4b7569.ts.net/lbs-vault/requests/x'):
        label = 'curl_local' if url.startswith('http://127.0.0.1:') else 'curl_served'
        code = capture(label,['/usr/bin/curl','-q','--silent','--show-error','--max-time','10',
                             '--output','/dev/null','--write-out','%{http_code}',url],log)
        if code != b'401':
            raise RuntimeError('unauthenticated_probe_not_401')


try:
    if os.geteuid() != 0:
        raise PermissionError('root_required')
    os.umask(0o077)
    signal.signal(signal.SIGHUP, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    leo = pwd.getpwnam('leo')
    handoff_fd = os.open(HANDOFF, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    ds = os.fstat(handoff_fd)
    if ds.st_uid != leo.pw_uid or stat.S_IMODE(ds.st_mode) != 0o700:
        raise RuntimeError('unsafe_handoff_directory')
    proof_fd = os.open('root-p0.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                       0o600, dir_fd=handoff_fd)
    fd = os.open(ARCHIVE, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=handoff_fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != leo.pw_uid or stat.S_IMODE(before.st_mode) != 0o600
                or not 0 < before.st_size <= 8*1024*1024):
            raise RuntimeError('unsafe_source_archive')
        data = bytearray()
        while len(data) <= before.st_size:
            part = os.read(fd, min(65536, before.st_size+1-len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(fd)
        if (len(data) != before.st_size
                or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
                != (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                or hashlib.sha256(data).hexdigest() != DIGEST):
            raise RuntimeError('source_changed_or_digest_mismatch')
    finally:
        os.close(fd)
    private = Path(tempfile.mkdtemp(prefix='lbs-vault-p0-', dir='/root'))
    private.chmod(0o700)
    source = private/'source'
    source.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tf:
        if tf.pax_headers.get('comment') != COMMIT:
            raise RuntimeError('archive_commit_mismatch')
        members = tf.getmembers()
        seen = set()
        for m in members:
            name = m.name.rstrip('/')
            p = PurePosixPath(name)
            if p.is_absolute() or '..' in p.parts or name in seen:
                raise RuntimeError('unsafe_archive_member')
            seen.add(name)
            if m.isdir():
                if name not in DIRS:
                    raise RuntimeError('unexpected_archive_directory')
            elif not m.isfile() or name not in FILES or not 0 <= m.size <= 1024*1024:
                raise RuntimeError('unexpected_archive_file')
        if {m.name for m in members if m.isfile()} != FILES:
            raise RuntimeError('incomplete_source_archive')
        for name in DIRS:
            (source/name).mkdir(mode=0o700)
        for m in members:
            if not m.isfile():
                continue
            content = tf.extractfile(m).read(m.size+1)
            if len(content) != m.size:
                raise RuntimeError('archive_size_mismatch')
            with (source/m.name).open('xb') as f:
                f.write(content)
            (source/m.name).chmod(0o755 if m.mode & 0o111 else 0o644)
    result['stage'] = 'data_preflight'
    pending = [BASE]
    while pending:
        node = pending.pop()
        info = node.lstat()
        is_dir = stat.S_ISDIR(info.st_mode)
        if (info.st_uid != 0 or (not is_dir and not stat.S_ISREG(info.st_mode))
                or (not is_dir and info.st_nlink != 1)
                or stat.S_IMODE(info.st_mode) != (0o700 if is_dir else 0o600)):
            raise RuntimeError('unsafe_data_tree')
        if is_dir:
            pending.extend(node.iterdir())
    if set(PAIR) & set(device_ids()):
        raise RuntimeError('device_already_registered')
    protected = [BASE/'devices.json', BASE/'templates.json', BASE/'principals.json',
                 BASE/'keys/vault.key', Path('/root/.hermes/config.yaml')]
    required = {'devices.json','templates.json','principals.json','vault.key'}
    before_files = {str(p):metadata(p, p.name in required) for p in protected}
    for name in ('lbs-vault.service','lbs-vault-broker.service'):
        rendered = (source/'systemd'/name).read_bytes()
        for key,value in {b'@PREFIX@':b'/opt/lbs-vault',b'@DIR@':bytes(BASE),
                          b'@PORT@':b'938',b'@OWNER@':b'leo'}.items():
            rendered = rendered.replace(key,value)
        if Path('/etc/systemd/system',name).read_bytes() != rendered:
            raise RuntimeError('installed_unit_drift_needs_review')
    for name in ('devices.json','templates.json'):
        with (private/('before-'+name)).open('xb') as f:
            f.write((BASE/name).read_bytes())
    with (private/'operator.log').open('xb') as log:
        before_serve = json.loads(capture('serve_before',['tailscale','serve','status','--json'],log))
        gateway_args = ['systemctl','show','hermes-gateway.service','--property=MainPID',
                        '--property=ActiveState','--property=InvocationID','--property=LoadState']
        before_gateway = capture('gateway_before',gateway_args,log)
        before_invocations = {}
        for unit in ('lbs-vault.service','lbs-vault-broker.service'):
            raw = capture('unit_preflight:'+unit,[
                'systemctl','show',unit,'--property=FragmentPath',
                '--property=DropInPaths','--property=NeedDaemonReload','--property=InvocationID'],log)
            props = dict(line.split('=',1) for line in raw.decode().splitlines() if '=' in line)
            if (props.get('FragmentPath') != '/etc/systemd/system/'+unit
                    or props.get('DropInPaths') != '' or props.get('NeedDaemonReload') != 'no'
                    or not props.get('InvocationID')):
                raise RuntimeError('unit_runtime_drift_needs_review')
            before_invocations[unit] = props['InvocationID']
        result['stage'] = 'template_preflight'
        result['last_command'] = 'template_preflight'
        subprocess.run(['/usr/bin/python3','-I','-B','-c',
                        'import sys; sys.path.insert(0,sys.argv[1]); '
                        'from lbs_vault.broker import main; raise SystemExit(main(["check"]))',
                        str(source)],
                       env=dict(ENV,LBS_VAULT_DIR=str(BASE),LBS_VAULT_TEMPLATES=str(BASE/'templates.json')),
                       cwd='/',stdin=subprocess.DEVNULL,stdout=log,stderr=log,timeout=15,check=True)
        result['stage'] = 'install'
        mutate('installer',['/bin/bash','--noprofile','--norc',str(source/'scripts/install.sh'),'--no-serve'],
               log,cwd=str(source))
        result['stage'] = 'verify_install'
        if {str(p):metadata(p, p.name in required) for p in protected} != before_files:
            raise RuntimeError('protected_metadata_changed')
        if json.loads(capture('serve_after',['tailscale','serve','status','--json'],log)) != before_serve:
            raise RuntimeError('serve_or_funnel_changed')
        if capture('gateway_after',gateway_args,log) != before_gateway:
            raise RuntimeError('gateway_identity_or_state_changed')
        for rel in FILES:
            if rel.startswith('lbs_vault/'):
                installed = Path('/opt/lbs-vault/lib')/rel
            elif rel.startswith('plugin/'):
                installed = Path('/root/.hermes/plugins/lbs-vault')/Path(rel).name
            else:
                continue
            if installed.read_bytes() != (source/rel).read_bytes():
                raise RuntimeError('installed_code_mismatch')
        for unit in ('lbs-vault.service','lbs-vault-broker.service'):
            result['last_command'] = 'unit_active:'+unit
            subprocess.run(['systemctl','is-active','--quiet',unit],env=ENV,cwd='/',
                           stdin=subprocess.DEVNULL,stdout=log,stderr=log,timeout=10,check=True)
            invocation = capture('unit_identity:'+unit,[
                'systemctl','show',unit,'--property=InvocationID','--value'],log).decode().strip()
            if not invocation or invocation == before_invocations[unit]:
                raise RuntimeError('vault_unit_identity_unchanged')
        unauth_401(log)
        result['installed'] = True
        result['stage'] = 'pair'
        ids_before = device_ids()
        for device in PAIR:
            mutate('pair:'+device,['/bin/bash','--noprofile','--norc',str(source/'scripts/pair-device.sh'),device],log)
        result['stage'] = 'verify_pair'
        if device_ids() != ids_before+list(PAIR):
            raise RuntimeError('pair_registry_unexpected')
        if {str(p):metadata(p, p.name in required) for p in protected if p.name != 'devices.json'} != \
                {k:v for k,v in before_files.items() if not k.endswith('/devices.json')}:
            raise RuntimeError('protected_metadata_changed')
        stage_dir = Path(leo.pw_dir)/'.lbs-vault-pair'
        sd = stage_dir.lstat()
        if not stat.S_ISDIR(sd.st_mode) or sd.st_uid != leo.pw_uid or stat.S_IMODE(sd.st_mode) != 0o700:
            raise RuntimeError('pair_stage_unsafe')
        for device in PAIR:
            st = (stage_dir/(device+'.token')).lstat()
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != leo.pw_uid or st.st_nlink != 1
                    or stat.S_IMODE(st.st_mode) != 0o600 or not 24 <= st.st_size <= 256):
                raise RuntimeError('pair_stage_unsafe')
        if any(Path('/root/private/lbs-vault-pair').iterdir()):
            raise RuntimeError('pair_root_copy_left')
        if capture('gateway_after_pair',gateway_args,log) != before_gateway:
            raise RuntimeError('gateway_identity_or_state_changed')
        if json.loads(capture('serve_after_pair',['tailscale','serve','status','--json'],log)) != before_serve:
            raise RuntimeError('serve_or_funnel_changed')
        unauth_401(log)
    result.update(status='uncertain' if result.get('interrupt_during_mutation') else 'passed',
                  stage='complete',paired=list(PAIR),tokens_staged_for_leo=True,
                  unauthenticated_local=401,unauthenticated_served=401,
                  protected_metadata_unchanged_except_device_registry=True,
                  gateway_unchanged=True,serve_funnel_unchanged=True,installed_code_matches=True,
                  gateway_restart_needed_for_plugin=True,plugin_enable_attempted=False,
                  request_creation_attempted=False)
    if result.get('interrupt_during_mutation'):
        result['error_code'] = 'install_interrupted_requires_review'
except BaseException as exc:
    result['error_class'] = type(exc).__name__
    if isinstance(exc,(RuntimeError,PermissionError)) and exc.args and exc.args[0] in ERROR_CODES:
        result['error_code'] = exc.args[0]
    elif isinstance(exc,subprocess.CalledProcessError):
        result['error_code'] = 'command_failed'
        result['command_exit'] = exc.returncode
    elif isinstance(exc,subprocess.TimeoutExpired):
        result['error_code'] = 'command_timeout'
    elif isinstance(exc,KeyboardInterrupt):
        result['error_code'] = 'interrupted'
        result['status'] = 'uncertain'
    else:
        result['error_code'] = 'unexpected_error'
    if result['stage'] not in ('preflight','data_preflight','template_preflight'):
        result['outcome'] = 'uncertain'
finally:
    for sig in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT):
        signal.signal(sig,signal.SIG_IGN)
    if private is not None:
        result['root_log_directory'] = str(private)
    payload = (json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
    if private is not None:
        with (private/'root-p0.json').open('xb') as f:
            f.write(payload)
    if proof_fd is not None:
        with os.fdopen(proof_fd,'wb') as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
            os.fchown(f.fileno(),leo.pw_uid,leo.pw_gid)
    if handoff_fd is not None:
        os.close(handoff_fd)
    print(json.dumps(result,sort_keys=True))
if result['status'] != 'passed':
    sys.exit(1)
print('LBS-VAULT-P0-ROOT-COMPLETE')
PY
```
