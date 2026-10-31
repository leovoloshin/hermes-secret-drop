# Next root step — install the on-demand kind cutover only

**For LBS to review and run as root. The builder does not run this block.**

Source commit: `88e6a783887b8d3d22c4aabd61bb408dc0a63551` (pushed).
Private, git-ignored source archive: `/home/leo/lbs-secret-vault/work/live-probe-kind-update/release-88e6a78.tar` (0600 leo, parent 0700).
SHA-256: `d9eda685359d5ec5bc3ce42d25628d63ab147459ee8c56f48c8f6208bb0da61d`.

This is a new step, **not** the completed/revoked `20261031-200f6a5bf966` probe. Its historical broker/scan/revoke block is preserved in git at `eb005c9:work/ROOT-STEPS.md`; never rerun that fixture.

Reproduction recipe (run **as leo**, never root, using a new bare clone with no `info/attributes`; do not overwrite the handed-off archive):

```sh
repro=$(mktemp -d /home/leo/lbs-secret-vault/work/live-probe-kind-update/independent.XXXXXX)
git -c core.hooksPath=/dev/null clone --bare --no-hardlinks /home/leo/lbs-secret-vault "$repro/repro.git"
git --git-dir="$repro/repro.git" -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null -c tar.umask=0002 archive --format=tar --output="$repro/release.tar" 88e6a783887b8d3d22c4aabd61bb408dc0a63551 lbs_vault plugin scripts/install.sh scripts/uninstall.sh systemd
chmod 0600 "$repro/release.tar"
sha256sum "$repro/release.tar"
```

The digest must match above. Parent independently reproduced that digest with the fresh-bare-clone/pinned-settings recipe, and `git get-tar-commit-id` reported the exact pinned commit. The block also checks the tar's git PAX commit comment, not just a decorative commit label.

Scope:
- Copy and verify the immutable source through one no-follow descriptor, then extract only the eleven expected regular files into a fresh private root directory. Never run root Python/shell from the evolving leo checkout.
- Refuse unit drift or an installed template without an explicit kind. Do not infer a kind or edit target configuration automatically.
- Back up the existing device/template registries privately; install using the reviewed installer with `--no-serve`. Only `lbs-vault.service` / `lbs-vault-broker.service` may restart. Plugin files are staged, **not enabled**.
- Require unchanged device/template/principal/key/config metadata, unchanged gateway unit identity/state, unchanged full Serve/Funnel configuration, matching installed package/plugin bytes, both vault units active, and unauthenticated local/served HTTP 401.
- **No fake or real device is provisioned, no request is issued, no credential is read/exported from Keychain, no chat/state.db is read, no broker target is executed.** Typed native fixtures come in a separate reviewed step after native audits/device readiness; avoid creating ten-minute requests while a build or device is unavailable.
- Never enable the plugin, restart the gateway, change principals, or change Serve/Funnel. Installer activation advice is captured in a private root log and is **not authorization to follow it**.

Run once after review, preferably in a persistent root tmux/screen session. The installer is not killed by an outer timer; interruption is an **uncertain** outcome requiring inspection, never an automatic retry.

```sh
/usr/bin/python3 -I -B - <<'PY'
import hashlib, io, json, os, pwd, signal, stat, subprocess, sys, tarfile, tempfile
from pathlib import Path, PurePosixPath

COMMIT = '88e6a783887b8d3d22c4aabd61bb408dc0a63551'
DIGEST = 'd9eda685359d5ec5bc3ce42d25628d63ab147459ee8c56f48c8f6208bb0da61d'
HANDOFF = Path('/home/leo/lbs-secret-vault/work/live-probe-kind-update')
ARCHIVE = 'release-88e6a78.tar'
BASE = Path('/root/.hermes/lbs-vault')
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'HOME':'/root', 'LC_ALL':'C'}
FILES = {
    'lbs_vault/__init__.py', 'lbs_vault/store.py', 'lbs_vault/service.py',
    'lbs_vault/broker.py', 'lbs_vault/provision.py',
    'plugin/__init__.py', 'plugin/plugin.yaml',
    'scripts/install.sh', 'scripts/uninstall.sh',
    'systemd/lbs-vault.service', 'systemd/lbs-vault-broker.service',
}
DIRS = {'lbs_vault','plugin','scripts','systemd'}
ERROR_CODES = {
    'root_required','required_file_missing','unsafe_protected_file',
    'unsafe_handoff_directory','unsafe_source_archive','source_changed_or_digest_mismatch',
    'unsafe_archive_member','unexpected_archive_directory','unexpected_archive_file',
    'incomplete_source_archive','archive_size_mismatch','archive_commit_mismatch',
    'unsafe_data_tree','installed_unit_drift_needs_review','protected_metadata_changed',
    'unit_runtime_drift_needs_review',
    'vault_unit_identity_unchanged','install_interrupted_requires_review',
    'serve_or_funnel_changed','gateway_identity_or_state_changed',
    'installed_code_mismatch','unauthenticated_probe_not_401',
}
result = {'status':'failed','stage':'preflight','source_commit':COMMIT}
private = None
handoff_fd = proof_fd = None


def note_install_interrupt(_signum, _frame):
    result['interrupt_during_install'] = True


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


def capture(label, args, log):
    result['last_command'] = label
    p = subprocess.run(args, env=ENV, cwd='/', stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=log, timeout=15, check=True)
    return p.stdout


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


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
    # Exclusive proof leaf also prevents an automatic rerun after a partial result.
    proof_fd = os.open('root-update.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
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
    private = Path(tempfile.mkdtemp(prefix='lbs-vault-kinds-88e6a78-', dir='/root'))
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
    protected = [BASE/'devices.json', BASE/'templates.json', BASE/'principals.json',
                 BASE/'keys/vault.key', Path('/root/.hermes/config.yaml')]
    before_files = {str(p):metadata(p, p.name in {'devices.json','templates.json','vault.key'})
                    for p in protected}
    # Refuse unreviewed unit changes instead of overwriting operator customizations.
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
        # Only parse root-reviewed config; never resolve a stored credential or execute a target.
        result['last_command'] = 'template_preflight'
        subprocess.run(['/usr/bin/python3','-I','-B','-c',
                        'import sys; sys.path.insert(0,sys.argv[1]); '
                        'from lbs_vault.broker import main; raise SystemExit(main(["check"]))',
                        str(source)],
                       env=dict(ENV,LBS_VAULT_DIR=str(BASE),LBS_VAULT_TEMPLATES=str(BASE/'templates.json')),
                       cwd='/',stdin=subprocess.DEVNULL,stdout=log,stderr=log,timeout=15,check=True)
        result['stage'] = 'install'
        result['last_command'] = 'installer'
        for sig in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT):
            signal.signal(sig,note_install_interrupt)
        try:
            installer = subprocess.Popen(
                ['/bin/bash','--noprofile','--norc',str(source/'scripts/install.sh'),'--no-serve'],
                env=ENV,cwd=str(source),stdin=subprocess.DEVNULL,stdout=log,stderr=log,
                start_new_session=True)
            installer_exit = installer.wait()
        finally:
            for sig in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT):
                signal.signal(sig,interrupted)
        if installer_exit != 0:
            raise subprocess.CalledProcessError(installer_exit,['installer'])
        result['stage'] = 'verify'
        if {str(p):metadata(p, p.name in {'devices.json','templates.json','vault.key'})
                for p in protected} != before_files:
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
        statuses = []
        for url in ('http://127.0.0.1:938/lbs-vault/requests/x',
                    'https://spark-dd6e.tail4b7569.ts.net/lbs-vault/requests/x'):
            label = 'curl_local' if url.startswith('http://127.0.0.1:') else 'curl_served'
            code = capture(label,['/usr/bin/curl','-q','--silent','--show-error','--max-time','10',
                                 '--output','/dev/null','--write-out','%{http_code}',url],log)
            if code != b'401':
                raise RuntimeError('unauthenticated_probe_not_401')
            statuses.append(401)
    result.update(status='uncertain' if result.get('interrupt_during_install') else 'passed',
                  stage='complete',unauthenticated_local=statuses[0],vault_units_restarted=True,
                  unauthenticated_served=statuses[1],protected_metadata_unchanged=True,
                  gateway_unchanged=True,serve_funnel_unchanged=True,installed_code_matches=True,
                  device_provision_attempted=False,request_creation_attempted=False,plugin_enable_attempted=False)
    if result.get('interrupt_during_install'):
        result['error_code'] = 'install_interrupted_requires_review'
        result['outcome'] = 'uncertain'
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
    if result['stage'] in ('install','verify'):
        result['outcome'] = 'uncertain'
finally:
    for sig in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT):
        signal.signal(sig,signal.SIG_IGN)
    if private is not None:
        result['root_log_directory'] = str(private)
    payload = (json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
    if private is not None:
        with (private/'root-update.json').open('xb') as f:
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
print('LBS-VAULT-KINDS-ROOT-UPDATE-COMPLETE')
PY
```

On success, report the signal and metadata-only `work/live-probe-kind-update/root-update.json` (0600 leo). Do not paste private logs, config, headers or any credential values. No bearer/canary is created by this block.

If it fails or the install outcome is uncertain: **do not rerun, roll back registries, retry a broker use or touch the gateway/Serve.** Keep the private root log and report only the metadata proof (fixed error code, stage, command label/exit, error class). A SIGHUP/SIGTERM is recorded as interrupted; SIGKILL/power loss cannot be caught. The exclusive handoff proof intentionally blocks blind repetition, including an empty/unfinished proof. Registry backups are inventory/recovery material, not permission to resurrect old bearer digests.

Next after this update: fresh, separately reviewed fake-owner native test fixtures when the signed clients/devices and audit gates are ready. Native authenticated save/cancel, OS focus/keyboard and owner-preserving install remain unproved; no global done signal.
