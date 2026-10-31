#!/usr/bin/env bash
# LBS vault installer (Spark host). Root only, idempotent, prints every change.
#
# Installs:
#   @PREFIX@/lib/lbs_vault/              package code (root:root, 0755/0644)
#   /root/.hermes/plugins/lbs-vault/     Hermes plugin, STAGED ONLY (not enabled)
#   /etc/systemd/system/lbs-vault.service, lbs-vault-broker.service
#   @DIR@/ (0700) with devices.json + templates.json seeds (0600, never overwritten)
#   tailscale serve path /lbs-vault -> http://127.0.0.1:@PORT@ (other paths untouched)
#
# Never touches hermes-gateway.service, Hermes config.yaml, plugins.enabled or
# tailscale funnel. Existing files that change are backed up first.
#
# Usage: sudo scripts/install.sh [--dry-run] [--no-start] [--no-serve]
# Overrides (env): LBS_VAULT_PREFIX LBS_VAULT_DIR LBS_VAULT_PORT LBS_VAULT_OWNER
#                  LBS_VAULT_PLUGIN_DIR LBS_VAULT_BACKUP_ROOT LBS_VAULT_UNIT_DIR
set -euo pipefail
umask 077
export LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

DRY_RUN=0 START=1 SERVE=1
for arg in "$@"; do
	case "$arg" in
		--dry-run) DRY_RUN=1 ;;
		--no-start) START=0 ;;
		--no-serve) SERVE=0 ;;
		-h|--help) sed -n '2,20p' "$0"; exit 0 ;;
		*) echo "unknown option: $arg" >&2; exit 2 ;;
	esac
done

PREFIX=${LBS_VAULT_PREFIX:-/opt/lbs-vault}
DIR=${LBS_VAULT_DIR:-/root/.hermes/lbs-vault}
PORT=${LBS_VAULT_PORT:-938}
OWNER=${LBS_VAULT_OWNER:-leo}
PLUGIN_DIR=${LBS_VAULT_PLUGIN_DIR:-/root/.hermes/plugins/lbs-vault}
BACKUP_ROOT=${LBS_VAULT_BACKUP_ROOT:-/root/.hermes/lbs-vault-backups}
UNIT_DIR=${LBS_VAULT_UNIT_DIR:-/etc/systemd/system}
HOST=spark-dd6e.tail4b7569.ts.net   # must match lbs_vault.service.HOST
SERVE_PATH=/lbs-vault
PY=/usr/bin/python3
MARKER=.lbs-vault-installed
UNITS=(lbs-vault-broker.service lbs-vault.service)

die() { echo "ERROR: $*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
CHANGES=0
change() { CHANGES=$((CHANGES + 1)); printf 'CHANGE: %s\n' "$*"; }
run() {
	printf '  +'; printf ' %q' "$@"; printf '\n'
	if [[ $DRY_RUN == 0 ]]; then "$@"; fi
}

[[ $EUID -eq 0 ]] || die "must run as root (sudo $0)"
SRC=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

# ---- input validation -------------------------------------------------------
for v in PREFIX DIR PLUGIN_DIR BACKUP_ROOT UNIT_DIR; do
	p=${!v}
	[[ $p =~ ^/[A-Za-z0-9._/-]+$ && $p != *..* && $p != */ ]] || die "$v must be a plain absolute path: $p"
done
[[ $PORT =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT < 1024 )) || die "LBS_VAULT_PORT must be a privileged port (1..1023)"
read -r UNPRIVILEGED_START </proc/sys/net/ipv4/ip_unprivileged_port_start
(( PORT < UNPRIVILEGED_START )) || die "kernel permits non-root binds on port $PORT; restore privileged-port protection first"
[[ $OWNER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "LBS_VAULT_OWNER must be a plain user name"
for t in systemctl tailscale curl ss install sha256sum diff "$PY"; do
	command -v "$t" >/dev/null || die "missing tool: $t"
done

# Every existing component of PATH (and the path itself) must be a real
# directory/file owned by root and not writable by group/other.
assert_root_path() {
	local rest=${1#/} cur="" c uid mode
	while :; do
		[[ -e ${cur:-/} || -L ${cur:-/} ]] || return 0
		[[ ! -L ${cur:-/} ]] || die "refusing symlink in install path: $cur"
		read -r uid mode <<<"$(stat -c '%u %a' -- "${cur:-/}")"
		[[ $uid == 0 ]] || die "not root-owned: ${cur:-/} (uid $uid)"
		(( (8#$mode & 8#022) == 0 )) || die "group/other-writable: ${cur:-/} (mode $mode)"
		[[ -n $rest ]] || return 0
		c=${rest%%/*}
		[[ $rest == */* ]] && rest=${rest#*/} || rest=""
		cur=$cur/$c
	done
}
for p in "$PREFIX" "$DIR" "$PLUGIN_DIR" "$BACKUP_ROOT" "$UNIT_DIR"; do assert_root_path "$p"; done

# ---- source tree checks -----------------------------------------------------
[[ -f $SRC/lbs_vault/service.py && -f $SRC/lbs_vault/store.py && -f $SRC/lbs_vault/broker.py ]] \
	|| die "source tree incomplete: $SRC/lbs_vault"
[[ -f $SRC/plugin/plugin.yaml && -f $SRC/plugin/__init__.py ]] || die "source tree incomplete: $SRC/plugin"
for u in "${UNITS[@]}"; do [[ -f $SRC/systemd/$u ]] || die "missing unit template: $SRC/systemd/$u"; done
for d in lbs_vault plugin systemd; do
	bad=$(find "$SRC/$d" ! -type f ! -type d -print -quit)
	[[ -z $bad ]] || die "refusing non-regular file in source: $bad"
done

say "== LBS vault install (dry-run=$DRY_RUN) =="
say "source:  $SRC"
say "prefix:  $PREFIX   data: $DIR   plugin: $PLUGIN_DIR   port: 127.0.0.1:$PORT   owner: $OWNER"

# ---- preflight ----------------------------------------------------------------
env -i "$PY" -I -c 'from cryptography.fernet import Fernet; Fernet(Fernet.generate_key())' \
	|| die "system python lacks cryptography (no network installs are done; install python3-cryptography)"
listener=$(ss -ltnH "sport = :$PORT" | head -n1 || true)
if [[ -n $listener ]] && ! systemctl is-active --quiet lbs-vault.service; then
	die "port $PORT already in use by another process: $listener"
fi

STAGE=$(mktemp -d /tmp/lbs-vault-install.XXXXXX)
trap 'rm -rf -- "$STAGE"' EXIT
TARGET=http://127.0.0.1:$PORT
serve_check() { # MODE BEFORE_JSON [AFTER_JSON]
	"$PY" -I - "$@" "$HOST" "$SERVE_PATH" "$TARGET" <<'PYEOF'
import json, sys
mode, before_path = sys.argv[1], sys.argv[2]
after_path = sys.argv[3] if mode == "verify" else None
host, path, target = sys.argv[-3:]
hp = host + ":443"
def load(p):
    with open(p) as f:
        return json.load(f)
def handler(cfg):
    h = ((cfg.get("Web") or {}).get(hp) or {}).get("Handlers") or {}
    return {k: v for k, v in h.items() if k.rstrip("/") == path}
def without(cfg):
    cfg = json.loads(json.dumps(cfg))
    h = ((cfg.get("Web") or {}).get(hp) or {}).get("Handlers")
    if h is not None:
        for k in list(h):
            if k.rstrip("/") == path:
                del h[k]
    return cfg
def ours(h):
    if len(h) != 1:
        return False
    (v,) = h.values()
    return (v.get("Proxy") or "").rstrip("/") == target and set(v) == {"Proxy"}
before = load(before_path)
if hp in (before.get("AllowFunnel") or {}) and before["AllowFunnel"][hp]:
    sys.exit(f"funnel is enabled on {hp}; refusing to publish the vault there")
if mode == "plan":
    h = handler(before)
    if not h:
        print("add")
    elif ours(h):
        print("same")
    else:
        sys.exit(f"{path} already served by something else: {json.dumps(h)}")
else:
    after = load(after_path)
    if not ours(handler(after)):
        sys.exit(f"{path} not mapped to {target} after change")
    if without(before) != without(after):
        sys.exit("serve config changed outside " + path + "; compare backup with `tailscale serve status --json`")
    if (after.get("AllowFunnel") or {}) != (before.get("AllowFunnel") or {}):
        sys.exit("funnel settings changed unexpectedly")
    print("verified")
PYEOF
}
# Reject foreign/stale routes before installing code or changing running units,
# including --no-serve: an old unprivileged backend must never be left squattable.
tailscale serve status --json >"$STAGE/serve-preflight.json"
serve_check plan "$STAGE/serve-preflight.json" >/dev/null \
	|| die "foreign or unsafe vault Serve route; review/remove it explicitly before this clean cutover"
BACKUP_DIR=""
backup_dir() {
	if [[ -z $BACKUP_DIR ]]; then
		BACKUP_DIR=$BACKUP_ROOT/install-$(date -u +%Y%m%dT%H%M%SZ)-$$
		if [[ ! -d $BACKUP_ROOT ]]; then run install -d -m 0700 -o root -g root "$BACKUP_ROOT"; fi
		run install -d -m 0700 -o root -g root "$BACKUP_DIR"
	fi
}

# stage_tree SRC DEST: race-safe copy of a (user-owned) source tree into a fresh
# root-private stage. Directories and files are opened fd-relative with
# O_NOFOLLOW, so a symlink swapped in after any check can never make root read
# and republish another file (e.g. a root secret). Symlinks, non-regular files,
# hardlinked files and files that change while being read are refused. Caches
# (__pycache__, *.pyc) are skipped. Result: root:root, dirs 0755, files 0644.
stage_tree() {
	"$PY" -I -B - "$1" "$2" "$MARKER" <<'PYEOF'
import os, stat, sys
src, dst, marker = sys.argv[1:]
NOFOLLOW_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
def die(msg):
    sys.exit(f"ERROR: {msg}")
def copy_dir(sfd, dfd, rel):
    for name in sorted(os.listdir(sfd)):
        path = f"{rel}/{name}"
        if name == "__pycache__" or name.endswith(".pyc"):
            continue
        st = os.stat(name, dir_fd=sfd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            child = os.open(name, NOFOLLOW_DIR, dir_fd=sfd)
            try:
                cst = os.fstat(child)
                if (cst.st_dev, cst.st_ino) != (st.st_dev, st.st_ino):
                    die(f"source changed during copy: {path}")
                os.mkdir(name, 0o700, dir_fd=dfd)
                dchild = os.open(name, NOFOLLOW_DIR, dir_fd=dfd)
                try:
                    copy_dir(child, dchild, path)
                    os.fchmod(dchild, 0o755)
                finally:
                    os.close(dchild)
            finally:
                os.close(child)
        elif stat.S_ISREG(st.st_mode):
            if st.st_nlink != 1:
                die(f"refusing hardlinked source file: {path}")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=sfd)
            try:
                before = os.fstat(fd)
                ident = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_nlink, s.st_mode)
                if not stat.S_ISREG(before.st_mode) or ident(before) != ident(st):
                    die(f"source changed during copy: {path}")
                if before.st_size > 4 * 1024 * 1024:
                    die(f"source file too large: {path}")
                chunks, total = [], 0
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > before.st_size:
                        break
                data = b"".join(chunks)
                if len(data) != before.st_size or ident(os.fstat(fd)) != ident(before):
                    die(f"source changed during copy: {path}")
            finally:
                os.close(fd)
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(out, view):]
                os.fchown(out, 0, 0)
                os.fchmod(out, 0o644)
            finally:
                os.close(out)
        else:
            die(f"refusing symlink or special file in source: {path}")
os.makedirs(dst, mode=0o700)
sfd = os.open(src, NOFOLLOW_DIR)
dfd = os.open(dst, NOFOLLOW_DIR)
try:
    copy_dir(sfd, dfd, src)
    m = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    os.write(m, b"installed by lbs-secret-vault scripts/install.sh\n")
    os.fchown(m, 0, 0)
    os.fchmod(m, 0o644)
    os.close(m)
    os.fchown(dfd, 0, 0)
    os.fchmod(dfd, 0o755)
finally:
    os.close(sfd)
    os.close(dfd)
PYEOF
	chown -R root:root "$2"
}

# Hermes may write __pycache__ when it imports the plugin; that is not drift.
tree_listing() { (cd "$1" && find . -name __pycache__ -prune -o -printf '%P %y %m %u %g\n' | sort); }

# install_tree STAGED DEST LABEL -> sets TREE_CHANGED
install_tree() {
	local staged=$1 dest=$2 label=$3
	TREE_CHANGED=0
	if [[ -d $dest ]]; then
		[[ -f $dest/$MARKER ]] || die "$dest exists but was not installed by this script; refusing to replace"
		if diff -r --no-dereference -x __pycache__ -q "$staged" "$dest" >/dev/null \
			&& [[ "$(tree_listing "$staged")" == "$(tree_listing "$dest")" ]]; then
			say "ok: $label unchanged ($dest)"
			return 0
		fi
		backup_dir
		change "$label updated: $dest (previous copy -> $BACKUP_DIR)"
		diff -r --no-dereference -x __pycache__ -q "$staged" "$dest" | sed 's/^/    /' || true
		run cp -a -- "$staged" "$dest.new.$$"
		run mv -- "$dest" "$BACKUP_DIR/$(basename "$dest")"
		run mv -- "$dest.new.$$" "$dest"
	else
		[[ ! -e $dest && ! -L $dest ]] || die "$dest exists and is not a directory"
		change "$label installed: $dest"
		if [[ ! -d $(dirname "$dest") ]]; then run install -d -m 0755 -o root -g root "$(dirname "$dest")"; fi
		run cp -a -- "$staged" "$dest.new.$$"
		run mv -- "$dest.new.$$" "$dest"
	fi
	TREE_CHANGED=1
}

# ---- 1. package code ----------------------------------------------------------
stage_tree "$SRC/lbs_vault" "$STAGE/lib/lbs_vault"
rm -f -- "$STAGE/lib/lbs_vault/$MARKER"
printf 'installed by lbs-secret-vault scripts/install.sh\n' >"$STAGE/lib/$MARKER"
chmod 0755 "$STAGE/lib"; chown root:root "$STAGE/lib" "$STAGE/lib/$MARKER"; chmod 0644 "$STAGE/lib/$MARKER"
# Import check of the staged root-owned copy only: -I keeps the caller's cwd,
# user site and PYTHON* env off sys.path; no bytecode is written.
if [[ $DRY_RUN == 0 ]]; then
	env -i "$PY" -I -B -c 'import sys; sys.path.insert(0, sys.argv[1]); import lbs_vault.store, lbs_vault.service, lbs_vault.broker' \
		"$STAGE/lib" || die "staged package failed to import"
else
	say "skip: dry-run never imports candidate package code"
fi
assert_root_path "$PREFIX"
if [[ ! -d $PREFIX ]]; then
	change "create $PREFIX"
	run install -d -m 0755 -o root -g root "$PREFIX"
fi
install_tree "$STAGE/lib" "$PREFIX/lib" "package code"
CODE_CHANGED=$TREE_CHANGED
say "package sha256:"
(cd "$STAGE/lib" && find . -type f -name '*.py' -print0 | sort -z | xargs -0 sha256sum | sed 's/^/    /')

# ---- 2. data directory (encrypted store lives here; never overwritten) ----------
if [[ ! -d $DIR ]]; then
	change "create private data dir $DIR (0700 root)"
	run install -d -m 0700 -o root -g root "$DIR"
else
	mode=$(stat -c '%a' -- "$DIR")
	if [[ $mode != 700 ]]; then change "chmod 0700 $DIR (was $mode)"; run chmod 0700 "$DIR"; fi
fi
if [[ -d $DIR ]]; then
	while IFS= read -r -d '' f; do
		[[ ! -L $f ]] || die "refusing symlink in data dir: $f"
		read -r uid mode kind <<<"$(stat -c '%u %a %F' -- "$f")"
		[[ $uid == 0 ]] || die "data dir entry not root-owned: $f"
		want=600; [[ $kind == directory ]] && want=700
		if [[ $mode != "$want" ]]; then change "chmod $want $f (was $mode)"; run chmod "$want" "$f"; fi
	done < <(find "$DIR" -mindepth 1 -print0)
fi
seed() {
	local name=$1 content=$2
	if [[ -e $DIR/$name || -L $DIR/$name ]]; then
		say "ok: $DIR/$name exists (kept)"
		return 0
	fi
	change "seed $DIR/$name = $content (0600 root)"
	printf '%s\n' "$content" >"$STAGE/$name"
	run install -m 0600 -o root -g root "$STAGE/$name" "$DIR/$name"
}
seed devices.json '{"devices":[]}'
seed templates.json '{"templates":[]}'

# ---- 3. Hermes plugin: staged only, never enabled here -------------------------
stage_tree "$SRC/plugin" "$STAGE/plugin"
assert_root_path "$PLUGIN_DIR"
install_tree "$STAGE/plugin" "$PLUGIN_DIR" "Hermes plugin (staged, not enabled)"

# ---- 4. systemd units ------------------------------------------------------------
UNITS_CHANGED=0
stage_tree "$SRC/systemd" "$STAGE/units"
for u in "${UNITS[@]}"; do
	[[ -f $STAGE/units/$u ]] || die "missing unit template: systemd/$u"
	sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@DIR@|$DIR|g" -e "s|@PORT@|$PORT|g" -e "s|@OWNER@|$OWNER|g" \
		"$STAGE/units/$u" >"$STAGE/$u"
	! grep -q '@[A-Z]*@' "$STAGE/$u" || die "unrendered placeholder in $u"
	dest=$UNIT_DIR/$u
	if [[ -f $dest ]] && cmp -s "$STAGE/$u" "$dest"; then
		say "ok: $dest unchanged"
		continue
	fi
	if [[ -e $dest ]]; then
		backup_dir
		change "update $dest (previous -> $BACKUP_DIR/$u)"
		diff -u "$dest" "$STAGE/$u" | sed 's/^/    /' || true
		run cp -a -- "$dest" "$BACKUP_DIR/$u"
	else
		change "install $dest"
	fi
	run install -m 0644 -o root -g root "$STAGE/$u" "$dest"
	UNITS_CHANGED=1
done
if [[ $UNITS_CHANGED == 1 ]]; then run systemctl daemon-reload; fi

# ---- 5. start vault units (only lbs-vault*; never the Hermes gateway) ----------
probe_local() {
	curl -sS -o /dev/null -w '%{http_code}' --max-time 3 \
		-H "Host: 127.0.0.1:$PORT" "http://127.0.0.1:$PORT$SERVE_PATH/requests/$(printf 'A%.0s' {1..43})" 2>/dev/null || true
}
if [[ $START == 1 ]]; then
	for u in "${UNITS[@]}"; do
		if [[ $(systemctl is-enabled "$u" 2>/dev/null || true) != enabled ]]; then
			change "enable $u"; run systemctl enable "$u"
		fi
		if ! systemctl is-active --quiet "$u"; then
			change "start $u"; run systemctl start "$u"
		elif [[ $UNITS_CHANGED == 1 || $CODE_CHANGED == 1 ]]; then
			change "restart $u (code/unit changed)"; run systemctl restart "$u"
		else
			say "ok: $u active"
		fi
	done
	if [[ $DRY_RUN == 0 ]]; then
		code=000
		for _ in $(seq 1 20); do
			code=$(probe_local)
			[[ $code == 401 ]] && break
			sleep 0.5
		done
		[[ $code == 401 ]] || die "local probe expected 401 (unauthenticated), got $code; see: journalctl -u lbs-vault.service"
		say "ok: unauthenticated local probe -> $code"
	fi
else
	say "skip: --no-start (units installed but not enabled/started)"
fi

# ---- 6. tailscale serve /lbs-vault (backup first; other paths untouched) -------
if [[ $SERVE == 1 ]]; then
	dns=$(tailscale status --json | "$PY" -I -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')
	[[ $dns == "$HOST" ]] || die "tailscale DNS name is $dns, expected $HOST"
	tailscale serve status --json >"$STAGE/serve-before.json"
	plan=$(serve_check plan "$STAGE/serve-before.json") || die "tailscale serve preflight failed"
	if [[ $plan == same ]]; then
		say "ok: tailscale serve $SERVE_PATH -> $TARGET already present"
	else
		backup_dir
		change "tailscale serve: add https://$HOST$SERVE_PATH -> $TARGET (backup: $BACKUP_DIR/serve-before.json)"
		run install -m 0600 -o root -g root "$STAGE/serve-before.json" "$BACKUP_DIR/serve-before.json"
		run tailscale serve --bg --https=443 --set-path="$SERVE_PATH" "$TARGET"
		if [[ $DRY_RUN == 0 ]]; then
			tailscale serve status --json >"$STAGE/serve-after.json"
			serve_check verify "$STAGE/serve-before.json" "$STAGE/serve-after.json" \
				|| die "serve verification failed; previous config saved at $BACKUP_DIR/serve-before.json"
			install -m 0600 -o root -g root "$STAGE/serve-after.json" "$BACKUP_DIR/serve-after.json"
			say "ok: only $SERVE_PATH added; all other serve paths and funnel settings unchanged"
		fi
	fi
else
	say "skip: --no-serve"
fi

# ---- summary ---------------------------------------------------------------------
say ""
say "== $CHANGES change(s)$([[ $DRY_RUN == 1 ]] && echo ' planned (dry run: nothing applied)') =="
[[ -z $BACKUP_DIR ]] || say "backups: $BACKUP_DIR"
for old in /root/.hermes/plugins/secret-drop /root/.hermes/plugins/hermes-secret-drop; do
	if [[ -e $old ]]; then
		say "WARNING: legacy plaintext secret-drop plugin present at $old (stores values in .env); disable it when the gateway is next restarted."
	fi
done
say "Legacy cutover gate: before real secrets or plugin activation, supervisor must review old secret-drop-names metadata, remove approved legacy .env entries and terminal.env_passthrough names without printing values, and disable the old plugin at the authorized gateway restart. This installer never reads/migrates old values or changes gateway config."
say "Hermes gateway: NOT touched. The agent plugin is staged at $PLUGIN_DIR but not enabled."
say "Activation owed (Leo): hermes plugins enable lbs-vault, then /restart the gateway."
say "Served URL: https://$HOST$SERVE_PATH/  (expect: curl -s -o /dev/null -w '%{http_code}' https://$HOST$SERVE_PATH/requests/x -> 401)"
say "LBS-VAULT-RESTART-NEEDED"
say "Owner binding gate: provision the first device with --telegram-owner-id <Leo numeric user id>. Until principals.json is configured, every plugin tool refuses. Gateway's general allowlist is not vault authorization."
