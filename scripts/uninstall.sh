#!/usr/bin/env bash
# LBS vault uninstaller. Root only, idempotent, prints every change.
#
# Removes the vault units, the tailscale serve path /lbs-vault (backing up the
# serve config first; other paths untouched), the installed package and the
# staged Hermes plugin. The encrypted store and key in the data dir are KEPT
# unless --purge-data is given (that destroys every saved secret).
# Never touches hermes-gateway.service, Hermes config.yaml or plugins.enabled.
#
# Usage: sudo scripts/uninstall.sh [--dry-run] [--purge-data]
# Overrides (env): same as install.sh.
set -euo pipefail
umask 077
export LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

DRY_RUN=0 PURGE=0
for arg in "$@"; do
	case "$arg" in
		--dry-run) DRY_RUN=1 ;;
		--purge-data) PURGE=1 ;;
		-h|--help) sed -n '2,11p' "$0"; exit 0 ;;
		*) echo "unknown option: $arg" >&2; exit 2 ;;
	esac
done

PREFIX=${LBS_VAULT_PREFIX:-/opt/lbs-vault}
DIR=${LBS_VAULT_DIR:-/root/.hermes/lbs-vault}
PORT=${LBS_VAULT_PORT:-8738}
PLUGIN_DIR=${LBS_VAULT_PLUGIN_DIR:-/root/.hermes/plugins/lbs-vault}
BACKUP_ROOT=${LBS_VAULT_BACKUP_ROOT:-/root/.hermes/lbs-vault-backups}
UNIT_DIR=${LBS_VAULT_UNIT_DIR:-/etc/systemd/system}
HOST=spark-dd6e.tail4b7569.ts.net
SERVE_PATH=/lbs-vault
PY=/usr/bin/python3
MARKER=.lbs-vault-installed
UNITS=(lbs-vault.service lbs-vault-broker.service)

die() { echo "ERROR: $*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
CHANGES=0
change() { CHANGES=$((CHANGES + 1)); printf 'CHANGE: %s\n' "$*"; }
run() {
	printf '  +'; printf ' %q' "$@"; printf '\n'
	if [[ $DRY_RUN == 0 ]]; then "$@"; fi
}

[[ $EUID -eq 0 ]] || die "must run as root (sudo $0)"
for v in PREFIX DIR PLUGIN_DIR BACKUP_ROOT UNIT_DIR; do
	p=${!v}
	[[ $p =~ ^/[A-Za-z0-9._/-]+$ && $p != *..* && $p != */ && $p != / ]] || die "$v must be a plain absolute path: $p"
done
[[ $PORT =~ ^[0-9]+$ ]] || die "LBS_VAULT_PORT must be numeric"

STAGE=$(mktemp -d /tmp/lbs-vault-uninstall.XXXXXX)
trap 'rm -rf -- "$STAGE"' EXIT
BACKUP_DIR=""
backup_dir() {
	if [[ -z $BACKUP_DIR ]]; then
		BACKUP_DIR=$BACKUP_ROOT/uninstall-$(date -u +%Y%m%dT%H%M%SZ)-$$
		if [[ ! -d $BACKUP_ROOT ]]; then run install -d -m 0700 -o root -g root "$BACKUP_ROOT"; fi
		run install -d -m 0700 -o root -g root "$BACKUP_DIR"
	fi
}

say "== LBS vault uninstall (dry-run=$DRY_RUN, purge-data=$PURGE) =="

# ---- 1. tailscale serve path (only ours) --------------------------------------
TARGET=http://127.0.0.1:$PORT
if command -v tailscale >/dev/null; then
	tailscale serve status --json >"$STAGE/serve-before.json"
	state=$("$PY" -I - "$STAGE/serve-before.json" "$HOST:443" "$SERVE_PATH" "$TARGET" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
hp, path, target = sys.argv[2:]
h = ((cfg.get("Web") or {}).get(hp) or {}).get("Handlers") or {}
mine = {k: v for k, v in h.items() if k.rstrip("/") == path}
if not mine:
    print("absent")
elif len(mine) == 1 and set(next(iter(mine.values()))) == {"Proxy"} and next(iter(mine.values()))["Proxy"].rstrip("/") == target:
    print("ours " + next(iter(mine)))
else:
    print("foreign")
PYEOF
)
	case "$state" in
		absent) say "ok: no tailscale serve $SERVE_PATH" ;;
		foreign) say "WARNING: $SERVE_PATH is served by something other than $TARGET; left untouched" ;;
		ours*)
			backup_dir
			change "tailscale serve: remove https://$HOST$SERVE_PATH (backup: $BACKUP_DIR/serve-before.json)"
			run install -m 0600 -o root -g root "$STAGE/serve-before.json" "$BACKUP_DIR/serve-before.json"
			run tailscale serve --https=443 --set-path="${state#ours }" off
			;;
		*) die "could not read tailscale serve config" ;;
	esac
else
	say "skip: tailscale not installed"
fi

# ---- 2. systemd units ------------------------------------------------------------
UNITS_CHANGED=0
for u in "${UNITS[@]}"; do
	if systemctl is-active --quiet "$u"; then change "stop $u"; run systemctl stop "$u"; fi
	if [[ $(systemctl is-enabled "$u" 2>/dev/null || true) == enabled ]]; then
		change "disable $u"; run systemctl disable "$u"
	fi
	if [[ -e $UNIT_DIR/$u ]]; then
		backup_dir
		change "remove $UNIT_DIR/$u (copy -> $BACKUP_DIR/$u)"
		run cp -a -- "$UNIT_DIR/$u" "$BACKUP_DIR/$u"
		run rm -f -- "$UNIT_DIR/$u"
		UNITS_CHANGED=1
	else
		say "ok: $UNIT_DIR/$u absent"
	fi
done
if [[ $UNITS_CHANGED == 1 ]]; then run systemctl daemon-reload; fi

# ---- 3. installed trees (only ones carrying our marker) ------------------------
remove_tree() {
	local dest=$1 marker=$2 label=$3
	if [[ ! -e $dest && ! -L $dest ]]; then say "ok: $label absent ($dest)"; return 0; fi
	[[ -d $dest && ! -L $dest && -f $marker ]] || die "$dest was not installed by install.sh (no $marker); refusing to delete"
	change "remove $label: $dest"
	run rm -rf --one-file-system -- "$dest"
}
remove_tree "$PLUGIN_DIR" "$PLUGIN_DIR/$MARKER" "staged Hermes plugin"
remove_tree "$PREFIX" "$PREFIX/lib/$MARKER" "package code"

# ---- 4. data (encrypted store + key) --------------------------------------------
if [[ -d $DIR ]]; then
	if [[ $PURGE == 1 ]]; then
		change "DESTROY data dir $DIR (encrypted store, key, audit log, device digests)"
		run rm -rf --one-file-system -- "$DIR"
	else
		say "kept: $DIR (encrypted store + key; rerun with --purge-data to destroy)"
	fi
else
	say "ok: data dir absent ($DIR)"
fi

say ""
say "== $CHANGES change(s)$([[ $DRY_RUN == 1 ]] && echo ' planned (dry run: nothing applied)') =="
[[ -z $BACKUP_DIR ]] || say "backups: $BACKUP_DIR"
say "Hermes gateway: NOT touched. If lbs-vault is in plugins.enabled, remove it (hermes plugins disable lbs-vault) before the next gateway /restart."
