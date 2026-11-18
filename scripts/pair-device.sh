#!/usr/bin/env bash
# Pair one native client with the LBS vault. Root only.
#
#   sudo scripts/pair-device.sh <device-name>
#
# 1. Provisions <device-name> with the INSTALLED root-owned code (never this checkout's
#    Python), writing the new bearer to a fresh 0600 root file. The owner Telegram ID
#    already lives in principals.json; it is not touched here.
# 2. Restarts only lbs-vault.service so the HTTP service loads the new device registry.
#    Never the Hermes gateway.
# 3. Stages the bearer for leo's delivery step (scripts/deliver-device-token.sh) at
#    /home/leo/.lbs-vault-pair/<device-name>.token (0600 leo, dir 0700 leo). The copy
#    is written AS leo through stdin (no root write into a leo-owned path, no token on a
#    command line), then the root copy is shredded.
#
# Prints metadata only. The token never reaches stdout, logs or argv.
set -euo pipefail
umask 077
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "must run as root"
[[ $# -eq 1 ]] || die "usage: $0 <device-name>"
DEVICE=$1
[[ $DEVICE =~ ^[a-z0-9][a-z0-9-]{1,31}$ ]] || die "device name must match ^[a-z0-9][a-z0-9-]{1,31}$"

LIB=${LBS_VAULT_PREFIX:-/opt/lbs-vault}/lib
DIR=${LBS_VAULT_DIR:-/root/.hermes/lbs-vault}
OWNER=${LBS_VAULT_OWNER:-leo}
STAGE_USER=leo
PRIVATE=/root/private/lbs-vault-pair
# Installed code and its parents must be root-owned and not group/other-writable.
for p in "$LIB" "$LIB/lbs_vault" "$LIB/lbs_vault/__init__.py" "$LIB/lbs_vault/provision.py" "$LIB/lbs_vault/store.py"; do
	read -r uid mode <<<"$(stat -c '%u %a' -- "$p")" || die "missing installed code: $p"
	[[ $uid == 0 && $(( 8#$mode & 8#022 )) == 0 ]] || die "installed code not root-owned/protected: $p"
done
[[ -f $DIR/principals.json ]] || die "principals.json missing: set the owner Telegram ID first"

[[ -d /root/private ]] || install -d -m 0700 -o root -g root /root/private
[[ -d $PRIVATE ]] || install -d -m 0700 -o root -g root "$PRIVATE"
[[ ! -L $PRIVATE && $(stat -c '%u %a' -- "$PRIVATE") == "0 700" ]] || die "unsafe $PRIVATE"
OUT=$PRIVATE/$DEVICE.token
[[ ! -e $OUT ]] || die "$OUT exists; a previous pairing did not finish. Inspect, shred, revoke before retrying"

STAGE_HOME=$(getent passwd "$STAGE_USER" | cut -d: -f6)
STAGE_DIR=$STAGE_HOME/.lbs-vault-pair
STAGED=$STAGE_DIR/$DEVICE.token

# Preflight the leo staging side BEFORE registering anything, so a stale file can't strand a device.
runuser -u "$STAGE_USER" -- /bin/bash --noprofile --norc -c '
	d=$1; f=$2
	[[ ! -e $d || ( -d $d && ! -L $d && -O $d && $(stat -c %a -- "$d") == 700 ) ]] || { echo "unsafe staging dir $d" >&2; exit 1; }
	[[ ! -e $f && ! -L $f ]] || { echo "stale staged token $f: deliver or shred it first" >&2; exit 1; }' _ "$STAGE_DIR" "$STAGED"

# No shred trap: once provisioning has registered the device, its 0600 root copy is the only
# recovery path, so on any later failure it is KEPT (and the message says where).
LBS_VAULT_DIR=$DIR LBS_VAULT_OWNER=$OWNER /usr/bin/python3 -I -B -c \
	'import sys; sys.path.insert(0, sys.argv[1]); del sys.argv[1]; from lbs_vault.provision import main; main()' \
	"$LIB" --device "$DEVICE" --owner "$OWNER" --output "$OUT"
echo "provisioned device $DEVICE"

# Stage as leo: leo's own umask/ownership, refuse to overwrite, no token in argv.
runuser -u "$STAGE_USER" -- /bin/bash --noprofile --norc -c '
	set -euo pipefail; umask 077
	d=$1; f=$2
	[[ -d $d ]] || mkdir -m 0700 -- "$d"
	[[ ! -L $d && -O $d && $(stat -c %a -- "$d") == 700 ]] || { echo "unsafe staging dir" >&2; exit 1; }
	set -o noclobber
	cat > "$f"
	chmod 0600 -- "$f"' _ "$STAGE_DIR" "$STAGED" <"$OUT" \
	|| die "staging failed; device $DEVICE is registered, root copy kept at $OUT for recovery"
cmp -s -- "$OUT" "$STAGED" || die "staged copy differs; root copy kept at $OUT for recovery"

shred -u -- "$OUT"
echo "staged for $STAGE_USER delivery at $STAGED (0600); root copy shredded"

systemctl restart lbs-vault.service
systemctl is-active --quiet lbs-vault.service || die "lbs-vault.service not active after restart (token stays staged)"
echo "restarted lbs-vault.service (gateway untouched)"
echo "next (as $STAGE_USER): scripts/deliver-device-token.sh $DEVICE"
