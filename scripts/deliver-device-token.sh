#!/usr/bin/env bash
# Deliver a staged vault bearer to a native client over lbm. Run as leo, never root.
#
#   scripts/deliver-device-token.sh rubric-iphone   # Leo's iPhone, via devicectl when lbm sees it
#   scripts/deliver-device-token.sh rubric-mac      # Rubric on lbm, TGLens tdata handoff
#
# Input: ~/.lbs-vault-pair/<device>.token from `sudo scripts/pair-device.sh <device>`.
# 1. One authorized metadata call over the served URL proves the bearer is live (404 for a
#    well-formed unknown request id; 401 would mean not paired).
# 2. Copies the token to lbm over ssh STDIN into a private temp file and from there into the
#    app's handoff path; the lbm temp copy is deleted right after the copy (best-effort on APFS/SSD:
#    rely on FileVault/LUKS, not overwrite, for residue).
# 3. Waits until the app has imported it (handoff file gone: the importer only deletes after
#    a verified Keychain write), repeats the authorized call, then shreds the Spark copy.
# The token never appears on a command line, in logs, chat or git. Output is metadata only.
set -euo pipefail
umask 077
export LC_ALL=C

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || die "run as leo, not root"
[[ $# -eq 1 ]] || die "usage: $0 rubric-iphone|rubric-mac"
DEVICE=$1
case $DEVICE in rubric-iphone|rubric-mac) ;; *) die "unknown device $DEVICE" ;; esac

LBM=${LBS_PAIR_LBM:-lbm}
IPHONE_UDID=${LBS_PAIR_IPHONE_UDID:-00008150-001679D60269401C}
BUNDLE=ai.leobrain.tglens.codex
URL=https://spark-dd6e.tail4b7569.ts.net/lbs-vault/requests/$(printf 'A%.0s' {1..43})
POLL_S=${LBS_PAIR_POLL_S:-60}
MAX_POLLS=${LBS_PAIR_MAX_POLLS:-1440}   # 24h at 60s
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10)
[[ $LBM =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "bad LBS_PAIR_LBM"
[[ $IPHONE_UDID =~ ^[0-9A-Fa-f-]{8,40}$ ]] || die "bad LBS_PAIR_IPHONE_UDID"
[[ $POLL_S =~ ^[1-9][0-9]{0,3}$ && $MAX_POLLS =~ ^[1-9][0-9]{0,5}$ ]] || die "bad poll settings"

DIR=$HOME/.lbs-vault-pair
TOKEN=$DIR/$DEVICE.token
[[ -d $DIR && ! -L $DIR && -O $DIR && $(stat -c %a -- "$DIR") == 700 ]] || die "unsafe or missing $DIR"
[[ -f $TOKEN && ! -L $TOKEN && -O $TOKEN && $(stat -c '%a %h' -- "$TOKEN") == "600 1" ]] \
	|| die "missing or unsafe staged token $TOKEN"

HDR=$(mktemp "$DIR/.hdr.XXXXXX")
trap 'shred -u -- "$HDR" 2>/dev/null || true' EXIT
{ IFS= read -r tok; printf 'Authorization: Bearer %s\n' "$tok"; unset tok; } <"$TOKEN" >"$HDR"

vault_reply() {   # $1 = header file; prints "<code> <Server header> <body>" — never the bearer
	local body hdrs code
	body=$(mktemp "$DIR/.body.XXXXXX"); hdrs=$(mktemp "$DIR/.resp.XXXXXX")
	code=$(curl -q -sS --max-time 15 -D "$hdrs" -o "$body" -w '%{http_code}' -H @"$1" "$URL") || code=000
	printf '%s %s %s\n' "$code" "$(grep -i '^server:' "$hdrs" | tr -d '\r' | cut -d' ' -f2)" "$(head -c 200 "$body")"
	rm -f -- "$body" "$hdrs"
}
authorized_probe() {
	# The real vault must answer: a fake bearer gets 401 unauthorized, ours gets 404 not_found.
	local fake reply
	fake=$(mktemp "$DIR/.fake.XXXXXX")
	printf 'Authorization: Bearer FAKE%s\n' "$(head -c 24 /dev/urandom | base64 | tr '+/' '-_')" >"$fake"
	reply=$(vault_reply "$fake"); rm -f -- "$fake"
	[[ $reply == '401 LBSVault {"error":"unauthorized"}' ]] || { echo "fake-bearer probe unexpected: ${reply%% *}"; return 1; }
	reply=$(vault_reply "$HDR")
	echo "authorized metadata probe: HTTP ${reply%% *}"
	[[ $reply == '404 LBSVault {"error":"not_found"}' ]]
}
authorized_probe || die "vault did not accept the bearer (want 404 not_found from LBSVault); not delivering"

if [[ $DEVICE == rubric-iphone ]]; then
	phone_ready() {
		"${SSH[@]}" "$LBM" "xcrun devicectl list devices 2>/dev/null | grep -F '$IPHONE_UDID' | grep -qv unavailable" 2>/dev/null
	}
	handoff_present() {   # exit 0 present, 1 absent (listing succeeded), anything else unknown
		"${SSH[@]}" "$LBM" bash -s -- "$IPHONE_UDID" "$BUNDLE" <<'REMOTE'
set -uo pipefail
j=$(mktemp); trap 'rm -f "$j"' EXIT
xcrun devicectl device info files --device "$1" --domain-type appDataContainer \
	--domain-identifier "$2" --subdirectory Documents/tglens --json-output "$j" >/dev/null 2>&1 || exit 2
/usr/bin/python3 - "$j" <<'PY'
import json, sys
try:  # exit 1 ONLY for a validated listing without the file; anything odd is unknown (2)
    doc = json.load(open(sys.argv[1]))
    ok = (isinstance(doc, dict) and isinstance(doc.get("info"), dict)
          and doc["info"].get("outcome") == "success" and isinstance(doc.get("result"), dict)
          and isinstance(doc["result"].get("files"), list))
except Exception:
    ok = False
if not ok:
    sys.exit(2)
hits = []
def walk(node):
    if isinstance(node, dict):
        if any(isinstance(v, str) and v.endswith("lbs_vault_token") for v in node.values()):
            hits.append(node)
        for v in node.values(): walk(v)
    elif isinstance(node, list):
        for v in node: walk(v)
try:
    walk(doc["result"])
except Exception:
    sys.exit(2)
for h in hits:  # metadata only: mode/owner/size, never contents
    print("on-device handoff metadata:", {k: v for k, v in h.items()
          if any(s in k.lower() for s in ("perm", "mode", "owner", "uid", "size"))})
sys.exit(0 if hits else 1)
PY
REMOTE
	}
	for ((i = 0; ; i++)); do
		phone_ready && break
		((i < MAX_POLLS)) || die "phone not seen by $LBM within the polling window; staged token kept"
		((i % 30)) || echo "waiting for $LBM to see the iPhone"
		sleep "$POLL_S"
	done
	echo "iPhone available; copying handoff into $BUNDLE Documents/tglens"
	"${SSH[@]}" "$LBM" "bash -c '
		set -euo pipefail; umask 077
		d=\$(mktemp -d); trap \"rm -P -f \$d/lbs_vault_token 2>/dev/null; rmdir \$d\" EXIT
		cat > \$d/lbs_vault_token; chmod 600 \$d/lbs_vault_token
		xcrun devicectl device copy to --device $IPHONE_UDID --source \$d/lbs_vault_token \
			--destination Documents/tglens/lbs_vault_token --domain-type appDataContainer \
			--domain-identifier $BUNDLE >/dev/null'" <"$TOKEN"
	echo "copied; lbm temp copy removed"
	handoff_present || die "handoff not visible on the phone right after copy; staged token kept, investigate"
else
	echo "copying handoff into TGLens tdata on $LBM"
	"${SSH[@]}" "$LBM" "bash -c '
		set -euo pipefail; umask 077; set -o noclobber
		f=\"\$HOME/Library/Application Support/TGLens/tdata/lbs_vault_token\"
		cat > \"\$f\"; chmod 600 \"\$f\"'" <"$TOKEN"
	echo "copied"
	handoff_present() {
		"${SSH[@]}" "$LBM" 'test -e "$HOME/Library/Application Support/TGLens/tdata/lbs_vault_token"'
		local rc=$?; ((rc == 255)) && return 2; return $rc
	}
	handoff_present || die "handoff not visible on $LBM right after copy; staged token kept, investigate"
fi

echo "waiting for the app to import (opens on Leo's next 'Give it here' tap or launch)"
for ((i = 0; ; i++)); do
	rc=0; handoff_present || rc=$?
	if ((rc == 1)); then break; fi
	((i < MAX_POLLS)) || die "handoff not imported within the polling window; staged token kept for retry"
	sleep "$POLL_S"
done
echo "handoff file gone after being seen on the device: app imported it into Keychain"
authorized_probe || die "bearer rejected after import"
shred -u -- "$TOKEN"
echo "Spark staged copy shredded; $DEVICE paired"
