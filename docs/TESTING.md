# Canary-only verification

Run target code only with a read-only source/toolchain and isolated loopback. On Spark, unprivileged bubblewrap and unshare cannot configure namespaces (`RTM_NEWADDR: Operation not permitted`, `uid_map: Operation not permitted`). Existing Docker image `python:3.12-slim` and already-installed Python 3.12 dependencies support the following offline alternative; no downloads:

```sh
docker run --rm --network none --read-only --user 1000:1000 \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --memory 256m --cpus 1 \
  --ulimit cpu=30:30 --ulimit fsize=16777216:16777216 --ulimit nofile=128:128 \
  --tmpfs /scratch:rw,exec,nosuid,nodev,size=64m,mode=1777 \
  --mount type=bind,source=/home/leo/lbs-secret-vault,target=/src,readonly \
  --mount type=bind,source=/usr/local/lib/python3.12/dist-packages,target=/deps,readonly \
  --mount type=bind,source=/etc/passwd,target=/etc/passwd,readonly \
  --workdir /src --entrypoint /usr/bin/env python:3.12-slim \
  -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/scratch TMPDIR=/scratch \
  PYTHONPATH=/src:/deps PYTHONDONTWRITEBYTECODE=1 \
  python -m pytest -q -p no:cacheprovider --basetemp=/scratch/pytest
```

Apply an outer wall-clock timeout (90 seconds for the suite invocation). `exec` on scratch is required for executable fake targets; no secrets or home directories are mounted. Read-only passwd supplies the broker's fixed-uid/home metadata, not shadow credentials. Scratch writes are disk-bounded to 64 MiB. No host sockets, Docker socket, production endpoints or external networking enter the container.

The tests exercise fake owner/device principals and fake stdin targets. They must never contact thedoorpc, send Telegram messages, read chat history, restart the gateway, or read real credentials. Unit/daemon proof is not native Rubric visual proof or real Tailscale routing proof.

## Owner-gated live probe

Only after LBS reviews/runs `scripts/install.sh` and authorizes live probes: provision a dedicated fake-canary device, create a local request, submit a generated `CANARY-<random>` over the real served URL using a protected file/HTTP header (never a URL token or command argument containing the value), use a local fake target, and verify metadata-only results. Write the canary into a new 0600 file at an explicitly agreed owner-readable private path; LBS may then grep **only that canary** in `/root/.hermes/state.db`. Do not dump message contents, read unrelated rows, or search for historical secrets. Record unauthenticated served `curl -w '%{http_code}'` result (must be 401), save status, broker exit/redacted output, and canary-negative leak scans. Delete dedicated fake fixture/device/target through reviewed operator steps; no real saved secrets are involved.

## Installed-service live verification — probe 20261031-200f6a5bf966

Authorization: `work/LBS-INSTALL-DONE.md`. LBS reports root installation completed with 13 changes, both vault units active, plugin staged/not enabled, gateway untouched, and the tailnet Serve path installed without changing other paths/Funnel.

Builder-observed first matrix (bounded `curl --max-time 10`, body suppressed, status codes only):

| Request | Observed HTTP |
|---|---:|
| Served GET `/lbs-vault/requests/x`, unauthenticated | 401 |
| Served malformed JSON POST, unauthenticated | 401 |
| Served GET with client-supplied `Tailscale-Funnel-Request: ?1`, unauthenticated | 401 |
| Loopback GET with `Tailscale-Funnel-Request: ?1`, unauthenticated | 403 |

Authentication precedes body parsing. The served client marker is stripped by the proxy; the direct-backend marker is refused. This is not actual Funnel traffic, does not enable Funnel, and does not close the audit's Funnel-marker deployment caveat.

LBS reports the reviewed root setup completed successfully: installed library matches the repo, registry backed up, service active, private 0600 test header/metadata handed to leo, and gateway/plugin/Funnel/principals untouched. Builder then exercised the authenticated served URL on 2026-10-31 at 17:45:40 UTC:

| Authenticated case | Observed HTTP |
|---|---:|
| Malformed JSON | 400 |
| Body over 16384 bytes | 413 |
| Wrong Origin | 403 |
| Invalid handle | 400 |
| Client-supplied Funnel marker on GET `/requests/x` | 404 (marker suppressed by proxy; authenticated route lookup) |
| Public request creation | 403 |
| Isolated fake-owner canary save | 200 |

The save response was exactly the expected handle-only object. Every response was checked in-process for both the canary and bearer; neither appeared. Curl used `-q`, an empty allowlisted environment, private `--header @file` / `--data-binary @file`, and private response files deleted after validation. No value was put in argv, environment, URL or displayed output. Status-only evidence: ignored private `client-results.json`.

**Status: Spark live canary verification complete.** LBS executed the reviewed root block successfully, and the builder read its metadata-only `root-proof.json`: `status=passed`, broker exit `0`, no timeout, exact output `accepted:[REDACTED]`, and revoked test bearer HTTP `401`. Root proof ran `2026-10-31T18:17:47Z` through `18:17:51Z`.

| Exact-canary scan | Observed root result |
|---|---|
| Fake owner ciphertext | Absent in raw bytes |
| Current audit | Absent in raw bytes |
| Previous audit archive | File not present |
| state.db / WAL / SHM | Absent in raw bytes in all three |
| Journal since setup, all exported fields | Absent in export bytes |

These are exact fixed-pattern byte searches, not SQL row reconstruction or detection of arbitrary encoding/compression. No matching lines, messages, canary or bearer values were printed. Root proof records removal of the test template/device, fake ciphertext, helper/directory, private credentials and leo bearer handoff; vault key retained. LBS reports the vault service active. No gateway/plugin/principal/Serve modification was made by the root block.

Evidence: metadata-only `work/live-probe-20261031-200f6a5bf966/root-proof.json` (0600 leo, intentionally git-ignored), with non-sensitive summary in `work/VERIFY.md`. Do not rerun `work/ROOT-STEPS.md`: this fixture has been revoked and removed. Native iOS/desktop visual and client integration verification continues separately; plugin activation and real-secret onboarding remain Leo-controlled gates.
