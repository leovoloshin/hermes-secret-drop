"""Offline root operator provisioning; token is written only to a private file."""
import argparse
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from .store import Store, atomic, read_private, private_dir, text

def main():
    if os.geteuid()!=0: raise SystemExit('root required')
    parser=argparse.ArgumentParser()
    parser.add_argument('--device',required=True)
    parser.add_argument('--owner',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--days',type=int,default=90)
    parser.add_argument('--telegram-owner-id')
    args=parser.parse_args()
    text(args.device,64); text(args.owner,64)
    if not 1<=args.days<=365: raise SystemExit('days must be 1..365')
    if args.telegram_owner_id is not None and not (
            args.telegram_owner_id.isascii() and args.telegram_owner_id.isdecimal() and
            1<=len(args.telegram_owner_id)<=20 and not args.telegram_owner_id.startswith('0')):
        raise SystemExit('telegram owner id must be a positive ASCII numeric id')
    private_dir(args.output.parent)
    base=Path(os.environ.get('LBS_VAULT_DIR','/root/.hermes/lbs-vault'))
    store=Store(base)
    with store.transaction():
        path=base/'devices.json'
        data=json.loads(read_private(path)) if path.exists() else {'devices':[]}
        if any(d['id']==args.device for d in data['devices']): raise SystemExit('device exists; revoke explicitly before replacing')
        principals=Path(os.environ.get('LBS_VAULT_PRINCIPALS',str(base/'principals.json')))
        private_dir(principals.parent)
        policy=None
        if args.telegram_owner_id is not None:
            policy={'owner':args.owner,'telegram_user_id':args.telegram_owner_id}
            existing=json.loads(read_private(principals)) if principals.exists() else {}
            if existing and existing!=policy:
                raise SystemExit('owner principal already configured; review it explicitly before replacement')
        token=secrets.token_urlsafe(32)
        fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:
            f.write(token+'\n'); f.flush(); os.fsync(f.fileno())
        data['devices'].append(dict(id=args.device,owner=args.owner,token_sha256=hashlib.sha256(token.encode()).hexdigest(),expires_at=time.time()+args.days*86400))
        atomic(path,json.dumps(data).encode())
        if policy is not None: atomic(principals,json.dumps(policy).encode())
    print('Device provisioned to private output file. Restart vault HTTP service to load device registry; never restart gateway for this.')

if __name__=='__main__': main()
