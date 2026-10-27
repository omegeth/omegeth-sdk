#!/usr/bin/env python3
"""Read and verify a world's Claims Office docket from the public record, and
print the claims in force and any pending node key changes.

    python3 examples/docket.py

Needs Python 3.10+ and `cryptography`. OMEGETH_RECORD, OMEGETH_ROOT_KEY and
OMEGETH_WORLD override the record's address, the pinned root key and the world.
"""
import base64
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'python'))
import omegeth_reader as C  # noqa: E402

BASE = os.environ.get('OMEGETH_RECORD', 'https://docs.omegeth.com/log/')
ROOT_KEY = base64.b64decode(os.environ.get('OMEGETH_ROOT_KEY', 'tDJlaUGNOXxmggV4zAIZw3yiumN8CwJ9QIgIUGf3I1I='))  # pinned
WORLD = os.environ.get('OMEGETH_WORLD', 'lunar-2')
OFFICE = 'omegeth.claims-office'


def http_reader(base):
    """A `read` for verify_log over HTTPS: bytes, or None for a missing file."""
    def read(relative):
        try:
            with urllib.request.urlopen(base + relative, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
    return read


def claims_docket(base=BASE, root_key=ROOT_KEY, world=WORLD):
    """The verified docket: {'sequence', 'batch_sha256', 'entries'}."""
    root_log = C.verify_log(http_reader(f'{base}{C.ROOT_ISSUER}/{world}/'), root_key, world, {C.REGISTRY})
    registry = C.registry_in_force(C.registry_versions(root_log['entries']), datetime.now(timezone.utc))
    if registry is None:
        raise ValueError('no registry in force yet')
    office = C.registry_office(registry, OFFICE)
    if office is None:
        raise ValueError('the registry names no Claims Office')
    last = None
    for key in office['keys']:
        try:
            log = C.verify_log(http_reader(f'{base}{OFFICE}/{world}/'), base64.b64decode(key['public_key_base64']),
                               world, {'office.receipt.v1', 'office.decision.v1'})
        except C.InvalidLog as exc:
            last = exc                               # a log is signed with one key: try the next
            continue
        for e in log['entries']:
            if key['key_id'] not in C.registry_keys(registry, OFFICE, e['created_at']):
                raise ValueError(f"docket {e['docket']}: signed outside the key's dates")
        return log
    raise last


def claims_now(entries):
    """{claim_id: {'partition', 'actor_id', 'node_key'}}: the grants, then each node key change in docket order."""
    claims = {}
    for d in sorted((e for e in entries if e['type'] == 'office.decision.v1'), key=lambda e: e['docket']):
        if d['outcome'] == 'GRANTED':
            claims[d['claim']['claim_id']] = {'partition': d['claim']['partition'], 'actor_id': d['actor_id'],
                                              'node_key': d['claim']['node_key']}
        elif d['outcome'] == 'REKEYED':
            claims[d['rekey']['claim_id']]['node_key'] = d['rekey']['node_key']
    return claims


def pending_key_changes(entries):
    """Node key changes received and not yet decided, with when each takes over."""
    decided = {e['docket'] for e in entries if e['type'] == 'office.decision.v1'}
    return [{'docket': e['docket'], 'claim_id': e['params']['claim_id'], 'actor_id': e['actor_id'],
             'node_key': e['params']['node_key'], 'takes_effect': C.moment(e['received_at']) + timedelta(hours=24)}
            for e in entries if e['type'] == 'office.receipt.v1' and e['action'] == 'claim.rekey'
            and e['status'] == 'RECEIVED' and e['docket'] not in decided]


def main():
    log = claims_docket()
    print(f"Verified {len(log['entries'])} entries of world {WORLD} from root key {C.key_id(ROOT_KEY)}.")
    for claim_id, claim in sorted(claims_now(log['entries']).items(), key=lambda kv: kv[1]['partition']):
        print(f"{claim['partition']}  {claim_id}  node key {C.key_id(base64.b64decode(claim['node_key']))}")
    for p in pending_key_changes(log['entries']):
        print(f"pending: claim {p['claim_id']} takes node key {C.key_id(base64.b64decode(p['node_key']))} "
              f"at {p['takes_effect']:%Y-%m-%d %H:%M} UTC unless cancelled")


if __name__ == '__main__':
    main()
