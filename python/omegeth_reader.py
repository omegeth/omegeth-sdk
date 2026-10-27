"""Omegeth reader: verify the public record at docs.omegeth.com.

Verifies signed statements, public logs (head and hash-chained batches), the
office registry, and client keys' proofs of possession, and makes proofs of
possession. Contract version 4. Requires Python 3.10+ and the
`cryptography` package.

Generated from the Omegeth reference implementation; do not edit. Every
function passes the same test vectors as the JavaScript reader,
omegeth_contract.js.
"""
import base64
import hashlib
import json
import re
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONTRACT_VERSION = 4
PREFIX = b'OMEGETH-SIGNED\0'
WORLD = re.compile(r'^[a-z0-9][a-z0-9.-]{2,62}$')
TYPE = re.compile(r'^[a-z][a-z0-9_.-]{2,80}$')
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
TIMESTAMP = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$')


class InvalidStatement(ValueError):
    """A statement that does not verify. `reason` is one of invalid_envelope,
    invalid_signature or invalid_statement."""

    def __init__(self, reason, detail=''):
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason


def key_id(public_key_raw):
    """The first 16 hex digits of SHA-256 of the raw 32-byte public key."""
    return hashlib.sha256(public_key_raw).hexdigest()[:16]


def signed_bytes(world, statement_type, statement_json):
    """Exactly what the signature covers."""
    return PREFIX + world.encode() + b'\0' + statement_type.encode() + b'\0' + statement_json


def verify(public_key_raw, world, statement_type, envelope_json):
    """Check an envelope for one world and one type, and return its statement.
    Raises InvalidStatement. The signature is checked over the statement bytes
    as received; nothing is re-serialized."""
    try:
        envelope = json.loads(envelope_json)
    except (TypeError, ValueError) as exc:
        raise InvalidStatement('invalid_envelope', 'not JSON') from exc
    if (not isinstance(envelope, dict) or envelope.get('algorithm') != 'Ed25519'
            or not isinstance(envelope.get('statement_json'), str) or not isinstance(envelope.get('signature_base64'), str)):
        raise InvalidStatement('invalid_envelope')
    raw = envelope['statement_json'].encode()
    try:
        signature = base64.b64decode(envelope['signature_base64'], validate=True)
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, signed_bytes(world, statement_type, raw))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise InvalidStatement('invalid_signature') from exc
    try:
        statement = json.loads(raw)
    except ValueError as exc:
        raise InvalidStatement('invalid_statement', 'not JSON') from exc
    if not isinstance(statement, dict):
        raise InvalidStatement('invalid_statement', 'not an object')
    problem = _common_fields(statement)
    if problem:
        raise InvalidStatement('invalid_statement', problem)
    if statement['type'] != statement_type or statement['world'] != world or statement['key_id'] != key_id(public_key_raw):
        raise InvalidStatement('invalid_statement', 'type, world or key_id does not match')
    return statement


def _common_fields(statement):
    checks = (('type', TYPE), ('world', WORLD), ('key_id', re.compile(r'^[0-9a-f]{16}$')),
              ('publication_id', UUID), ('created_at', TIMESTAMP))
    for name, pattern in checks:
        if not isinstance(statement.get(name), str) or not pattern.fullmatch(statement[name]):
            return f'{name} missing or malformed'
    if not isinstance(statement.get('issuer'), str) or not statement['issuer']:
        return 'issuer missing'
    return None


LOG_BATCH, LOG_HEAD = 'log.batch.v1', 'log.head.v1'
BATCH_LIMIT = 1000
SHA256_HEX = re.compile(r'^[0-9a-f]{64}$')


class InvalidLog(ValueError):
    """A log that does not verify. `reason` is one of invalid_head,
    missing_batch, invalid_batch, broken_chain, invalid_entry, unexpected_type."""

    def __init__(self, reason, detail=''):
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason


def batch_path(sequence):
    """Where batch `sequence` lives, relative to the world's directory."""
    return f'batches/{sequence:08d}.json'


def entry_type(envelope_json):
    """The type an entry claims, read before verifying it; verify() then
    checks the claim against the signature."""
    try:
        return json.loads(json.loads(envelope_json)['statement_json'])['type']
    except (TypeError, ValueError, KeyError):
        return None


def verify_log(read, public_key_raw, world, entry_types, after=None):
    """Verify a world's log and return {'sequence', 'batch_sha256', 'entries'}.

    `read(path)` returns the bytes of a file relative to the world's directory
    (`head.json`, `batches/…`), or None if it is missing. `entry_types` are the
    statement types this reader accepts from this key. `after`, a
    (sequence, batch_sha256) pair from an earlier verification, verifies only
    what is newer and returns only the newer entries.
    """
    head_bytes = read('head.json')
    if head_bytes is None:
        raise InvalidLog('invalid_head', 'head.json missing')
    try:
        head = verify(public_key_raw, world, LOG_HEAD, head_bytes.decode())
    except (InvalidStatement, UnicodeDecodeError) as exc:
        raise InvalidLog('invalid_head', str(exc)) from exc
    last = head.get('sequence')
    if type(last) is not int or last < 0 or not SHA256_HEX.fullmatch(str(head.get('batch_sha256'))):
        raise InvalidLog('invalid_head', 'sequence or batch_sha256 malformed')
    start, previous = (0, None) if after is None else (after[0] + 1, after[1])
    if after is not None and last < after[0]:
        raise InvalidLog('broken_chain', 'the head is older than what was already verified')
    if after is not None and last == after[0]:
        if head['batch_sha256'] != after[1]:
            raise InvalidLog('broken_chain', 'the head names a different newest batch')
        return {'sequence': last, 'batch_sha256': after[1], 'entries': []}
    entries = []
    for sequence in range(start, last + 1):
        raw = read(batch_path(sequence))
        if raw is None:
            raise InvalidLog('missing_batch', batch_path(sequence))
        try:
            batch = verify(public_key_raw, world, LOG_BATCH, raw.decode())
        except (InvalidStatement, UnicodeDecodeError) as exc:
            raise InvalidLog('invalid_batch', f'{batch_path(sequence)}: {exc}') from exc
        if batch.get('sequence') != sequence or batch.get('previous_sha256') != previous:
            raise InvalidLog('broken_chain', batch_path(sequence))
        batch_entries = batch.get('entries')
        if not isinstance(batch_entries, list) or not 1 <= len(batch_entries) <= BATCH_LIMIT:
            raise InvalidLog('invalid_batch', f'{batch_path(sequence)}: entries')
        for envelope in batch_entries:
            claimed = entry_type(envelope) if isinstance(envelope, str) else None
            if claimed not in entry_types:
                raise InvalidLog('unexpected_type', f'{batch_path(sequence)}: {claimed!r}')
            try:
                entries.append(verify(public_key_raw, world, claimed, envelope))
            except InvalidStatement as exc:
                raise InvalidLog('invalid_entry', f'{batch_path(sequence)}: {exc}') from exc
        previous = hashlib.sha256(raw).hexdigest()
    if previous != head['batch_sha256']:
        raise InvalidLog('broken_chain', 'the head does not name the newest batch')
    return {'sequence': last, 'batch_sha256': previous, 'entries': entries}


def directory_reader(path):
    """A `read` for verify_log over a local copy of a world's directory."""
    from pathlib import Path
    root = Path(path)

    def read(relative):
        target = root / relative
        return target.read_bytes() if target.is_file() else None
    return read


OFFICE_ID = re.compile(r'^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$')


def moment(text):
    """A contract timestamp as an aware datetime. Compare these, never the
    strings: fractional digits vary."""
    if not isinstance(text, str) or not TIMESTAMP.fullmatch(text):
        raise ValueError(f'not a contract timestamp: {text!r}')
    return datetime.fromisoformat(text.replace('Z', '+00:00'))


REGISTRY = 'office.registry.v1'
ROOT_ISSUER = 'omegeth.corporate-root'
ROLES = ('identity', 'office')
ACTION_PREFIX = re.compile(r'^[a-z][a-z0-9_]*\.$')


class InvalidRegistry(ValueError):
    """A registry log whose versions break the registry's rules."""


def registry_versions(entries):
    """Check the entries of a verified root log (verify_log(...)['entries']
    with entry types {REGISTRY}) and return them: versions 1, 2, 3 … in
    order, effective times never going back, well-formed offices and keys."""
    previous = None
    for number, version in enumerate(entries, 1):
        if version.get('type') != REGISTRY or version.get('issuer') != ROOT_ISSUER or version.get('version') != number:
            raise InvalidRegistry(f'entry {number} is not registry version {number}')
        try:
            effective = moment(version.get('effective_from'))
        except ValueError as exc:
            raise InvalidRegistry(f'version {number}: effective_from') from exc
        if previous is not None and effective < previous:
            raise InvalidRegistry(f'version {number} takes effect before version {number - 1}')
        previous = effective
        offices = version.get('offices')
        if not isinstance(offices, list) or not offices:
            raise InvalidRegistry(f'version {number}: no offices')
        ids = [o.get('id') if isinstance(o, dict) else None for o in offices]
        if len(set(ids)) != len(ids):
            raise InvalidRegistry(f'version {number}: an office is listed twice')
        for office in offices:
            _check_office(number, office)
    return list(entries)


def _check_office(number, office):
    where = f"version {number}, {office.get('id')!r}"
    if set(office) != {'id', 'role', 'action_prefixes', 'keys'} or not isinstance(office['id'], str) \
            or not OFFICE_ID.fullmatch(office['id']) or office['role'] not in ROLES:
        raise InvalidRegistry(f'{where}: id, role or fields')
    prefixes = office['action_prefixes']
    if not isinstance(prefixes, list) or not all(isinstance(p, str) and ACTION_PREFIX.fullmatch(p) for p in prefixes) \
            or (office['role'] == 'office') != bool(prefixes):
        raise InvalidRegistry(f'{where}: action_prefixes (offices have some, the identity office none)')
    keys = office['keys']
    if not isinstance(keys, list) or not keys:
        raise InvalidRegistry(f'{where}: no keys')
    for key in keys:
        try:
            raw = base64.b64decode(key['public_key_base64'], validate=True)
            start, until = moment(key['from']), None if key['until'] is None else moment(key['until'])
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidRegistry(f'{where}: a key is malformed') from exc
        if set(key) != {'key_id', 'public_key_base64', 'from', 'until'} or len(raw) != 32 or key['key_id'] != key_id(raw) \
                or (until is not None and until <= start):
            raise InvalidRegistry(f'{where}: a key is malformed')


def registry_in_force(versions, at):
    """The newest version whose effective_from is not after `at` (a datetime
    or timestamp), or None."""
    at = moment(at) if isinstance(at, str) else at
    current = None
    for version in versions:
        if moment(version['effective_from']) <= at:
            current = version
    return current


def registry_office(registry, office_id):
    """An office's entry in a registry version, or None."""
    return next((o for o in registry['offices'] if o['id'] == office_id), None)


def registry_keys(registry, office_id, at):
    """{key_id: raw public key} for the office's keys valid at `at`."""
    at = moment(at) if isinstance(at, str) else at
    office = registry_office(registry, office_id)
    return {k['key_id']: base64.b64decode(k['public_key_base64']) for k in (office or {}).get('keys', ())
            if moment(k['from']) <= at and (k['until'] is None or at < moment(k['until']))}


def registry_allows(registry, office_id, action):
    """True if `office_id` is an office in this version and `action` begins
    with one of its prefixes."""
    office = registry_office(registry, office_id)
    return bool(office and office['role'] == 'office' and any(action.startswith(p) for p in office['action_prefixes']))


PROOF_PREFIX = b'OMEGETH-KEY-PROOF-V1\0'
PURPOSE = re.compile(r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$')


def key_proof_bytes(world, purpose, subject):
    """Exactly what a proof of possession signs."""
    if not WORLD.fullmatch(world or '') or not PURPOSE.fullmatch(purpose or '') or not isinstance(subject, str) \
            or '\0' in subject:
        raise ValueError('invalid world, purpose or subject')
    return PROOF_PREFIX + world.encode() + b'\0' + purpose.encode() + b'\0' + subject.encode()


def sign_key_proof(private_key, world, purpose, subject):
    """A client key's proof of possession, base64."""
    return base64.b64encode(private_key.sign(key_proof_bytes(world, purpose, subject))).decode()


def verify_key_proof(public_key_b64, proof_b64, world, purpose, subject):
    """True when `proof_b64` is the key's signature over this world, purpose
    and subject. Never raises for bad input; returns False."""
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
        signature = base64.b64decode(proof_b64, validate=True)
        if len(raw) != 32 or len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(signature, key_proof_bytes(world, purpose, subject))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
