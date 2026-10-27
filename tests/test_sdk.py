"""The Python reader, the examples and the repository itself. Run from the
repository root:  python3 -m unittest discover -s tests
Needs Python 3.10+ and `cryptography`."""
import base64
import contextlib
import functools
import hashlib
import http.server
import json
import os
import re
import subprocess
import sys
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'python'), str(ROOT / 'examples')]
import omegeth_reader as r  # noqa: E402
import docket  # noqa: E402

VECTORS = ROOT / 'vectors'
WORLD = 'vectors.example'
# The example record's root key: a test key, never used outside the vectors.
ROOT_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96))).public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load(name):
    return json.loads((VECTORS / name).read_text(encoding='utf-8'))


@contextlib.contextmanager
def record_host():
    """vectors/log served over HTTP, as docs.omegeth.com serves /log/."""
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    handler = functools.partial(Quiet, directory=str(VECTORS / 'log'))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_address[1]}/'
    finally:
        server.shutdown()
        server.server_close()


class CopyTests(unittest.TestCase):
    """js/, python/ and vectors/ are copies; each must match its recorded SHA-256."""

    def test_copies_are_unchanged(self):
        vendored = json.loads((ROOT / 'contract' / 'VENDORED.json').read_text())
        self.assertTrue(vendored['public'])
        self.assertEqual(set(vendored['sha256']), set(vendored['files'].values()))
        for target, digest in vendored['sha256'].items():
            self.assertEqual(hashlib.sha256((ROOT / target).read_bytes()).hexdigest(), digest, f'{target} was edited')
        self.assertEqual(vendored['contract_version'], r.CONTRACT_VERSION)
        js = (ROOT / 'js' / 'omegeth_contract.js').read_text()
        self.assertIn(f'const CONTRACT_VERSION = {r.CONTRACT_VERSION};', js)


class ReaderTests(unittest.TestCase):
    def test_statement_vectors(self):
        vectors = load('public_statements.json')
        key = base64.b64decode(vectors['public_key_base64'])
        for v in vectors['valid']:
            self.assertEqual(r.verify(key, v['world'], v['publication_type'], v['envelope_json']), v['statement'])
        for v in vectors['invalid']:
            with self.assertRaises(r.InvalidStatement, msg=v['case']) as caught:
                r.verify(key, v['world'], v['publication_type'], v['envelope_json'])
            self.assertEqual(caught.exception.reason, v['reason'], v['case'])

    def test_key_proof_vectors(self):
        proofs = load('key_proofs.json')
        check = lambda v: r.verify_key_proof(v['public_key_base64'], v['proof_base64'], v['world'], v['purpose'], v['subject'])  # noqa: E731
        self.assertTrue(all(check(v) for v in proofs['valid']))
        for v in proofs['invalid']:
            self.assertFalse(check(v), v['case'])
        client = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(proofs['client_seed_hex']))
        v = proofs['valid'][0]
        self.assertEqual(r.sign_key_proof(client, v['world'], v['purpose'], v['subject']), v['proof_base64'])

    def test_the_example_registry_and_logs(self):
        log_dir = VECTORS / 'log'
        reg = r.verify_log(r.directory_reader(log_dir / r.ROOT_ISSUER / WORLD), ROOT_KEY, WORLD, {r.REGISTRY})
        versions = r.registry_versions(reg['entries'])
        self.assertIsNone(r.registry_in_force(versions, '2026-09-30T00:00:00Z'))
        registry = r.registry_in_force(versions, '2026-10-20T00:00:00Z')
        identity = r.registry_office(registry, 'omegeth.identity-office')['keys'][0]
        actors = r.verify_log(r.directory_reader(log_dir / 'omegeth.identity-office' / WORLD),
                              base64.b64decode(identity['public_key_base64']), WORLD, {'identity.actor.v1'})
        self.assertEqual([e['designation'] for e in actors['entries']], ['Café One', '月面探査', "O'Neil-Smith"])
        newer = r.verify_log(r.directory_reader(log_dir / 'omegeth.identity-office' / WORLD),
                             base64.b64decode(identity['public_key_base64']), WORLD, {'identity.actor.v1'},
                             after=(0, hashlib.sha256((log_dir / 'omegeth.identity-office' / WORLD / 'batches/00000000.json').read_bytes()).hexdigest()))
        self.assertEqual([e['designation'] for e in newer['entries']], ["O'Neil-Smith"])
        with self.assertRaises(r.InvalidLog) as caught:
            r.verify_log(r.directory_reader(log_dir / 'omegeth.identity-office' / WORLD),
                         base64.b64decode(identity['public_key_base64']), WORLD, {'office.receipt.v1'})
        self.assertEqual(caught.exception.reason, 'unexpected_type')


class ExampleTests(unittest.TestCase):
    """examples/docket.py against the example record, served over HTTP."""

    def test_the_docket_example(self):
        with record_host() as base:
            log = docket.claims_docket(base, ROOT_KEY, WORLD)
        self.assertEqual([(e['type'], e['docket']) for e in log['entries']],
                         [('office.receipt.v1', 1), ('office.decision.v1', 1), ('office.receipt.v1', 2)])
        claims = docket.claims_now(log['entries'])
        self.assertEqual([c['partition'] for c in claims.values()], ['M-0412'])
        pending = docket.pending_key_changes(log['entries'])
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]['takes_effect'].isoformat(), '2026-10-21T08:00:00+00:00')

    def test_a_changed_root_key_is_refused(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        with record_host() as base, self.assertRaises(r.InvalidLog) as caught:
            docket.claims_docket(base, other, WORLD)
        self.assertEqual(caught.exception.reason, 'invalid_head')

    def test_the_script_runs(self):
        with record_host() as base:
            env = {**os.environ, 'OMEGETH_RECORD': base, 'OMEGETH_WORLD': WORLD,
                   'OMEGETH_ROOT_KEY': base64.b64encode(ROOT_KEY).decode()}
            out = subprocess.run([sys.executable, str(ROOT / 'examples' / 'docket.py')], env=env, capture_output=True, text=True,
                                 check=True, timeout=60).stdout
        self.assertIn('Verified 3 entries of world vectors.example', out)
        self.assertRegex(out, r'M-0412  8fa0afa2-a3ee-5ecc-965e-8a2c593cae9c  node key [0-9a-f]{16}')
        self.assertIn('pending: claim 8fa0afa2-a3ee-5ecc-965e-8a2c593cae9c', out)


class RepositoryTests(unittest.TestCase):
    """This repository is public: it describes the public record and nothing behind it."""

    INTERNAL = re.compile(r'(?i:relay|enclave|handoff|/api/|\.php\b|private/)|\bOIC\b')
    TEXT = {'.md', '.js', '.py', '.json', '.html', '.yml', '.txt', ''}

    def test_no_internal_detail(self):
        found = []
        for path in sorted(ROOT.rglob('*')):
            if '.git' in path.parts or not path.is_file() or path.suffix not in self.TEXT or path == Path(__file__).resolve():
                continue
            for number, line in enumerate(path.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
                if self.INTERNAL.search(line):
                    found.append(f'{path.relative_to(ROOT)}:{number}: {line.strip()[:100]}')
        self.assertEqual(found, [])


if __name__ == '__main__':
    unittest.main()
