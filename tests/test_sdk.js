'use strict';
// The JavaScript reader and examples/docket.js against the same vectors as Python.
// Run: node tests/test_sdk.js   (Node 20+; in CI)
const assert = require('assert'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const C = require('../js/omegeth_contract.js');
const {claimsDocket, claimsNow, pendingKeyChanges} = require('../examples/docket.js');
const ROOT = path.join(__dirname, '..');
const VECTORS = path.join(ROOT, 'vectors');
const WORLD = 'vectors.example';
const json = name => JSON.parse(fs.readFileSync(path.join(VECTORS, name), 'utf8'));

// The example record's root key: a test key, never used outside the vectors.
function rootKey() {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(Array.from({length: 32}, (_, i) => 64 + i))]);
  return crypto.createPublicKey(crypto.createPrivateKey({key: der, format: 'der', type: 'pkcs8'})).export({format: 'der', type: 'spki'}).subarray(12);
}
// vectors/log as docs.omegeth.com serves /log/, through fetch.
const BASE = 'https://record.test/log/';
async function fakeFetch(url) {
  const file = path.join(VECTORS, 'log', url.slice(BASE.length));
  return fs.existsSync(file) ? {ok: true, status: 200, text: async () => fs.readFileSync(file, 'utf8')} : {ok: false, status: 404};
}

(async () => {
  const statements = json('public_statements.json');
  const key = C.fromBase64(statements.public_key_base64);
  for (const v of statements.valid) assert.deepStrictEqual(await C.verify(key, v.world, v.publication_type, v.envelope_json), v.statement);
  for (const v of statements.invalid) await assert.rejects(C.verify(key, v.world, v.publication_type, v.envelope_json), e => e.reason === v.reason, v.case);
  console.log('PASS: statement vectors');

  const proofs = json('key_proofs.json');
  for (const v of proofs.valid) assert.ok(await C.verifyKeyProof(v.public_key_base64, v.proof_base64, v.world, v.purpose, v.subject));
  for (const v of proofs.invalid) assert.ok(!await C.verifyKeyProof(v.public_key_base64, v.proof_base64, v.world, v.purpose, v.subject), v.case);
  const pair = await crypto.webcrypto.subtle.generateKey({name: 'Ed25519'}, false, ['sign', 'verify']);
  const nodeKey = C.toBase64(new Uint8Array(await crypto.webcrypto.subtle.exportKey('raw', pair.publicKey)));
  const proof = await C.signKeyProof(pair.privateKey, WORLD, 'claim.node', 'subject');
  assert.ok(await C.verifyKeyProof(nodeKey, proof, WORLD, 'claim.node', 'subject'));
  console.log('PASS: key proof vectors, and a non-extractable key proves possession');

  const record = {base: BASE, rootKey: C.toBase64(rootKey()), world: WORLD};
  const log = await claimsDocket(C, record, fakeFetch);
  assert.deepStrictEqual(log.entries.map(e => [e.type, e.docket]), [['office.receipt.v1', 1], ['office.decision.v1', 1], ['office.receipt.v1', 2]]);
  assert.deepStrictEqual([...claimsNow(log.entries).values()].map(c => c.partition), ['M-0412']);
  const pending = pendingKeyChanges(log.entries);
  assert.deepStrictEqual(pending.map(p => p.takesEffect.toISOString()), ['2026-10-21T08:00:00.000Z']);
  const officeKey = C.fromBase64(await registryKey(record));
  const more = await C.verifyLog(C.httpReader(`${BASE}omegeth.claims-office/${WORLD}/`, fakeFetch), officeKey,
                                 WORLD, ['office.receipt.v1', 'office.decision.v1'], [log.sequence, log.batchSha256]);
  assert.deepStrictEqual(more.entries, []);
  await assert.rejects(claimsDocket(C, {...record, rootKey: C.toBase64(new Uint8Array(32).fill(7))}, fakeFetch), e => e.reason === 'invalid_head');
  console.log('PASS: examples/docket.js reads the example record; nothing new after the head; another root key is refused');
})().catch(e => { console.error('FAIL:', e); process.exit(1); });

async function registryKey(record) {
  const reg = await C.verifyLog(C.httpReader(`${BASE}${C.ROOT_ISSUER}/${WORLD}/`, fakeFetch), C.fromBase64(record.rootKey), WORLD, [C.REGISTRY]);
  const registry = C.registryInForce(await C.registryVersions(reg.entries), '2026-10-20T00:00:00Z');
  return C.registryOffice(registry, 'omegeth.claims-office').keys[0].public_key_base64;
}
