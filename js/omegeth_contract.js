'use strict';
/* Omegeth contract: the JavaScript reader, for pages and Node 20+.
 *
 * Verifies signed statements, public logs (head and hash-chained batches)
 * and the office registry, and makes and checks client keys' proofs of
 * possession, with WebCrypto Ed25519 (Chrome 137+, Firefox 129+, Safari 17+,
 * Node 20+). It signs nothing but proofs of possession.
 *
 * Copied unchanged wherever it is used, and checked against its SHA-256.
 * Every function here passes the same test vectors as the Python reader.
 */
const OmegethContract = (() => {
  const CONTRACT_VERSION = 4;
  const SIGNED_PREFIX = 'OMEGETH-SIGNED\0';
  const PROOF_PREFIX = 'OMEGETH-KEY-PROOF-V1\0';
  const WORLD = /^[a-z0-9][a-z0-9.-]{2,62}$/;
  const TYPE = /^[a-z][a-z0-9_.-]{2,80}$/;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/;
  const KEY_ID = /^[0-9a-f]{16}$/;
  const SHA256_HEX = /^[0-9a-f]{64}$/;
  const PURPOSE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
  const LOG_BATCH = 'log.batch.v1', LOG_HEAD = 'log.head.v1', BATCH_LIMIT = 1000;
  const REGISTRY = 'office.registry.v1', ROOT_ISSUER = 'omegeth.corporate-root';
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  const encoder = new TextEncoder();

  class InvalidStatement extends Error { constructor(reason, detail) { super(detail ? `${reason}: ${detail}` : reason); this.reason = reason; } }
  class InvalidLog extends Error { constructor(reason, detail) { super(detail ? `${reason}: ${detail}` : reason); this.reason = reason; } }
  class InvalidRegistry extends Error {}

  // Strict base64, as Python's b64decode(validate=True): the standard
  // alphabet, padded, nothing else.
  function fromBase64(text) {
    if (typeof text !== 'string' || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new TypeError('not base64');
    const binary = atob(text);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
  }
  function toBase64(bytes) {
    let binary = '';
    for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
    return btoa(binary);
  }
  const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
  async function sha256Hex(bytes) { return hex(await subtle.digest('SHA-256', typeof bytes === 'string' ? encoder.encode(bytes) : bytes)); }
  function concat(...parts) {
    const arrays = parts.map(p => typeof p === 'string' ? encoder.encode(p) : p);
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
    let at = 0;
    for (const a of arrays) { out.set(a, at); at += a.length; }
    return out;
  }
  /** The first 16 hex digits of SHA-256 of the raw 32-byte public key. */
  async function keyId(publicRaw) { return (await sha256Hex(publicRaw)).slice(0, 16); }
  function importPublic(publicRaw) { return subtle.importKey('raw', publicRaw, {name: 'Ed25519'}, false, ['verify']); }
  async function ed25519Verify(publicRaw, signature, data) {
    try { return await subtle.verify('Ed25519', await importPublic(publicRaw), signature, data); }
    catch (_) { return false; }
  }

  function commonFieldsProblem(st) {
    const checks = [['type', TYPE], ['world', WORLD], ['key_id', KEY_ID], ['publication_id', UUID], ['created_at', TIMESTAMP]];
    for (const [name, pattern] of checks) if (typeof st[name] !== 'string' || !pattern.test(st[name])) return `${name} missing or malformed`;
    if (typeof st.issuer !== 'string' || !st.issuer) return 'issuer missing';
    return null;
  }

  /** Check an envelope for one world and one type and return its statement.
   * Throws InvalidStatement (invalid_envelope, invalid_signature,
   * invalid_statement). The signature covers the statement bytes as received. */
  async function verify(publicRaw, world, type, envelopeJson) {
    let envelope;
    try { envelope = JSON.parse(envelopeJson); } catch (_) { throw new InvalidStatement('invalid_envelope', 'not JSON'); }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) || envelope.algorithm !== 'Ed25519'
        || typeof envelope.statement_json !== 'string' || typeof envelope.signature_base64 !== 'string') throw new InvalidStatement('invalid_envelope');
    const raw = encoder.encode(envelope.statement_json);
    let signature;
    try { signature = fromBase64(envelope.signature_base64); } catch (_) { throw new InvalidStatement('invalid_signature'); }
    if (!await ed25519Verify(publicRaw, signature, concat(SIGNED_PREFIX, world, '\0', type, '\0', raw))) throw new InvalidStatement('invalid_signature');
    let st;
    try { st = JSON.parse(envelope.statement_json); } catch (_) { throw new InvalidStatement('invalid_statement', 'not JSON'); }
    if (!st || typeof st !== 'object' || Array.isArray(st)) throw new InvalidStatement('invalid_statement', 'not an object');
    const problem = commonFieldsProblem(st);
    if (problem) throw new InvalidStatement('invalid_statement', problem);
    if (st.type !== type || st.world !== world || st.key_id !== await keyId(publicRaw)) throw new InvalidStatement('invalid_statement', 'type, world or key_id does not match');
    return st;
  }

  // -- the public log ------------------------------------------------------
  const batchPath = n => `batches/${String(n).padStart(8, '0')}.json`;
  function entryType(envelope) {
    try { return JSON.parse(JSON.parse(envelope).statement_json).type; } catch (_) { return null; }
  }
  /** Verify a world's log. `read(path)` resolves to the file's text, or null
   * when it is missing. Returns {sequence, batchSha256, entries}; with
   * `after` [sequence, sha256] from an earlier call, only what is newer. */
  async function verifyLog(read, publicRaw, world, entryTypes, after = null) {
    const types = new Set(entryTypes);
    const headText = await read('head.json');
    if (headText === null) throw new InvalidLog('invalid_head', 'head.json missing');
    let head;
    try { head = await verify(publicRaw, world, LOG_HEAD, headText); } catch (e) { throw new InvalidLog('invalid_head', e.message); }
    const last = head.sequence;
    if (!Number.isInteger(last) || last < 0 || !SHA256_HEX.test(String(head.batch_sha256))) throw new InvalidLog('invalid_head', 'sequence or batch_sha256 malformed');
    let start = 0, previous = null;
    if (after) {
      [start, previous] = [after[0] + 1, after[1]];
      if (last < after[0]) throw new InvalidLog('broken_chain', 'the head is older than what was already verified');
      if (last === after[0]) {
        if (head.batch_sha256 !== after[1]) throw new InvalidLog('broken_chain', 'the head names a different newest batch');
        return {sequence: last, batchSha256: after[1], entries: []};
      }
    }
    const entries = [];
    for (let n = start; n <= last; n++) {
      const text = await read(batchPath(n));
      if (text === null) throw new InvalidLog('missing_batch', batchPath(n));
      let batch;
      try { batch = await verify(publicRaw, world, LOG_BATCH, text); } catch (e) { throw new InvalidLog('invalid_batch', `${batchPath(n)}: ${e.message}`); }
      if (batch.sequence !== n || batch.previous_sha256 !== previous) throw new InvalidLog('broken_chain', batchPath(n));
      if (!Array.isArray(batch.entries) || batch.entries.length < 1 || batch.entries.length > BATCH_LIMIT) throw new InvalidLog('invalid_batch', `${batchPath(n)}: entries`);
      for (const envelope of batch.entries) {
        const claimed = typeof envelope === 'string' ? entryType(envelope) : null;
        if (!types.has(claimed)) throw new InvalidLog('unexpected_type', `${batchPath(n)}: ${claimed}`);
        try { entries.push(await verify(publicRaw, world, claimed, envelope)); } catch (e) { throw new InvalidLog('invalid_entry', `${batchPath(n)}: ${e.message}`); }
      }
      previous = await sha256Hex(text);
    }
    if (previous !== head.batch_sha256) throw new InvalidLog('broken_chain', 'the head does not name the newest batch');
    return {sequence: last, batchSha256: previous, entries};
  }
  /** A `read` for verifyLog over HTTP(S), e.g. https://docs.omegeth.com/log/<issuer>/<world>/ */
  function httpReader(base, fetchFn = globalThis.fetch) {
    return async path => {
      const res = await fetchFn(base + path, {cache: path === 'head.json' ? 'no-cache' : 'default'});
      if (res.status === 404) return null;
      if (!res.ok) throw new InvalidLog('missing_batch', `${path}: HTTP ${res.status}`);
      return res.text();
    };
  }

  // -- the office registry -------------------------------------------------
  // Contract timestamps to milliseconds, keeping microseconds as a fraction.
  function moment(text) {
    const m = typeof text === 'string' && TIMESTAMP.test(text) && text.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/);
    if (!m) throw new InvalidRegistry(`not a contract timestamp: ${text}`);
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) + Number((m[7] || '').padEnd(6, '0')) / 1000;
  }
  /** Check verified registry entries (versions 1, 2, 3 ... in order, well formed) and return them. */
  async function registryVersions(entries) {
    let previous = null;
    for (const [i, v] of entries.entries()) {
      const n = i + 1;
      if (v.type !== REGISTRY || v.issuer !== ROOT_ISSUER || v.version !== n) throw new InvalidRegistry(`entry ${n} is not registry version ${n}`);
      const effective = moment(v.effective_from);
      if (previous !== null && effective < previous) throw new InvalidRegistry(`version ${n} takes effect before version ${n - 1}`);
      previous = effective;
      if (!Array.isArray(v.offices) || !v.offices.length) throw new InvalidRegistry(`version ${n}: no offices`);
      const ids = v.offices.map(o => o && o.id);
      if (new Set(ids).size !== ids.length) throw new InvalidRegistry(`version ${n}: an office is listed twice`);
      for (const o of v.offices) {
        const keysOk = Array.isArray(o.keys) && o.keys.length > 0;
        const prefixesOk = Array.isArray(o.action_prefixes) && o.action_prefixes.every(p => typeof p === 'string' && /^[a-z][a-z0-9_]*\.$/.test(p))
          && (o.role === 'office') === (o.action_prefixes.length > 0);
        if (Object.keys(o).sort().join() !== 'action_prefixes,id,keys,role' || !/^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$/.test(o.id)
            || !['identity', 'office'].includes(o.role) || !prefixesOk || !keysOk) throw new InvalidRegistry(`version ${n}, ${o.id}: malformed`);
        for (const k of o.keys) {
          let raw;
          try { raw = fromBase64(k.public_key_base64); } catch (_) { throw new InvalidRegistry(`version ${n}, ${o.id}: a key is malformed`); }
          const start = moment(k.from), until = k.until === null ? null : moment(k.until);
          if (Object.keys(k).sort().join() !== 'from,key_id,public_key_base64,until' || raw.length !== 32
              || k.key_id !== await keyId(raw) || (until !== null && until <= start)) throw new InvalidRegistry(`version ${n}, ${o.id}: a key is malformed`);
        }
      }
    }
    return entries;
  }
  const atMs = at => typeof at === 'string' ? moment(at) : (at instanceof Date ? at.getTime() : at);
  function registryInForce(versions, at) {
    let current = null;
    for (const v of versions) if (moment(v.effective_from) <= atMs(at)) current = v;
    return current;
  }
  const registryOffice = (registry, id) => registry.offices.find(o => o.id === id) || null;
  /** {key_id: raw public key} for the office's keys valid at `at`. */
  function registryKeys(registry, id, at) {
    const t = atMs(at), out = {}, office = registryOffice(registry, id);
    for (const k of (office ? office.keys : [])) {
      if (moment(k.from) <= t && (k.until === null || t < moment(k.until))) out[k.key_id] = fromBase64(k.public_key_base64);
    }
    return out;
  }

  // -- client keys -------------------------------------------------------------
  function keyProofBytes(world, purpose, subject) {
    if (!WORLD.test(world || '') || !PURPOSE.test(purpose || '') || typeof subject !== 'string' || subject.includes('\0')) throw new TypeError('invalid world, purpose or subject');
    return concat(PROOF_PREFIX, world, '\0', purpose, '\0', subject);
  }
  /** Sign a proof of possession with a WebCrypto Ed25519 private key. Base64. */
  async function signKeyProof(privateKey, world, purpose, subject) {
    return toBase64(await subtle.sign('Ed25519', privateKey, keyProofBytes(world, purpose, subject)));
  }
  /** True when the proof is the key's signature over this world, purpose and subject. */
  async function verifyKeyProof(publicKeyB64, proofB64, world, purpose, subject) {
    let raw, signature, data;
    try { raw = fromBase64(publicKeyB64); signature = fromBase64(proofB64); data = keyProofBytes(world, purpose, subject); }
    catch (_) { return false; }
    if (raw.length !== 32 || signature.length !== 64) return false;
    return ed25519Verify(raw, signature, data);
  }

  return {CONTRACT_VERSION, InvalidStatement, InvalidLog, InvalidRegistry, fromBase64, toBase64, sha256Hex, keyId, verify,
          batchPath, verifyLog, httpReader, registryVersions, registryInForce, registryOffice, registryKeys,
          keyProofBytes, signKeyProof, verifyKeyProof, LOG_BATCH, LOG_HEAD, REGISTRY, ROOT_ISSUER};
})();
if (typeof module !== 'undefined') module.exports = OmegethContract;
