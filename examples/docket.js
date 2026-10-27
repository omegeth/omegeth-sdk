'use strict';
/* Read and verify a world's Claims Office docket from the public record, and
 * work out the claims in force and any pending node key changes.
 *
 * In a page: load ../js/omegeth_contract.js first, then this file, and call
 * claimsDocket(OmegethContract). docket.html does exactly that.
 */
const RECORD = {
  base: 'https://docs.omegeth.com/log/',
  rootKey: 'tDJlaUGNOXxmggV4zAIZw3yiumN8CwJ9QIgIUGf3I1I=',   // pinned: compare with docs.omegeth.com/root.json
  world: 'lunar-2',
};
const CLAIMS_OFFICE = 'omegeth.claims-office';
const DAY_MS = 24 * 60 * 60 * 1000;

/** The verified docket: {sequence, batchSha256, entries}. Throws if it does not verify. */
async function claimsDocket(C, record = RECORD, fetchFn = globalThis.fetch) {
  // 1. The office registry for the world, signed by the root key.
  const reg = await C.verifyLog(C.httpReader(`${record.base}${C.ROOT_ISSUER}/${record.world}/`, fetchFn),
                                C.fromBase64(record.rootKey), record.world, [C.REGISTRY]);
  const registry = C.registryInForce(await C.registryVersions(reg.entries), Date.now());
  if (!registry) throw new Error('no registry in force yet');
  // 2. The office's log, verified with a key the registry gives it ...
  const office = C.registryOffice(registry, CLAIMS_OFFICE);
  if (!office) throw new Error('the registry names no Claims Office');
  let lastError = null;
  for (const key of office.keys) {
    try {
      const log = await C.verifyLog(C.httpReader(`${record.base}${CLAIMS_OFFICE}/${record.world}/`, fetchFn),
                                    C.fromBase64(key.public_key_base64), record.world, ['office.receipt.v1', 'office.decision.v1']);
      // 3. ... and each entry signed while the registry gave the office that key.
      for (const e of log.entries) {
        if (!(key.key_id in C.registryKeys(registry, CLAIMS_OFFICE, e.created_at))) {
          throw new Error(`docket ${e.docket}: signed outside the key's dates`);
        }
      }
      return log;
    } catch (e) { lastError = e; }      // a log is signed with one key: try the next
  }
  throw lastError;
}

/** The claims in force: Map claim_id -> {partition, actor_id, node_key}. */
function claimsNow(entries) {
  const claims = new Map();
  const decisions = entries.filter(e => e.type === 'office.decision.v1').sort((a, b) => a.docket - b.docket);
  for (const d of decisions) {
    if (d.outcome === 'GRANTED') claims.set(d.claim.claim_id, {partition: d.claim.partition, actor_id: d.actor_id, node_key: d.claim.node_key});
    else if (d.outcome === 'REKEYED') claims.get(d.rekey.claim_id).node_key = d.rekey.node_key;
  }
  return claims;
}

/** Node key changes received and not yet decided: [{docket, claim_id, actor_id, node_key, takesEffect}]. */
function pendingKeyChanges(entries) {
  const decided = new Set(entries.filter(e => e.type === 'office.decision.v1').map(e => e.docket));
  return entries.filter(e => e.type === 'office.receipt.v1' && e.action === 'claim.rekey' && e.status === 'RECEIVED' && !decided.has(e.docket))
    .map(e => ({docket: e.docket, claim_id: e.params.claim_id, actor_id: e.actor_id, node_key: e.params.node_key,
                takesEffect: new Date(Date.parse(e.received_at) + DAY_MS)}));
}

if (typeof module !== 'undefined') module.exports = {RECORD, claimsDocket, claimsNow, pendingKeyChanges};
