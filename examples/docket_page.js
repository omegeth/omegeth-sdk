'use strict';
// Fills docket.html from the verified record. Shows nothing it could not verify.
(async () => {
  const C = OmegethContract;
  const status = document.getElementById('status');
  const cell = text => { const td = document.createElement('td'); td.textContent = text; return td; };
  let log;
  try {
    log = await claimsDocket(C);
  } catch (e) {
    // After a world reset a cached batch may be stale: try once past the cache.
    try {
      log = await claimsDocket(C, RECORD, (url, options = {}) => fetch(url, {...options, cache: 'reload'}));
    } catch (again) {
      status.textContent = `The record did not verify: ${again.message}`;
      status.className = 'warn';
      return;
    }
  }
  const rootId = await C.keyId(C.fromBase64(RECORD.rootKey));
  status.textContent = `Verified ${log.entries.length} entries of world ${RECORD.world} from root key ${rootId}.`;
  const body = document.querySelector('#claims tbody');
  const claims = [...claimsNow(log.entries)].sort((a, b) => a[1].partition.localeCompare(b[1].partition));
  for (const [claimId, claim] of claims) {
    const row = document.createElement('tr');
    row.append(cell(claim.partition), cell(claimId), cell(await C.keyId(C.fromBase64(claim.node_key))));
    body.append(row);
  }
  document.getElementById('claims').hidden = false;
  const pending = pendingKeyChanges(log.entries);
  document.getElementById('pending-title').hidden = pending.length === 0;
  for (const p of pending) {
    const item = document.createElement('li');
    item.textContent = `Claim ${p.claim_id}: new node key ${await C.keyId(C.fromBase64(p.node_key))} takes over ${p.takesEffect.toISOString()} unless cancelled`;
    document.getElementById('pending').append(item);
  }
})();
