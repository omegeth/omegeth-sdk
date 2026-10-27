# Building on Omegeth

A guide for third-party developers. Updated 27 October 2026.

## What you can build on

Omegeth offers third parties one interface: a public, signed, read-only record at docs.omegeth.com, which anyone may read and verify without an account or a key. Services that need a player to act (register, file a claim) send the player to an Omegeth page. There is no write API, no sign-in for third-party sites, and no push notification.

| Available | What it gives you | How |
| --- | --- | --- |
| The public record | Every claim filed and every decision made in a world, and the directory of registered players | Static JSON over HTTPS, readable from any origin |
| The corporate root key | The single key from which everything in the record can be verified | Published in three places; pin it |
| Links to Omegeth pages | A way to send players to register, see their claims, or manage their node | Plain links |

| Not available | What to do instead |
| --- | --- |
| An API that changes anything | Link the player to the Omegeth page that does it |
| Signing players in with Omegeth | Not offered. Show public data by actor ID or partition |
| Webhooks or push | Re-read the record; new entries appear within about a minute of being published |
| Private data (email addresses, credentials) | Never exposed. Actor IDs reveal nothing about the person |

Typical value-add services: claim maps and explorers, partition availability, statistics and leaderboards, independent audits of the Claims Office's decisions, and alerts for players watching a claim or a partition.

## The public record

The record is a set of append-only logs, one per issuer and world, served as static files. Each file is signed, so its trustworthiness comes from the signatures, not from the host or any cache between you and it.

```text
https://docs.omegeth.com/root.json                                   the corporate root key
https://docs.omegeth.com/log/index.json                              the logs currently published
https://docs.omegeth.com/log/<issuer>/<world>/head.json              the newest batch's number and hash
https://docs.omegeth.com/log/<issuer>/<world>/batches/00000000.json  batches, numbered from 0, 8 digits
```

**Worlds.** A world is one run of the game, and everything in the record belongs to exactly one world. The current game world is `lunar-2`; players' identities are in `world-a.0`. When a world ends, its logs stay published as an archive and a new world starts with new logs. Make the world a setting in your service.

**Issuers.**

| Issuer | Publishes | Entry types |
| --- | --- | --- |
| `omegeth.corporate-root` | The office registry for each game world: which offices exist and their keys | `office.registry.v1` |
| `omegeth.claims-office` | Every claim command received and every decision | `office.receipt.v1`, `office.decision.v1` |
| `omegeth.identity-office` | The directory of registered players | `identity.actor.v1` |

**Files.**

| File | Changes | Cache-Control |
| --- | --- | --- |
| `head.json` | When a batch is added | `public, max-age=60` |
| `batches/NNNNNNNN.json` | Never | `public, max-age=31536000, immutable` |
| `log/index.json`, `root.json` | Occasionally | `public, max-age=60` |

Every response, a 404 included, carries `Access-Control-Allow-Origin: *`, so a web page on any domain can read the record directly. `index.json` and `root.json` are unsigned conveniences; never treat them as proof of anything.

**The root key.** Key ID `7c8106e7b87c3746`, public key (Ed25519, base64):

```text
tDJlaUGNOXxmggV4zAIZw3yiumN8CwJ9QIgIUGf3I1I=
```

It is published at docs.omegeth.com/root.json, on the record's home page, and on the home page of omegeth.com. Check that they agree, then pin it in your service's configuration.

**Statements.** Every entry is an envelope:

```json
{"algorithm": "Ed25519", "statement_json": "{...}", "signature_base64": "..."}
```

The signature covers `"OMEGETH-SIGNED\0" + world + "\0" + type + "\0" + statement_json`, using the exact published bytes of `statement_json`. Every statement includes `type`, `world`, `issuer`, `key_id` (first 16 hex digits of SHA-256 of the signer's raw public key), `publication_id` and `created_at` (UTC). Batches are signed the same way, and each names the SHA-256 of the batch before it, so an entry cannot be removed or reordered without detection.

## Verifying the record

Verify before you display or compute anything: start from the pinned root key, verify the registry for the world, take the office's key from the registry, then verify the office's log. Omegeth provides small reference libraries that do each step, with no dependencies beyond Ed25519 and SHA-256.

They are in this repository, with test vectors and runnable examples:

| Path | What it is |
| --- | --- |
| `js/omegeth_contract.js` | The browser reader (WebCrypto Ed25519: Chrome 137+, Firefox 129+, Safari 17+). Load it as a script; it defines `OmegethContract` |
| `python/omegeth_reader.py` | The Python reader, for Python 3.10+ with the `cryptography` package |
| `examples/` | `docket.html`, `docket.js` and `docket.py`: the code in this guide, ready to run |
| `vectors/` | Statements, proofs of possession and a small example record that every reader must handle exactly as the tests say |

Copy the reader you need into your project unchanged; the repository's tests check each copy against its recorded SHA-256.

**In a browser:**

```javascript
const C = OmegethContract;
const BASE = 'https://docs.omegeth.com/log/';
const ROOT_KEY = 'tDJlaUGNOXxmggV4zAIZw3yiumN8CwJ9QIgIUGf3I1I=';   // pinned
const WORLD = 'lunar-2', OFFICE = 'omegeth.claims-office';

async function claimsDocket() {
  // 1. The office registry for the world, signed by the root key.
  const reg = await C.verifyLog(C.httpReader(`${BASE}${C.ROOT_ISSUER}/${WORLD}/`), C.fromBase64(ROOT_KEY), WORLD, [C.REGISTRY]);
  const registry = C.registryInForce(await C.registryVersions(reg.entries), Date.now());
  if (!registry) throw new Error('no registry in force yet');
  // 2. The office's log, verified with a key the registry gives it ...
  const office = C.registryOffice(registry, OFFICE);
  let lastError = null;
  for (const key of office.keys) {
    try {
      const log = await C.verifyLog(C.httpReader(`${BASE}${OFFICE}/${WORLD}/`), C.fromBase64(key.public_key_base64), WORLD,
                                    ['office.receipt.v1', 'office.decision.v1']);
      // 3. ... and each entry signed while the registry gave the office that key.
      for (const e of log.entries)
        if (!(key.key_id in C.registryKeys(registry, OFFICE, e.created_at))) throw new Error(`docket ${e.docket}: signed outside the key's dates`);
      return log;                       // {sequence, batchSha256, entries}
    } catch (e) { lastError = e; }      // a log is signed with one key: try the next
  }
  throw lastError;
}
```

Your page's Content Security Policy needs `connect-src https://docs.omegeth.com`.

**In Python:**

```python
import base64, urllib.error, urllib.request
from datetime import datetime, timezone
import omegeth_reader as C

BASE = 'https://docs.omegeth.com/log/'
ROOT_KEY = base64.b64decode('tDJlaUGNOXxmggV4zAIZw3yiumN8CwJ9QIgIUGf3I1I=')
WORLD, OFFICE = 'lunar-2', 'omegeth.claims-office'

def http_reader(base):
    def read(relative):
        try:
            with urllib.request.urlopen(base + relative, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
    return read

def claims_docket():
    root_log = C.verify_log(http_reader(f'{BASE}{C.ROOT_ISSUER}/{WORLD}/'), ROOT_KEY, WORLD, {C.REGISTRY})
    registry = C.registry_in_force(C.registry_versions(root_log['entries']), datetime.now(timezone.utc))
    if registry is None:
        raise SystemExit('no registry in force yet')
    last = None
    for key in C.registry_office(registry, OFFICE)['keys']:
        try:
            log = C.verify_log(http_reader(f'{BASE}{OFFICE}/{WORLD}/'), base64.b64decode(key['public_key_base64']),
                               WORLD, {'office.receipt.v1', 'office.decision.v1'})
        except C.InvalidLog as exc:
            last = exc
            continue
        for e in log['entries']:
            if key['key_id'] not in C.registry_keys(registry, OFFICE, e['created_at']):
                raise SystemExit(f"docket {e['docket']}: signed outside the key's dates")
        return log
    raise last
```

**Staying current.** Keep the `sequence` and batch hash from your last verification and pass them as `after` (`[sequence, batchSha256]` in JavaScript, `(sequence, batch_sha256)` in Python). The library then fetches the head and only the newer batches, and returns only new entries.

**When verification fails,** the library raises `InvalidLog` with a reason: `invalid_head`, `missing_batch`, `invalid_batch`, `broken_chain`, `invalid_entry` or `unexpected_type`. Show nothing from that log. After a new world starts, a browser or proxy may hold an old cached batch; retry once bypassing the cache (`fetch(url, {cache: 'reload'})`, passed to `httpReader(base, fetchFn)`) before reporting a failure.

## The data

The current state of every claim is the Claims Office's decisions replayed in docket order. A claim's node key is the one it was granted with, replaced by each later `REKEYED` decision for it. Because decisions follow published rules from the receipts alone, an independent service can recompute and audit every one.

**Receipts** (`office.receipt.v1`): one per claim command received, numbered by `docket` from 1 with no gaps, each chained to the previous one by `previous_receipt_sha256`.

| Field | Meaning |
| --- | --- |
| `docket` | The receipt's number; a refused command still gets one |
| `status`, `reason` | `RECEIVED` with `null`, or `REFUSED` with a reason |
| `received_at` | When it was received; decision times count from here |
| `command_id` | The command's ID; the decision carries the same one |
| `actor_id` | The player who made it |
| `action`, `params` | What was asked: `claim.file` (`partition`, `node_key`), `claim.rekey` (`claim_id`, `node_key`), `claim.cancel` (`command_id`) |

**Decisions** (`office.decision.v1`) carry `docket`, `command_id`, `actor_id`, `action`, `outcome`, `reason` and `decided_at`, plus:

| Outcome | Applies to | Extra fields |
| --- | --- | --- |
| `GRANTED` | `claim.file` | `claim`: `claim_id`, `partition`, `region`, `ruleset`, `node_key` |
| `REKEYED` | `claim.rekey` | `rekey`: `claim_id`, `partition`, `node_key` (the new key) |
| `CANCELLED` | `claim.cancel` | `target_docket`: the filing or rekey it withdrew |
| `WITHDRAWN` | `claim.file`, `claim.rekey` | `cancelled_by`: the cancel's docket |
| `DENIED` | Any | `reason`: `partition_taken`, `claim_limit`, `not_found`, `not_yours`, `not_cancellable`, `already_cancelled`, `too_late` |

**The claims in force:**

```javascript
function claimsNow(entries) {
  const claims = new Map();               // claim_id -> {partition, actor_id, node_key}
  const decisions = entries.filter(e => e.type === 'office.decision.v1').sort((a, b) => a.docket - b.docket);
  for (const d of decisions) {
    if (d.outcome === 'GRANTED') claims.set(d.claim.claim_id, {partition: d.claim.partition, actor_id: d.actor_id, node_key: d.claim.node_key});
    else if (d.outcome === 'REKEYED') claims.get(d.rekey.claim_id).node_key = d.rekey.node_key;
  }
  return claims;
}
```

A `claim.rekey` receipt that is `RECEIVED` with no decision yet is a pending key change. It takes effect 24 hours after `received_at` unless the holder cancels it, which makes it worth showing in any service that watches claims.

**The rules in `lunar-2` (ruleset thin-3):**

- A partition is a capital letter, a hyphen and four digits (`M-0412`). There is one region, `open`.
- Filings and cancels are decided 5 minutes after receipt. Key changes are decided 24 hours after.
- The first filing for a partition wins. Each player may hold one claim.
- Claims are not transferable.

**The actor directory** (`omegeth.identity-office`, world `world-a.0`) holds one `identity.actor.v1` entry per registered player: `actor_id`, `designation` (the name they registered) and `activated_at`. Verify it like any other log, with the key the registry of the game world gives `omegeth.identity-office`, accepting only `identity.actor.v1`. Use it to show a designation beside an actor ID.

## Sending players to Omegeth

When a player wants to act, link them to the Omegeth page that does it. Players approve every action with their own passkey on Omegeth's pages, so your service never handles credentials and needs no permission to link.

| The player wants to | Link to |
| --- | --- |
| Register, or see their account | `https://omegeth.com/oic/` |
| See their claims, filings and pending key changes; cancel a filing; replace a node key | `https://omegeth.com/claims/` |
| Make a node key and file a claim | `https://lunardig.com/node/` |

Use plain links and open them in a new top-level tab or window. Omegeth's pages cannot be embedded in frames.

A filing starts at lunardig.com/node/, where the player's node key is made and kept. Do not build filing links yourself: a filing is bound to a key only the player's node holds.

A service that watches the record can tell a player when to act, for example when a key change is pending on their claim, or a partition they want is still free. It then links them to the page that acts.

## Ground rules and change policy

Read the record only from docs.omegeth.com, verify it before you use it, and leave players' actions to Omegeth's pages.

1. **Read from docs.omegeth.com only.** Omegeth's pages on omegeth.com are for players. Automated requests to them are not supported and may be blocked.
2. **Read politely.** Fetch each `head.json` at most once a minute, fetch only batches you do not have, and cache batches indefinitely. A server-side service that shares one copy of the record among its users is preferred to every user's browser fetching it.
3. **Pin the root key.** Do not fetch it at run time as your anchor. When you show verified data, show the root key ID you verified from.
4. **Verify before you show.** Show nothing from a log that fails, and say why.
5. **Never ask players for credentials.** Do not ask for a passkey, an email code, or anything else Omegeth's pages ask for, and do not imitate Omegeth's pages or branding.
6. **Respect pseudonymity.** Actor IDs and designations are public; the people behind them are not. Do not try to link one to the other.

**Change policy.** Omegeth is a research project. Worlds are reset, and a new world may bring new formats with no compatibility with the old. A reset is visible in the record: a new world name, a new registry and new logs, with the old world's logs kept as an archive. Keep the world name and the expected entry types in configuration, and treat an `unexpected_type` failure as a sign that a format has changed.
