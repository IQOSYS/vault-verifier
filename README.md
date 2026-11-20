# IQOSYS Vault verifier

Checks an IQOSYS proof of origin without IQOSYS: with SHA-256 and a public Polygon node only. It keeps working if IQOSYS stops operating.

It needs either a PDF sealed by IQOSYS (the proof is attached to it), or the registered document and its public proof `iqosys-proof-<reference>.json`.

## What it checks

1. **The document.** For a sealed PDF, the original is every byte before the line `% IQOSYS proof seal <reference>` (without the line feed before it). Its SHA-256 must be one of the fingerprints in the proof.
2. **The tree leaf.** `SHA-256("iqosys-vault-leaf:v1|<subject type>|<subject id>|<fingerprint in lowercase>")` must equal the proof's `tree_leaf`.
3. **The Merkle proof.** `h = SHA-256(0x00 || leaf)`, then for each proof hash `p`, in order, `h = SHA-256(0x01 || min(h, p) || max(h, p))`, comparing 32-byte values. The last `h` must equal the `merkle_root`.
4. **The blockchain.** On the HashRegistry contract, `getHashRecord(0x<root>)` must return `exists = true` with the registry entry of the proof (`VAULT_BATCH <batch id>`); its timestamp is the time the root was recorded. `isHashSuperseded(0x<root>)` must be false. The transaction must send this root to the registry.
5. **The registry.** The contract must be one IQOSYS has published (`KNOWN_REGISTRIES` in `verifier.mjs`, and the deployments listed in [IQOSYS/smart-contracts](https://github.com/IQOSYS/smart-contracts#deployments)).

Every step can also be done by hand with any SHA-256 tool and a Polygon explorer ("Read Contract" on the registry).

## Use it

In a browser: open `index.html` from any static web server (or the published page), choose the file, then **Verify**. The file is read in the page and never sent.

From a terminal (Node.js 20 or later, no dependency to install):

```sh
node cli.mjs my-document-sealed.pdf
node cli.mjs my-document.docx --proof iqosys-proof-SEC-XXXXXXXXXX.json
node cli.mjs my-document-sealed.pdf --rpc https://your-polygon-node
```

The exit code is 0 when every check passes.

## What it proves, and what it does not

A verified proof shows that this exact file existed when its batch root was recorded on Polygon, and that IQOSYS recorded it under that reference. It does not show who wrote the document or who owns its content: the signed declaration and the identity checks are separate evidence.

## Tests

```sh
node --test test/*.test.mjs
```

The sample in `test/fixtures` has random hashes and an invented contract and transaction; the tests answer for the blockchain with a simulated node.

## Licence

MIT
