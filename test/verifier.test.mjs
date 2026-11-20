import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { attachedProof, merkleRoot, originalPart, sha256, toHex, treeLeaf, verify } from "../verifier.mjs";

const sealed = new Uint8Array(await readFile(new URL("./fixtures/sample-sealed.pdf", import.meta.url)));
const proof = await attachedProof(sealed);
const anchor = proof.anchors[0];

/** A Polygon node answering for one root, ABI-encoded as HashRegistry.getHashRecord returns it. */
const fakeNode = ({ exists = true, superseded = false, chainId = 137 } = {}) => async (url, request) => {
    const { method, params } = JSON.parse(request.body);
    const word = (value) => BigInt(value).toString(16).padStart(64, "0");
    const known = params?.[0]?.data?.endsWith(anchor.merkle_root);
    const results = {
        eth_chainId: `0x${chainId.toString(16)}`,
        eth_call: params?.[0]?.data?.startsWith("0x60e2c2d0")
            ? `0x${word(exists && known ? 1 : 0)}${word("0x" + "11".repeat(20))}${word(1795171771)}${word(160)}${word(3917)}${word(11)}${Buffer.from("VAULT_BATCH").toString("hex").padEnd(64, "0")}`
            : `0x${word(superseded ? 1 : 0)}`,
        eth_getTransactionByHash: { to: anchor.chain.registry_address, blockNumber: "0x4bbbaaf", input: `0x0000${anchor.merkle_root}` },
        eth_getTransactionReceipt: { status: "0x1" },
    };
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: results[method] }));
};

test("the original part of a sealed PDF is cut before the seal line and matches the proof", async () => {
    const original = originalPart(sealed);
    assert.ok(original && original.length < sealed.length);
    assert.equal(toHex(await sha256(original)), proof.secret.document_sha256);
    assert.equal(originalPart(original), null, "the original holds no seal");
});

test("the leaf and the Merkle root are recomputed from the printed rules", async () => {
    const leaf = await treeLeaf(anchor);
    assert.equal(leaf, anchor.tree_leaf);
    assert.equal(await merkleRoot(leaf, anchor.proof), anchor.merkle_root);
    assert.notEqual(await merkleRoot(leaf, [...anchor.proof].reverse()), anchor.merkle_root, "the order of the proof matters");
});

test("a sealed PDF is verified end to end against the registry", async () => {
    globalThis.fetch = fakeNode();
    const result = await verify({ file: sealed, rpcUrl: "https://node.example" });
    const failed = result.checks.filter((check) => !check.ok).map((check) => check.label);
    // The sample's registry is invented, so only the published-list check fails.
    assert.equal(failed.length, 1);
    assert.match(failed[0], /not in this verifier's published list/);
    assert.ok(result.checks.some((check) => check.ok && /Root recorded on chain 137 at 2026-11-20T10:49:31Z/.test(check.label)));
    assert.ok(result.checks.some((check) => check.ok && check.label === "Registry entry VAULT_BATCH 3917"));
});

test("a modified document, an unknown root, a superseded root and a wrong chain fail", async () => {
    globalThis.fetch = fakeNode();
    const changed = sealed.slice();
    changed[200] ^= 1;
    assert.ok((await verify({ file: changed, rpcUrl: "https://node.example" })).checks.some((check) => !check.ok && /not the registered document/.test(check.label)));

    globalThis.fetch = fakeNode({ exists: false });
    assert.ok((await verify({ file: sealed, rpcUrl: "https://node.example" })).checks.some((check) => !check.ok && /Root not found/.test(check.label)));

    globalThis.fetch = fakeNode({ superseded: true });
    assert.ok((await verify({ file: sealed, rpcUrl: "https://node.example" })).checks.some((check) => !check.ok && /superseded/.test(check.label)));

    globalThis.fetch = fakeNode({ chainId: 1 });
    assert.ok((await verify({ file: sealed, rpcUrl: "https://node.example" })).checks.some((check) => !check.ok && /not reachable/.test(check.label)));
});

test("a sealed PDF without its attachment asks for the JSON, and the API's {data} wrapper is accepted", async () => {
    const original = originalPart(sealed);
    const bare = new Uint8Array([...original, ...new TextEncoder().encode("\n% IQOSYS proof seal SEC-RJ4FVXHZAH\n%%EOF\n")]);
    const result = await verify({ file: bare });
    assert.match(result.checks.at(-1).label, /no proof attached/);

    globalThis.fetch = fakeNode();
    const wrapped = await verify({ file: bare, proof: { data: proof }, rpcUrl: "https://node.example" });
    assert.ok(wrapped.checks.some((check) => check.ok && check.label === "The document's SHA-256 is in the proof"));
});
