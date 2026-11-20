// IQOSYS Vault verifier: checks an IQOSYS proof of origin with SHA-256 and a public Polygon node only.
// No IQOSYS server is contacted. Runs unchanged in a browser and in Node.js 20 or later. MIT licence.

/** HashRegistry contracts IQOSYS has published, by chain ID. A proof naming another contract is reported. */
export const KNOWN_REGISTRIES = {
    80002: ["0x57d9f03da08de4448053a695031d50e6fc821dde"],
    137: ["0xeda7f04d01734658b054a5cb6a6af8caa5e904db"],
};

/** Public JSON-RPC nodes tried in turn when none is given. Any Polygon node gives the same answer. */
export const PUBLIC_RPCS = {
    137: ["https://polygon-bor-rpc.publicnode.com", "https://polygon-rpc.com"],
    80002: ["https://polygon-amoy-bor-rpc.publicnode.com", "https://rpc-amoy.polygon.technology"],
};

/** Function selectors: the first 4 bytes of keccak-256 of the signature (`cast sig "getHashRecord(bytes32)"`). */
const SELECTOR = {
    getHashRecord: "60e2c2d0",
    isHashSuperseded: "80d36c8a",
};

/** The line the IQOSYS seal starts with: everything before it is the original document, byte for byte. */
export const SEAL_MARKER = "\n% IQOSYS proof seal ";

const LEAF_TAG = "iqosys-vault-leaf:v1";
const encoder = new TextEncoder();

export const toHex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
export const fromHex = (hex) => {
    const clean = hex.replace(/^0x/i, "");
    if (!/^([0-9a-fA-F]{2})*$/.test(clean)) throw new Error(`not hexadecimal: ${hex}`);
    return Uint8Array.from(clean.match(/../g) ?? [], (pair) => parseInt(pair, 16));
};
const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let at = 0;
    for (const part of parts) {
        out.set(part, at);
        at += part.length;
    }
    return out;
};
const compare = (left, right) => {
    for (let index = 0; index < left.length; index++) if (left[index] !== right[index]) return left[index] - right[index];
    return 0;
};

export const sha256 = async (bytes) => new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));

const indexOf = (bytes, pattern, from = 0) => {
    const needle = encoder.encode(pattern);
    outer: for (let index = from; index <= bytes.length - needle.length; index++) {
        for (let offset = 0; offset < needle.length; offset++) if (bytes[index + offset] !== needle[offset]) continue outer;
        return index;
    }
    return -1;
};
const latin1 = (bytes) => Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");

/** The original document inside a sealed PDF: the bytes before the seal line. Null when the file holds no IQOSYS seal. */
export const originalPart = (bytes) => {
    const at = indexOf(bytes, SEAL_MARKER);
    return at < 0 ? null : bytes.subarray(0, at);
};

const inflate = async (bytes) => {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
};

/**
 * The public proof the seal attached to the PDF (`iqosys-proof-SEC-....json`): read from the embedded
 * files of the seal revision. Null when there is none; the proof can then be given separately.
 */
export const attachedProof = async (bytes) => {
    const seal = indexOf(bytes, SEAL_MARKER);
    if (seal < 0) return null;
    for (let at = indexOf(bytes, "/EmbeddedFile", seal); at >= 0; at = indexOf(bytes, "/EmbeddedFile", at + 1)) {
        const start = indexOf(bytes, "stream", at);
        if (start < 0) break;
        const dictionary = latin1(bytes.subarray(Math.max(seal, at - 512), start));
        if (!/\/Type\s*\/EmbeddedFile\b/.test(dictionary)) continue;
        const length = /\/Length\s+(\d+)(?!\s+\d+\s+R)/.exec(dictionary);
        let dataStart = start + "stream".length;
        if (bytes[dataStart] === 13) dataStart++;
        if (bytes[dataStart] === 10) dataStart++;
        const dataEnd = length ? dataStart + Number(length[1]) : indexOf(bytes, "endstream", dataStart);
        let data = bytes.subarray(dataStart, dataEnd);
        try {
            if (/\/Filter\s*\/FlateDecode/.test(dictionary)) data = await inflate(data);
            const proof = JSON.parse(new TextDecoder().decode(data));
            if (typeof proof?.format === "string" && Array.isArray(proof.anchors)) return proof;
        } catch {
            // Not the proof: look further.
        }
    }
    return null;
};

/** SHA-256 of "iqosys-vault-leaf:v1|<subject type>|<subject id>|<record hash>". */
export const treeLeaf = async (anchor) =>
    toHex(await sha256(encoder.encode(`${LEAF_TAG}|${anchor.subject_type}|${anchor.subject_id}|${anchor.record_sha256.toLowerCase()}`)));

/** Climbs the Merkle tree: H(0x00 || leaf), then H(0x01 || smaller || larger) with each proof hash. */
export const merkleRoot = async (leaf, proof) => {
    let node = await sha256(concat(Uint8Array.of(0), fromHex(leaf)));
    for (const sibling of proof) {
        const other = fromHex(sibling);
        if (other.length !== 32) throw new Error(`a proof hash is not 32 bytes: ${sibling}`);
        const [low, high] = compare(node, other) <= 0 ? [node, other] : [other, node];
        node = await sha256(concat(Uint8Array.of(1), low, high));
    }
    return toHex(node);
};

const rpc = async (url, method, params) => {
    const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
    const body = await response.json();
    if (body.error) throw new Error(`${url}: ${body.error.message ?? "error"}`);
    return body.result;
};

const word = (data, index) => data.slice(2 + index * 64, 2 + (index + 1) * 64);

/** Reads `getHashRecord(root)` and `isHashSuperseded(root)` on the registry, and the transaction, from one node. */
export const readChain = async ({ rpcUrl, chainId, registry, root, txHash }) => {
    const reported = Number(BigInt(await rpc(rpcUrl, "eth_chainId", [])));
    if (reported !== chainId) throw new Error(`${rpcUrl} is chain ${reported}, not ${chainId}`);
    const call = (selector) => rpc(rpcUrl, "eth_call", [{ to: registry, data: `0x${selector}${root.replace(/^0x/, "").toLowerCase()}` }, "latest"]);

    const record = await call(SELECTOR.getHashRecord);
    if (!record || record.length < 2 + 5 * 64) throw new Error("the registry gave no record: wrong contract address or chain");
    const exists = BigInt(`0x${word(record, 0)}`) === 1n;
    const submitter = `0x${word(record, 1).slice(24)}`;
    const timestamp = Number(BigInt(`0x${word(record, 2)}`));
    const stringAt = Number(BigInt(`0x${word(record, 3)}`)) / 32;
    const length = Number(BigInt(`0x${word(record, stringAt)}`));
    const referenceType = new TextDecoder().decode(fromHex(record.slice(2 + (stringAt + 1) * 64, 2 + (stringAt + 1) * 64 + length * 2)));
    const referenceId = BigInt(`0x${word(record, 4)}`).toString();
    const superseded = BigInt(await call(SELECTOR.isHashSuperseded)) === 1n;

    let transaction = null;
    if (txHash) {
        const tx = await rpc(rpcUrl, "eth_getTransactionByHash", [txHash]);
        const receipt = tx ? await rpc(rpcUrl, "eth_getTransactionReceipt", [txHash]) : null;
        transaction = tx && {
            to: (tx.to ?? "").toLowerCase(),
            block: tx.blockNumber ? Number(BigInt(tx.blockNumber)) : null,
            carriesRoot: (tx.input ?? "").toLowerCase().includes(root.replace(/^0x/, "").toLowerCase()),
            succeeded: receipt ? receipt.status === "0x1" : null,
        };
    }
    return { exists, submitter, timestamp, referenceType, referenceId, superseded, transaction };
};

/**
 * Checks a proof. `file` (optional) is the registered document or a sealed PDF; `proof` is the public
 * proof JSON (taken from the sealed PDF when not given). Returns every check, passed or failed.
 */
export const verify = async ({ file, proof, rpcUrl } = {}) => {
    // The proof as the IQOSYS API returns it ({"data": {...}}) is accepted too.
    if (proof && !Array.isArray(proof.anchors) && proof.data && Array.isArray(proof.data.anchors)) proof = proof.data;
    const checks = [];
    const check = (ok, label, detail = "") => checks.push({ ok, label, detail });

    let original = null;
    if (file) {
        original = originalPart(file);
        check(true, original ? "The file is a sealed PDF: its original part is checked" : "The file is checked as the original document");
        proof ??= await attachedProof(file);
        if (original && proof) check(true, "Public proof read from the PDF's attachment");
        if (original && !proof) {
            check(false, "This sealed PDF has no proof attached (sealed before IQOSYS attached it, or the attachment was removed): give the JSON file iqosys-proof-....json");
            return { ok: false, checks, proof: null };
        }
    }
    if (!proof) {
        check(false, "No public proof: give the JSON file (iqosys-proof-....json) or a PDF sealed by IQOSYS");
        return { ok: false, checks, proof: null };
    }

    const record = proof.kind === "contribution" ? proof.contribution : proof.secret;
    if (record?.reference) check(true, `Reference ${record.reference}`);
    if (file) {
        const fingerprint = toHex(await sha256(original ?? file));
        const matches = proof.anchors.some((anchor) => anchor.record_sha256?.toLowerCase() === fingerprint)
            || (proof.contribution?.file_sha256s ?? []).includes(fingerprint);
        check(matches, matches ? "The document's SHA-256 is in the proof" : "The document's SHA-256 is not in the proof: this is not the registered document", fingerprint);
    }

    const roots = new Map();
    for (const anchor of proof.anchors) {
        const name = `${anchor.record} (${anchor.record_sha256.slice(0, 12)}…)`;
        if (anchor.status !== "anchored" || !anchor.merkle_root || !anchor.chain) {
            check(false, `${name}: not anchored on a blockchain yet`, anchor.status);
            continue;
        }
        const leaf = await treeLeaf(anchor);
        check(leaf === anchor.tree_leaf.toLowerCase(), `${name}: tree leaf recomputed`, leaf);
        const root = await merkleRoot(leaf, anchor.proof ?? []);
        check(root === anchor.merkle_root.toLowerCase(), `${name}: Merkle proof leads to the root`, root);
        roots.set(`${anchor.chain.chain_id}|${anchor.chain.registry_address}|${root}`, anchor.chain);
    }

    for (const [key, chain] of roots) {
        const [, , root] = key.split("|");
        const chainId = Number(chain.chain_id);
        const registry = (chain.registry_address ?? "").toLowerCase();
        const known = (KNOWN_REGISTRIES[chainId] ?? []).includes(registry);
        check(known, known ? `Registry ${registry} is a published IQOSYS HashRegistry (chain ${chainId})` : `Registry ${registry} on chain ${chainId} is not in this verifier's published list: check it independently`);
        const urls = rpcUrl ? [rpcUrl] : (PUBLIC_RPCS[chainId] ?? []);
        let onChain = null;
        let lastError = null;
        for (const url of urls) {
            try {
                onChain = await readChain({ rpcUrl: url, chainId, registry, root, txHash: chain.tx_hash });
                break;
            } catch (error) {
                lastError = error;
            }
        }
        if (!onChain) {
            check(false, `Blockchain not reachable for chain ${chainId}`, String(lastError?.message ?? "no public node known: give one"));
            continue;
        }
        const when = onChain.timestamp ? new Date(onChain.timestamp * 1000).toISOString().replace(".000Z", "Z") : "";
        check(onChain.exists, onChain.exists ? `Root recorded on chain ${chainId} at ${when} (UTC)` : `Root not found on chain ${chainId}`, `0x${root}`);
        if (onChain.exists) {
            const entry = `${onChain.referenceType} ${onChain.referenceId}`;
            const expected = `${chain.reference_type} ${chain.reference_id}`;
            check(entry === expected, `Registry entry ${entry}`, entry === expected ? "" : `the proof says ${expected}`);
            check(!onChain.superseded, onChain.superseded ? "The root was later marked as superseded on the registry" : "The root is not superseded");
        }
        if (onChain.transaction) {
            const tx = onChain.transaction;
            check(tx.to === registry && tx.carriesRoot && tx.succeeded !== false, `Transaction ${chain.tx_hash} sends this root to the registry${tx.block !== null ? `, block ${tx.block}` : ""}`);
        } else if (chain.tx_hash) {
            check(false, `Transaction ${chain.tx_hash} not found on this node`);
        }
    }

    return { ok: checks.every((item) => item.ok), checks, proof };
};
