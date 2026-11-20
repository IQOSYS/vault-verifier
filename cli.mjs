#!/usr/bin/env node
// Usage: node cli.mjs [document or sealed PDF] [--proof iqosys-proof-....json] [--rpc https://...]
import { readFile } from "node:fs/promises";
import { verify } from "./verifier.mjs";

const args = process.argv.slice(2);
const option = (name) => {
    const at = args.indexOf(name);
    if (at < 0) return undefined;
    const [, value] = args.splice(at, 2);
    return value;
};
const proofPath = option("--proof");
const rpcUrl = option("--rpc");
const [filePath] = args;

if (!filePath && !proofPath) {
    console.log("Usage: node cli.mjs [document or sealed PDF] [--proof iqosys-proof-....json] [--rpc https://polygon-node]");
    process.exit(2);
}

const file = filePath ? new Uint8Array(await readFile(filePath)) : undefined;
const proof = proofPath ? JSON.parse(await readFile(proofPath, "utf8")) : undefined;
const result = await verify({ file, proof, rpcUrl });

for (const { ok, label, detail } of result.checks) console.log(`${ok ? "OK  " : "FAIL"} ${label}${detail ? `\n     ${detail}` : ""}`);
console.log(result.ok ? "\nVERIFIED: every check passed." : "\nNOT VERIFIED: see the failed checks above.");
process.exit(result.ok ? 0 : 1);
