/**
 * Generates Prover.toml for the Noir DER compliance circuit.
 *
 * Leaf hashes:    PedersenHash([v, f, pf, p, q])
 * Internal nodes: PedersenHash([left, right])
 *
 * Both match what main.nr uses (std::hash::pedersen_hash).
 */

import { createRequire } from 'module';
import { writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

const require = createRequire(import.meta.url);
const bb = require('@aztec/bb.js');

// ── DER readings — NREL PVWatts v8 (NSRDB TMY), Montreal June 21 07:00-14:00
// P: real AC output (W), rounded. V/f/PF/Q: IEEE 1547 grid model.
const v  = [ 993,  995,  996,  997,  996,  996,  993,  995];
const f  = [60003,59991,60012,59997,60008,60001,59994,60006];
const pf = [1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000];
const p  = [3086, 4521, 5942, 6469, 6345, 6453, 3350, 4672];
const q  = [  62,   90,   59,   65,   63,   65,   67,   93];

// Public compliance bounds (IEEE 1547-2018)
const v_min  = 880;
const v_max  = 1100;
const f_min  = 59500;
const f_max  = 60500;
const pf_min = 850;
const p_max  = 10000;
const r_max  = 3500;  // W/step (hourly); 350 W/min << IEEE 1547 10%/min

// ── Helpers ──────────────────────────────────────────────────────────────────
function frToBytes(n) {
  const buf = Buffer.alloc(32);
  let val = BigInt(n);
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return new Uint8Array(buf);
}

function toHex(buf) {
  return '0x' + Buffer.from(buf).toString('hex');
}

// ── Main ─────────────────────────────────────────────────────────────────────
await bb.BarretenbergSync.initSingleton();
const api = bb.BarretenbergSync.getSingleton();

function pedersenHash(inputs) {
  return api.pedersenHash({ inputs: inputs.map(frToBytes), hashIndex: 0 }).hash;
}

// Step 1: Poseidon2 leaf for each timestep  →  pedersenHash([v, f, pf, p, q])
const leaves = [];
for (let t = 0; t < 8; t++) {
  const hash = pedersenHash([v[t], f[t], pf[t], p[t], q[t]]);
  leaves.push(hash);
  console.log(`leaf[${t}] = ${toHex(hash)}`);
}

// Step 2: Poseidon2 Merkle tree (depth=3, 8 leaves)
// tree[0] = 8 leaves, tree[1] = 4 nodes, tree[2] = 2 nodes, tree[3][0] = root
const tree = [leaves];
for (let level = 0; level < 3; level++) {
  const cur = tree[level];
  const next = [];
  for (let i = 0; i < cur.length; i += 2) {
    next.push(pedersenHash([BigInt('0x' + Buffer.from(cur[i]).toString('hex')),
                              BigInt('0x' + Buffer.from(cur[i + 1]).toString('hex'))]));
  }
  tree.push(next);
}

const root = tree[3][0];
console.log(`\nmerkle_root = ${toHex(root)}`);

// Step 3: Path elements for each leaf t
// path[d] = sibling at depth d  (depth 0 = leaf level)
const pathElements = [];
const pathIndices  = [];
for (let t = 0; t < 8; t++) {
  const siblings = [
    tree[0][t ^ 1],
    tree[1][(t >> 1) ^ 1],
    tree[2][(t >> 2) ^ 1],
  ];
  pathElements.push(siblings.map(toHex));
  pathIndices.push(t);
}

// ── Write Prover.toml ────────────────────────────────────────────────────────
function arr1D(arr) {
  return '[' + arr.map(x => `"${x}"`).join(', ') + ']';
}

function arr2D(arr) {
  const rows = arr.map(row => '  [' + row.map(x => `"${x}"`).join(', ') + ']');
  return '[\n' + rows.join(',\n') + '\n]';
}

const toml = `\
merkle_root_pub = "${toHex(root)}"

v_min  = "${v_min}"
v_max  = "${v_max}"
f_min  = "${f_min}"
f_max  = "${f_max}"
pf_min = "${pf_min}"
p_max  = "${p_max}"
r_max  = "${r_max}"

v  = ${arr1D(v)}
f  = ${arr1D(f)}
pf = ${arr1D(pf)}
p  = ${arr1D(p)}
q  = ${arr1D(q)}

path_elements = ${arr2D(pathElements)}

path_indices = ${arr1D(pathIndices)}
`;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outPath = path.resolve(__dirname, '../noir/Prover.toml');
writeFileSync(outPath, toml);
console.log(`\nProver.toml written to ${outPath}`);
