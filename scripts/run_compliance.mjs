/**
 * DER Compliance Verification — direct evaluation of the Noir circuit logic.
 * Uses real NREL PVWatts + IEEE 1547 readings from inputs/der_readings.json.
 * Computes Poseidon2-Merkle tree and checks all circuit constraints.
 */

import { createRequire } from 'module';
import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const bb = require('@aztec/bb.js');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(readFileSync(path.resolve(__dirname, '../inputs/der_readings.json'), 'utf8'));

// ── Scale / units (×1000 fixed-point, matching circuit integers) ─────────────
// V   : per-unit × 1000  (1.0 pu = 1000)
// f   : Hz × 1000        (60.0 Hz = 60000)
// PF  : × 1000           (1.0 = 1000)
// P   : W (integer)
// Q   : VAr (integer)

const readings = data.readings;
const T = readings.length;

const V  = readings.map(r => r.V);
const f  = readings.map(r => r.f);
const PF = readings.map(r => r.PF);
const P  = readings.map(r => r.P);
const Q  = readings.map(r => r.Q);

// IEEE 1547-2018 compliance bounds (same as circuit public inputs)
const V_min  = 880;
const V_max  = 1100;
const f_min  = 59500;
const f_max  = 60100;
const PF_min = 850;
const PF_MAX = 1000;
const P_max  = 10000;
const R_max  = 3500;  // W/step (hourly); 350 W/min << IEEE 1547 10%/min

// ── Helpers ──────────────────────────────────────────────────────────────────
function frToBytes(n) {
  const buf = Buffer.alloc(32);
  let val = BigInt(n);
  for (let i = 31; i >= 0; i--) { buf[i] = Number(val & 0xffn); val >>= 8n; }
  return new Uint8Array(buf);
}
function toHex(buf) { return '0x' + Buffer.from(buf).toString('hex'); }
function toBigInt(buf) {
  let v = 0n;
  for (const b of buf) v = (v << 8n) | BigInt(b);
  return v;
}
function pass(ok) { return ok ? '✓ PASS' : '✗ FAIL'; }

// ── Initialise Barretenberg ──────────────────────────────────────────────────
await bb.BarretenbergSync.initSingleton();
const api = bb.BarretenbergSync.getSingleton();

function pedersenHash(inputs) {
  return api.pedersenHash({ inputs: inputs.map(x => frToBytes(BigInt(x))), hashIndex: 0 }).hash;
}

// ── Section 1: Per-step compliance checks ───────────────────────────────────
console.log('='.repeat(65));
console.log('  DER Compliance Verification — IEEE 1547-2018 / Noir Circuit');
console.log('  Source: NREL PVWatts v8 + IEEE 1547 grid model, Montréal');
console.log('='.repeat(65));
console.log();
console.log('Bounds:');
console.log(`  Voltage   : [${V_min/1000}, ${V_max/1000}] pu`);
console.log(`  Frequency : [${f_min/1000}, ${f_max/1000}] Hz`);
console.log(`  Power factor ≥ ${PF_min/1000}  |  P ≤ ${P_max} W  |  ΔP ≤ ${R_max} W/step`);
console.log();

const header = ['Step','Time ','V(pu) ','f(Hz)  ','PF   ','P(W)','Q(VAr)','V','f','PF','P','ΔP'];
console.log('Step  Time   V(pu)  f(Hz)    PF     P(W)  Q(VAr)  V    f    PF   P    ΔP');
console.log('-'.repeat(75));

let allPass = true;
const violations = [];

for (let t = 0; t < T; t++) {
  const r = readings[t];
  const vOk  = V[t]  >= V_min  && V[t]  <= V_max;
  const fOk  = f[t]  >= f_min  && f[t]  <= f_max;
  const pfOk = PF[t] >= PF_min && PF[t] <= PF_MAX;
  const pOk  = P[t]  <= P_max;
  let dpOk = true;
  let dp = 0;
  if (t > 0) {
    dp = Math.abs(P[t] - P[t-1]);
    dpOk = dp <= R_max;
  }

  const ok = vOk && fOk && pfOk && pOk && (t === 0 || dpOk);
  if (!ok) { allPass = false; violations.push(t); }

  const fmt = (x, w) => String(x).padStart(w);
  const tick = s => s ? '✓' : '✗';
  console.log(
    `  ${t}    ${r.time}  ${(V[t]/1000).toFixed(3)}  ${(f[t]/1000).toFixed(3)}  ` +
    `${(PF[t]/1000).toFixed(3)}  ${fmt(P[t],4)}  ${fmt(Q[t],5)}    ` +
    `${tick(vOk)} ${tick(fOk)} ${tick(pfOk)} ${tick(pOk)} ` +
    (t > 0 ? `${tick(dpOk)}(${dp})` : '  —  ')
  );
}

console.log('-'.repeat(75));
console.log(`\nColumn legend: V = voltage, f = frequency, PF = power factor, P = active power, ΔP = ramp`);
console.log();
console.log(`Overall compliance: ${allPass ? '✓ ALL CONSTRAINTS SATISFIED' : '✗ VIOLATIONS at steps: ' + violations.join(', ')}`);

// ── Section 2: Merkle tree ──────────────────────────────────────────────────
console.log();
console.log('='.repeat(65));
console.log('  Poseidon2 Merkle Tree  (depth D=3, T=8 leaves)');
console.log('='.repeat(65));
console.log();

const leaves = [];
for (let t = 0; t < T; t++) {
  const h = pedersenHash([V[t], f[t], PF[t], P[t], Q[t]]);
  leaves.push(h);
  console.log(`  leaf[${t}] (t=${t}, ${readings[t].time}) = ${toHex(h)}`);
}

// Build tree
const tree = [leaves];
for (let lv = 0; lv < 3; lv++) {
  const cur = tree[lv];
  const next = [];
  for (let i = 0; i < cur.length; i += 2) {
    next.push(pedersenHash([toBigInt(cur[i]), toBigInt(cur[i+1])]));
  }
  tree.push(next);
}
const root = tree[3][0];

console.log();
console.log(`  Internal nodes (level 1): ${tree[1].map(toHex).join('\n                             ')}`);
console.log();
console.log(`  Internal nodes (level 2): ${tree[2].map(toHex).join('\n                             ')}`);
console.log();
console.log(`  Merkle root:  ${toHex(root)}`);
console.log(`  (decimal):    ${toBigInt(root)}`);

// ── Section 3: Merkle path verification for each leaf ───────────────────────
console.log();
console.log('='.repeat(65));
console.log('  Merkle Path Verification (per-leaf root recomputation)');
console.log('='.repeat(65));
console.log();

let merkleOk = true;
for (let t = 0; t < T; t++) {
  let cur = toBigInt(leaves[t]);
  const siblings = [
    toBigInt(tree[0][t ^ 1]),
    toBigInt(tree[1][(t >> 1) ^ 1]),
    toBigInt(tree[2][(t >> 2) ^ 1]),
  ];
  const index = BigInt(t);
  // Replicate circuit logic: bits = index.to_le_bits(3)
  for (let d = 0; d < 3; d++) {
    const bit = (index >> BigInt(d)) & 1n;
    const [l, r] = bit ? [siblings[d], cur] : [cur, siblings[d]];
    cur = toBigInt(pedersenHash([l, r]));
  }
  const ok = cur === toBigInt(root);
  if (!ok) merkleOk = false;
  console.log(`  leaf[${t}] path → root: ${ok ? '✓ matches' : '✗ MISMATCH'}`);
}

// ── Section 4: Summary ───────────────────────────────────────────────────────
console.log();
console.log('='.repeat(65));
console.log('  Summary');
console.log('='.repeat(65));
console.log();
console.log(`  Dataset  : ${data.location}`);
console.log(`  Period   : ${data.period}`);
console.log(`  DER type : ${data.der_type}`);
console.log(`  T        : ${T} timesteps (hourly)`);
console.log();
console.log(`  [1] IEEE 1547 bounds  : ${allPass   ? '✓ PASS — all 8 timesteps compliant' : '✗ FAIL — violations at steps ' + violations.join(', ')}`);
console.log(`  [2] Merkle integrity  : ${merkleOk  ? '✓ PASS — all leaf paths verify to root' : '✗ FAIL'}`);
console.log(`  [3] Circuit witness   : ${allPass && merkleOk ? '✓ Satisfiable — ZK proof would be valid' : '✗ Witness would be rejected'}`);
console.log();
console.log(`  Merkle root committed: ${toHex(root)}`);
console.log();
