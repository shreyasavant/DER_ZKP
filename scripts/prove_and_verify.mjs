/**
 * Generates and verifies a ZK proof for the Noir DER compliance circuit.
 * Uses @aztec/bb.js (UltraHonkBackend) + @noir-lang/noir_js (Noir executor).
 */

import { createRequire } from 'module';
import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const { Noir } = require('@noir-lang/noir_js');
const { UltraHonkBackend } = require('@noir-lang/backend_barretenberg');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const circuit = JSON.parse(readFileSync(
  path.resolve(__dirname, '../target/der_compliance.json'), 'utf8'
));

// ── Parse Prover.toml ─────────────────────────────────────────────────────────
const proverText = readFileSync(
  path.resolve(__dirname, '../noir/Prover.toml'), 'utf8'
);

function parseScalar(text, key) {
  const m = text.match(new RegExp(`${key}\\s*=\\s*"([^"]+)"`));
  return m ? m[1] : null;
}

function parseArray1D(text, key) {
  const m = text.match(new RegExp(`${key}\\s*=\\s*\\[([^\\[\\]]+)\\]`));
  return m ? m[1].split(',').map(s => s.trim().replace(/"/g, '')) : null;
}

function parsePathElements(text) {
  const m = text.match(/path_elements\s*=\s*\[([\s\S]*?)\n\]/);
  if (!m) throw new Error('path_elements not found in Prover.toml');
  const rows = [];
  for (const row of m[1].matchAll(/\[([^\]]+)\]/g)) {
    rows.push(row[1].split(',').map(s => s.trim().replace(/"/g, '')));
  }
  return rows;
}

const inputs = {
  merkle_root_pub: parseScalar(proverText, 'merkle_root_pub'),
  v_min:  parseScalar(proverText, 'v_min'),
  v_max:  parseScalar(proverText, 'v_max'),
  f_min:  parseScalar(proverText, 'f_min'),
  f_max:  parseScalar(proverText, 'f_max'),
  pf_min: parseScalar(proverText, 'pf_min'),
  p_max:  parseScalar(proverText, 'p_max'),
  r_max:  parseScalar(proverText, 'r_max'),
  v:  parseArray1D(proverText, 'v'),
  f:  parseArray1D(proverText, 'f'),
  pf: parseArray1D(proverText, 'pf'),
  p:  parseArray1D(proverText, 'p'),
  q:  parseArray1D(proverText, 'q'),
  path_elements: parsePathElements(proverText),
  path_indices:  parseArray1D(proverText, 'path_indices'),
};

console.log('Inputs loaded:');
console.log('  merkle_root_pub:', inputs.merkle_root_pub);
console.log('  bounds: V[', inputs.v_min, ',', inputs.v_max, ']',
  'f[', inputs.f_min, ',', inputs.f_max, ']',
  'PF>=', inputs.pf_min, 'P<=', inputs.p_max, 'R_max=', inputs.r_max);

// ── Execute + Prove + Verify ──────────────────────────────────────────────────
console.log('\nInitializing Noir executor...');
const noir = new Noir(circuit);

console.log('Executing circuit (generating witness)...');
const t0 = Date.now();
const { witness } = await noir.execute(inputs);
console.log(`Witness generated in ${((Date.now() - t0) / 1000).toFixed(2)}s`);

console.log('\nInitializing UltraHonk prover...');
const backend = new UltraHonkBackend(circuit, { threads: 4 });

console.log('Generating proof...');
const t1 = Date.now();
const proof = await backend.generateProof(witness);
const proveTime = ((Date.now() - t1) / 1000).toFixed(2);
console.log(`Proof generated in ${proveTime}s`);
console.log('Public inputs:', proof.publicInputs);
console.log('Proof (first 32 bytes hex):', Buffer.from(proof.proof.slice(0, 32)).toString('hex'));

console.log('\nVerifying proof...');
const t2 = Date.now();
const valid = await backend.verifyProof(proof);
const verifyTime = ((Date.now() - t2) / 1000).toFixed(2);

console.log('\n========================================');
console.log(`Proof verification: ${valid ? 'VALID ✓' : 'INVALID ✗'}`);
console.log(`Prove time:  ${proveTime}s`);
console.log(`Verify time: ${verifyTime}s`);
console.log('Circuit: DER Compliance (8 timesteps, depth-3 Merkle)');
console.log('========================================');

await backend.destroy();
