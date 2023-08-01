import { Prover, Verifier } from '../src/index';
import poseidon from 'poseidon-lite';
import { params } from './configs';
import { ZqField } from 'ffjavascript';
/*
  This is the "Baby Jubjub" curve described here:
  https://iden3-docs.readthedocs.io/en/latest/_downloads/33717d75ab84e11313cc0d8a090b636f/Baby-Jubjub.pdf
*/
export const SNARK_FIELD_SIZE = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);
export const Fq = new ZqField(SNARK_FIELD_SIZE);
export function fieldFactory(excludes?: bigint[], trials: number = 100): bigint {
  if (excludes) {
    for (let i = 0; i < trials; i++) {
      const d = Fq.random();
      if (!excludes.includes(d)) {
        return d;
      }
    }
    throw new Error('Failed to generate random data');
  } else {
    return Fq.random();
  }
}

describe('IdentityCommitmet Nullifier', function () {
  const prover = new Prover(params.wasmFilePath, params.finalZkeyPath);
  const verifier = new Verifier(params.verificationKey);
  const identitySecret = fieldFactory();
  console.log(`Identity Secret: ${identitySecret}`);
  const externalNullifier = fieldFactory();
  console.log(`External Nullifier: ${externalNullifier}`);
  const identityCommitment = poseidon([identitySecret]);
  console.log(`Identity Commitment: ${identityCommitment}`);
  const nullifierHash = poseidon([externalNullifier, identityCommitment]);
  console.log(`Nullifier Hash: ${nullifierHash}`);

  test('should generate valid proof', async function () {
    const m0 = performance.now();
    const proof = await prover.generateProof({
      identitySecret,
      externalNullifier
    });
    const m1 = performance.now();
    const isValid = await verifier.verifyProof(proof);
    const m2 = performance.now();
    console.log(`Proof generation: ${m1 - m0} ms`);
    console.log(`Proof Verification: ${m2 - m1} ms`);
    expect(isValid).toBeTruthy();
  });
});
