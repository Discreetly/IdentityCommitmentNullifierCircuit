import { Prover, Verifier } from '../src/index';
import { poseidon1 } from 'poseidon-lite/poseidon1';
import { poseidon2 } from 'poseidon-lite/poseidon2';
import { ZqField } from 'ffjavascript';
import { Identity } from '@semaphore-protocol/identity';
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
  const identity = new Identity();
  const prover = new Prover();
  const verifier = new Verifier();
  const semaphoreIdentitySecret = identity.getSecret();
  const semaphoreIdentityCommitment = identity.getCommitment();
  const identityRaw = identity as unknown as {
    _commitment: string;
    _secret: string;
    _nullifier: string;
    _trapdoor: string;
  };
  console.log('Semaphore idc: ', semaphoreIdentityCommitment);
  console.log('Semaphore idc raw: ', identityRaw._commitment);
  const semaphoreIdentityCommitmentRaw = identityRaw._commitment;
  console.log(`Identity:`, identity);
  const externalNullifier = BigInt(Date.now());
  console.log(`External Nullifier:`, externalNullifier);
  const identitySecret = poseidon2([identity.nullifier, identity.trapdoor]);
  console.log(`Identity Secret:`, identitySecret);
  const identityCommitment = poseidon1([identitySecret]);
  console.log(`Identity Commitment:`, identityCommitment);

  test('should hash identity values correctly', () => {
    expect(identitySecret).toBe(semaphoreIdentitySecret);
    expect(identityCommitment).toBe(semaphoreIdentityCommitment);
    expect(identityCommitment).toBe(semaphoreIdentityCommitmentRaw);
  });

  const nullifierHash = poseidon2([externalNullifier, identityCommitment]);
  console.log(`Nullifier Hash:`, nullifierHash);

  test('should generate valid proof', async function () {
    const m0 = performance.now();
    const proof = await prover.generateProof({
      identity,
      externalNullifier
    });
    expect(proof.publicSignals.nullifierHash).toBe(nullifierHash.toString());
    expect(proof.publicSignals.identityCommitment).toBe(identityCommitment.toString());
    const m1 = performance.now();
    const isValid = await verifier.verifyProof(proof);
    const m2 = performance.now();
    console.log(`Proof generation: ${m1 - m0} ms`);
    console.log(`Proof Verification: ${m2 - m1} ms`);
    expect(isValid).toBeTruthy();
  });
});
