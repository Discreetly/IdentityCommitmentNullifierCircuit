import { groth16 } from 'snarkjs';
import { PublicSignals, SNARKProof, VerificationKey, Witness } from './types';
import poseidon from 'poseidon-lite';

/**
 * Wrapper class for proof generation.
 */
export class Prover {
  constructor(
    readonly wasmFilePath: string | Uint8Array,
    readonly finalZkeyPath: string | Uint8Array
  ) {}

  /**
   * Generates a full proof.
   * @param args The parameters for creating the proof.
   * @returns The full SnarkJS proof.
   */
  public async generateProof(args: {
    identitySecret: bigint;
    externalNullifier: bigint;
  }): Promise<SNARKProof> {
    const witness: Witness = {
      identitySecret: args.identitySecret,
      externalNullifier: args.externalNullifier
    };
    const { proof, publicSignals } = await groth16.fullProve(
      witness,
      this.wasmFilePath,
      this.finalZkeyPath,
      null
    );
    const snarkProof: SNARKProof = {
      proof,
      publicSignals: {
        nullifierHash: publicSignals[0],
        identityCommitment: publicSignals[1],
        externalNullifier: publicSignals[2]
      }
    };
    return snarkProof;
  }
}

/**
 * Wrapper of circuit verifier.
 */
export class Verifier {
  constructor(readonly verificationKey: VerificationKey) {}

  /**
   * Verifies a full proof.
   * @param fullProof The SnarkJS full proof.
   * @returns True if the proof is valid, false otherwise.
   * @throws Error if the proof is using different parameters.
   */
  public async verifyProof(snarkProof: SNARKProof): Promise<boolean> {
    const expectedNullifierHash = poseidon([
      BigInt(snarkProof.publicSignals.externalNullifier),
      BigInt(snarkProof.publicSignals.identityCommitment)
    ]);
    const expectedNullifierHash2 = poseidon([
      BigInt(snarkProof.publicSignals.identityCommitment),
      BigInt(snarkProof.publicSignals.externalNullifier)
    ]);
    const actualNullifierHash = snarkProof.publicSignals.nullifierHash;
    if (expectedNullifierHash !== BigInt(actualNullifierHash)) {
      throw new Error(
        `External nullifier does not match: expectedNullifierHash=${expectedNullifierHash}, expectedNullifierHash2=${expectedNullifierHash2},` +
          `actualNullifierHash=${actualNullifierHash}`
      );
    }

    const { proof, publicSignals } = snarkProof;
    return groth16.verify(
      this.verificationKey,
      [
        publicSignals.nullifierHash,
        publicSignals.identityCommitment,
        publicSignals.externalNullifier
      ],
      proof
    );
  }
}