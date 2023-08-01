import { groth16 } from 'snarkjs';
import { SNARKProof, VerificationKey, Witness } from './types';
import poseidon from 'poseidon-lite';
import { Identity } from '@semaphore-protocol/identity';

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
   * @param args An object containing the identity and external nullifier.
   * @returns An object containing the proof and public signals.
   */
  public async generateProof(args: {
    identity: Identity;
    externalNullifier: bigint;
  }): Promise<SNARKProof> {
    const identitySecret = poseidon([args.identity.trapdoor, args.identity.nullifier]);
    const witness: Witness = {
      identitySecret: identitySecret,
      externalNullifier: args.externalNullifier
    };
    const { proof, publicSignals } = await groth16.fullProve(
      witness,
      this.wasmFilePath,
      this.finalZkeyPath,
      null
    );
    console.debug('idc from semaphore: ' + poseidon([BigInt(identitySecret)]));
    console.debug('idc from generateProof: ' + poseidon([BigInt(identitySecret)]));
    const snarkProof: SNARKProof = {
      proof,
      publicSignals: {
        identityCommitment: publicSignals[0],
        nullifierHash: publicSignals[1],
        externalNullifier: publicSignals[2]
      }
    };
    console.debug(snarkProof.publicSignals);
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
   * @param An object with the proof and public signals.
   * @returns True if the proof is valid, false otherwise.
   * @throws Error if the proof is using different parameters.
   */
  public async verifyProof(snarkProof: SNARKProof): Promise<boolean> {
    const expectedNullifierHash = poseidon([
      BigInt(snarkProof.publicSignals.externalNullifier),
      BigInt(snarkProof.publicSignals.identityCommitment)
    ]);
    const actualNullifierHash = snarkProof.publicSignals.nullifierHash;
    if (expectedNullifierHash !== BigInt(actualNullifierHash)) {
      throw new Error(
        `External nullifier does not match: expectedNullifierHash=${expectedNullifierHash}` +
          `actualNullifierHash=${actualNullifierHash}`
      );
    }

    const { proof, publicSignals } = snarkProof;
    return groth16.verify(
      this.verificationKey,
      [
        publicSignals.identityCommitment,
        publicSignals.nullifierHash,
        publicSignals.externalNullifier
      ],
      proof
    );
  }
}
