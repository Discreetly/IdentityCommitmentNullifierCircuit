import * as fs from 'fs';
import * as path from 'path';
import { groth16 } from 'snarkjs';
import type { SNARKProof, VerificationKey, Witness } from './types';
import { poseidon1 } from 'poseidon-lite/poseidon1';
import { poseidon2 } from 'poseidon-lite/poseidon2';
import { Identity } from '@semaphore-protocol/identity';
import verificationKey from './zkeyFiles/idcNullifier/verification_key.json';

const wasmFilePath = path.join(__dirname, 'zkeyFiles', 'idcNullifier', 'circuit.wasm');
const finalZkeyPath = path.join(__dirname, 'zkeyFiles', 'idcNullifier', 'final.zkey');
/**
 * Wrapper class for proof generation.
 */
export class Prover {
  constructor(
    readonly _wasmFilePath: string | Uint8Array = wasmFilePath,
    readonly _finalZkeyPath: string | Uint8Array = finalZkeyPath
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
    const identitySecret = poseidon2([args.identity.trapdoor, args.identity.nullifier]);
    const witness: Witness = {
      identitySecret: identitySecret,
      externalNullifier: args.externalNullifier
    };
    const { proof, publicSignals } = await groth16.fullProve(
      witness,
      this._wasmFilePath,
      this._finalZkeyPath,
      null
    );
    console.debug('idc from semaphore: ' + poseidon1([BigInt(identitySecret)]));
    console.debug('idc from generateProof: ' + poseidon1([BigInt(identitySecret)]));
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
  constructor(readonly vKey: VerificationKey = verificationKey) {}

  /**
   * Verifies a full proof.
   * @param An object with the proof and public signals.
   * @returns True if the proof is valid, false otherwise.
   * @throws Error if the proof is using different parameters.
   */
  public async verifyProof(snarkProof: SNARKProof): Promise<boolean> {
    const expectedNullifierHash = poseidon2([
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
      this.vKey,
      [
        publicSignals.identityCommitment,
        publicSignals.nullifierHash,
        publicSignals.externalNullifier
      ],
      proof
    );
  }
}
