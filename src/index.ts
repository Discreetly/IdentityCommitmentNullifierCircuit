import * as path from 'path';
import { groth16 } from 'snarkjs';
import type { IDCProof, VerificationKey, Witness } from './types';
import { poseidon1 } from 'poseidon-lite/poseidon1';
import { poseidon2 } from 'poseidon-lite/poseidon2';
import { Identity } from '@semaphore-protocol/identity';
import verificationKey from './zkeyFiles/idcNullifier/verification_key.json';

let wasmFilePath;
let finalZkeyPath;

try {
  wasmFilePath = path.join(__dirname, 'zkeyFiles', 'idcNullifier', 'circuit.wasm');
  finalZkeyPath = path.join(__dirname, 'zkeyFiles', 'idcNullifier', 'final.zkey');
} catch (e) {
  console.warn('Could not find path to wasm and zkey files');
}
/**
 * Wrapper class for proof generation.
 */
export class Prover {
  wasmFile: string | Uint8Array;
  finalZkey: string | Uint8Array;
  constructor(
    _wasmFilePath: string | Uint8Array = wasmFilePath,
    _finalZkeyPath: string | Uint8Array = finalZkeyPath
  ) {
    this.wasmFile = _wasmFilePath;
    this.finalZkey = _finalZkeyPath;
  }

  /**
   * Generates a full proof.
   * @param args An object containing the identity and external nullifier.
   * @returns An object containing the proof and public signals.
   */
  public async generateProof(args: {
    identity: Identity;
    externalNullifier: bigint;
  }): Promise<IDCProof> {
    const identitySecret = poseidon2([args.identity.nullifier, args.identity.trapdoor]);
    const witness: Witness = {
      identitySecret: identitySecret,
      externalNullifier: args.externalNullifier
    };
    const { proof, publicSignals } = await groth16.fullProve(
      witness,
      this.wasmFile,
      this.finalZkey,
      null
    );
    const snarkProof: IDCProof = {
      proof,
      publicSignals: {
        identityCommitment: publicSignals[0],
        nullifierHash: publicSignals[1],
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
  constructor(readonly vKey: VerificationKey = verificationKey) {}

  /**
   * Verifies a full proof.
   * @param An object with the proof and public signals.
   * @returns True if the proof is valid, false otherwise.
   * @throws Error if the proof is using different parameters.
   */
  public async verifyProof(idcProof: IDCProof): Promise<boolean> {
    const expectedNullifierHash = poseidon2([
      BigInt(idcProof.publicSignals.externalNullifier),
      BigInt(idcProof.publicSignals.identityCommitment)
    ]);
    const actualNullifierHash = idcProof.publicSignals.nullifierHash;
    if (expectedNullifierHash !== BigInt(actualNullifierHash)) {
      throw new Error(
        `External nullifier does not match: expectedNullifierHash=${expectedNullifierHash}` +
          `actualNullifierHash=${actualNullifierHash}`
      );
    }

    const { proof, publicSignals } = idcProof;
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

export * from './types';
