import { Groth16Proof, PublicSignals } from 'snarkjs';

export interface SNARKProof {
  proof: Groth16Proof;
  publicSignals: PublicSignals;
}

/**
 * Witness that contains all the inputs needed for proof generation.
 */
export type Witness = {
  identitySecret: bigint;
  externalNullifier: bigint;
};

/**
 * Public signals that are generated along with the proof
 */
export type IDCPublicSignals = {
  nullifierHash: string;
  identityCommitment: string;
  externalNullifier: string;
};

export type IDCProof = {
  proof: Groth16Proof;
  publicSignals: IDCPublicSignals;
};

/**
 * snarkjs verification key.
 */
export type VerificationKey = {
  protocol: string;
  curve: string;
  nPublic: number;
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  vk_alphabeta_12: string[][][];
  IC: string[][];
};
