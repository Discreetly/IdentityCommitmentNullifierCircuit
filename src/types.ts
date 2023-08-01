import { Identity } from '@semaphore-protocol/identity';

export type StrBigInt = string | bigint;

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
export type PublicSignals = {
  nullifierHash: bigint;
  identityCommitment: bigint;
  externalNullifier: bigint;
};

export type SNARKProof = {
  proof: Proof;
  publicSignals: PublicSignals;
};

/**
 * snarkjs proof.
 */
export type Proof = {
  pi_a: StrBigInt[];
  pi_b: StrBigInt[][];
  pi_c: StrBigInt[];
  protocol: string;
  curve: string;
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
