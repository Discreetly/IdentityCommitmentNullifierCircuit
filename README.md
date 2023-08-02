# idcNullifier circuits

This is a circuit that takes a semaphore identity and a nullifier in, and generates an identity commitment and the hash of the identity commitment and nullifier together.

The purpose of this is to prove that you have the secrets to an identity commitment, with a nullifier to prevent replay attacks.

## Circuit

Constraints: 453

**Private Input**
_(semaphore identity secret)_

- identitySecret

**Public Inputs**

- externalNullifier - nullifier to prevent replay attack/double-signaling

**Outputs**

- nullifierHash - the identity commitment and nullifier hashed together
- identityCommitment - the identity commitment from the semaphore identity

## Proving Time

~380ms on a Macbook Air M2
~400ms on an AMD 5800x
~500ms on an Intel i7-1165G7

## Usage

```ts
import { Prover, Verifier } from "idcNullifier";
import { Identity } from "@semaphore-protocol/identity";

const newIdentity = new Identity();
const timestamp = new Date.now();

const prover = new Prover();

const proof = prover.generateProof({
  identity: newIdentity,
  externalNullifier: timestamp,
});

const identityCommitment = proof.publicSignals.identityCommitment;
const externalNullifier = proof.publicSignals.externalNullifier;

const verifier = new Verifier();
const isValid = verifier.verifyProof(proof);
```
