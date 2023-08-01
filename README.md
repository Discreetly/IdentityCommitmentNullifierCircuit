# idcNullifier circuits

This is a circuit that takes a semaphore identity and a nullifier in, and generates an identity commitment and the hash of the identity commitment and nullifier together.

The purpose of this is to prove that you have the secrets to an identity commitment, with a nullifier to prevent replay attacks.