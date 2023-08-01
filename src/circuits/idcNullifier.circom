pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template CalculateIdentityCommitment() {
    signal input secret;

    signal output out;

    component poseidon = Poseidon(1);

    poseidon.inputs[0] <== secret;

    out <== poseidon.out;
}

template CalculateNullifierHash() {
    signal input externalNullifier;
    signal input identityCommitment;

    signal output out;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== externalNullifier;
    poseidon.inputs[1] <== identityCommitment;

    out <== poseidon.out;
}

template idcNullifier() {
    signal input identitySecret;
    signal input externalNullifier;
    signal output identityCommitment;
    signal output nullifierHash;

    component calculateIdentityCommitment = CalculateIdentityCommitment();
    calculateIdentityCommitment.secret <== identitySecret;

    identityCommitment  <== calculateIdentityCommitment.out;

    component calculateNullifierHash = CalculateNullifierHash();
    calculateNullifierHash.externalNullifier <== externalNullifier;
    calculateNullifierHash.identityCommitment <== identityCommitment;

    nullifierHash <== calculateNullifierHash.out;
}

component main {public [externalNullifier]} = idcNullifier();
