pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";

template CalculateSecret() {
    signal input identityNullifier;
    signal input identityTrapdoor;

    signal output out;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== identityNullifier;
    poseidon.inputs[1] <== identityTrapdoor;

    out <== poseidon.out;
}

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
    signal input identityNullifier;
    signal input identityTrapdoor;

    signal input signalHash;
    signal input externalNullifier;

    signal output nullifierHash;
    signal output identityCommitment;

    component calculateSecret = CalculateSecret();
    calculateSecret.identityNullifier <== identityNullifier;
    calculateSecret.identityTrapdoor <== identityTrapdoor;

    signal secret;
    secret <== calculateSecret.out;

    component calculateIdentityCommitment = CalculateIdentityCommitment();
    calculateIdentityCommitment.secret <== secret;

    identityCommitment  <== calculateIdentityCommitment.out;

    component calculateNullifierHash = CalculateNullifierHash();
    calculateNullifierHash.externalNullifier <== externalNullifier;
    calculateNullifierHash.identityCommitment <== identityCommitment;

    // Dummy square to prevent tampering signalHash.
    signal signalHashSquared;
    signalHashSquared <== signalHash * signalHash;

    nullifierHash <== calculateNullifierHash.out;
}

component main {public [signalHash, externalNullifier]} = idcNullifier();
