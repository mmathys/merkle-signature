# Merkle Signing

Basic implementation of the merkle signing algorithm. It supports:

- Creation of a merkle tree (arbitrary number of leaves, not restricted to 2^n)
- Merkle tree path generation
- Merkle tree path verification (see `VerifyPath`)

## Merkle tree signature

The complete implementation of merkle signing requires a valid signature of the merkle root.

The signature of the merkle signing UTXO is defined as follows:
- merkle root
- signature of the merkle root
- path from own hash to merkle root
    - `path`: the hash path from our own hash to merkle root (own hash and merkle root are not included)
    - `indexes`: 0 if the defined hash is a left leaf, 1 if right
    (idea: indexes can be left out if we fix the order of the leaves (lexicographic), but later)

## Notes

The original repo is located at https://github.com/mmathys/merkle-signing
