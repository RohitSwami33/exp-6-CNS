# Experiment 12 — AES ECB/CBC and Secure Encryption Scheme

Based on the SIES Graduate School of Technology Experiment No. 12 handout.

This folder contains **both parts** of Experiment 12 from the supplied handout.

## Part 1 — AES Security Analysis: ECB vs CBC

Implements AES-128 using ECB and CBC modes, performs encryption/decryption, compares ciphertext blocks, and examines the security implications of repeated plaintext patterns, CBC chaining, and the IV.

### Files
- `experiment_12_aes_ecb_cbc.py` — Part 1 implementation.
- `output.txt` — captured Part 1 output.

### Run
```bash
python -m pip install -r requirements.txt
python experiment_12_aes_ecb_cbc.py
```

The CBC IV is generated randomly, so the CBC IV/ciphertext values change on each run. The ECB ciphertext is deterministic for the fixed demo key and plaintext.

### Captured Part 1 observation
- ECB blocks: 4 total, 4 unique.
- CBC blocks: 4 total, 4 unique.
- ECB and CBC decryption both verified successfully.
- The repeated string supplied in the handout does not align to identical 16-byte AES blocks for this exact input, so the captured ECB run does not show duplicate ciphertext blocks. ECB can still reveal repeated patterns when identical plaintext blocks are block-aligned.

## Part 2 — Design and Analysis of a Secure Encryption Scheme

Implements the complete Part 2 program specified in the handout:

1. Caesar Cipher
2. Euclidean Algorithm
3. Modular Inverse / Affine Cipher
4. Vigenere Cipher
5. Congruence Relation
6. Fermat's Little Theorem
7. Chinese Remainder Theorem (CRT)
8. AES-CBC
9. Final encryption/decryption verification

### Files
- `experiment_12_part2.py` — Part 2 implementation following the handout's algorithm and test values.
- `output2.txt` — captured Part 2 output.
- `requirements.txt` — PyCryptodome dependency.

### Run Part 2
```bash
python -m pip install -r requirements.txt
python experiment_12_part2.py
```

The Part 2 AES-CBC IV is random, so the IV and ciphertext will change on every fresh execution. The checked-in `output2.txt` is the captured run used for this submission.

### Captured Part 2 results
- Caesar Cipher: PASS
- Affine Cipher: PASS
- Vigenere Cipher: PASS
- AES-CBC: PASS
- CRT solution: `x = 23`
- Fermat verification: `3^6 mod 7 = 1`
- Euclidean GCD: `gcd(35, 26) = 1`
- Modular inverse of `5 mod 26`: `21`

## Requirements

```text
pycryptodome
```

Install with:

```bash
python -m pip install -r requirements.txt
```
