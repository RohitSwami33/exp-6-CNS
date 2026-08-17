# Experiment 12 — Security Analysis of AES Block Cipher Modes: ECB vs CBC

Based on the SIES Graduate School of Technology Experiment No. 12 handout.

## Aim
Implement AES-128 using ECB and CBC modes, perform encryption and decryption, compare ciphertext blocks, and observe the security implications of repeated plaintext patterns and CBC chaining/IV.

## Files
- `experiment_12_aes_ecb_cbc.py` — Python implementation using PyCryptodome.
- `output.txt` — captured experiment output.
- `requirements.txt` — required Python package.

## Run
```bash
python -m pip install -r requirements.txt
python experiment_12_aes_ecb_cbc.py
```

The CBC IV is generated randomly, so the CBC IV/ciphertext values will change on each run. The ECB ciphertext is deterministic for the fixed demo key and plaintext.

## Observation from the captured run
- ECB blocks: 4 total, 4 unique.
- CBC blocks: 4 total, 4 unique.
- Both ECB and CBC decryption verified successfully.
- The supplied handout's repeated string does not align to identical 16-byte AES blocks in this specific input, so the captured ECB run does **not** show repeated ciphertext blocks even though ECB can leak such patterns when repeated plaintext blocks are block-aligned.
