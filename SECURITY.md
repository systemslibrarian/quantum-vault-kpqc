# Security Policy

## Supported Versions

The current supported security format is the `QVKP` container family at version `2`.
Older experimental formats are not supported for new security fixes.

## Threat Model

Quantum Vault assumes an attacker capable of:

- intercepting ciphertext containers
- tampering with serialized containers and headers
- replaying or swapping previously captured containers
- obtaining fewer than the threshold number of Shamir shares
- attempting adaptive chosen-ciphertext style mutations against the parser and decryptor

The system relies on:

- SMAUG-T as the post-quantum KEM when `kpqc-native` is enabled
- HAETAE as the post-quantum signature scheme when `kpqc-native` is enabled
- AES-256-GCM for authenticated encryption
- Shamir Secret Sharing for threshold reconstruction
- OS-provided CSPRNG entropy only

## Cryptographic Assumptions

- Unknown container versions and unknown algorithm identifiers are rejected fail-closed.
- Header metadata is authenticated through both the signature input and AEAD AAD.
- Per-share AEAD keys and nonces are domain-separated via HKDF labels.
- Decryption failures are reported generically to reduce oracle leakage.

## Non-Goals

- The default `dev-backend` is not production cryptography.
- This project does not claim side-channel resistance against determined local attackers.
- Browser/WASM builds are for demonstration and interoperability testing, not hardened deployment.

## Reporting Vulnerabilities

Please report vulnerabilities privately to the repository owner before opening a public issue.
Include:

- affected commit or release
- reproduction steps or proof of concept
- impact assessment
- any suggested mitigation