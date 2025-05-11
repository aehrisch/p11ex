# p11ex

This Git repository contains `p11ex`, a PKCS#11 adapter library for Elixir that enables integration with cryptographic hardware security modules (HSMs) and smart cards. Built with a native interface (NIF) and Elixir-friendly abstractions, it provides a robust and developer-friendly way to use hardware security features directly from Elixir applications. The library supports the following set of cryptographic operations:

- Key Management:
  - Symmetric key generation
  - Asymmetric key pair generation
  - Secure key storage and retrieval
- Cryptographic Operations:
  - Encryption and Decryption (both single-buffer and streaming modes)
  - Digital Signatures (generation and verification)
  - Message Authentication Codes (MACs)
  - Secure hash operations
- Token Management:
  - Hardware token initialization and configuration
  - Slot and token enumeration
  - Session management
  - Object (keys, certificates) management
