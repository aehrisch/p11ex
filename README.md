[![SoftHSM Linux](https://github.com/aehrisch/p11ex/actions/workflows/softhsm-linux.yml/badge.svg)](https://github.com/aehrisch/p11ex/actions/workflows/softhsm-linux.yml)[![SoftHSM macOS](https://github.com/aehrisch/p11ex/actions/workflows/softhsm-macos.yml/badge.svg)](https://github.com/aehrisch/p11ex/actions/workflows/softhsm-macos.yml)[![p11ex_cli](https://github.com/aehrisch/p11ex/actions/workflows/p11ex-cli.yml/badge.svg)](https://github.com/aehrisch/p11ex/actions/workflows/p11ex-cli.yml)
<div align="right">
  <img src="img/p11ex-logo-400x400.png" alt="p11ex logo" width="100">
</div>

# p11ex --- PKCS#11 bindings for Elixir
`p11ex` is an Elixir library that provides access to the [PKCS#11 interface](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html) for cryptographic tokens such as Hardware Security Modules and smartcards. The library exposes most PKCS#11 functionality to Elixir, though it is not yet feature complete. Available functions include:

- `C_GetSlotList`: List tokens
- `C_GetTokenInfo`: Retrieve information about a token
- `C_OpenSession`: Open a new PKCS#11 session
- `C_CloseSession`: Close a PKCS#11 session
- `C_CloseAllSession`: Close all open sessions for a token
- `C_GetSessionInfo`: Retrieve status information about a session
- `C_Login`: Authenticate an open session
- `C_Logout`: Deauthenticate an open session
- `C_GenerateKey`: Generate a symmetric key
- `C_FindObjects`: Search for objects stored in the token
- `C_GetAttributeValue`: Retrieve attributes of an object
- `C_EncryptInit`, `C_Encrypt`, `C_EncryptUpdate`, and `C_EncryptFinal`: Encryption in chunks and as a complete block
- `C_DecryptInit`, `C_Decrypt`, `C_DecryptUpdate`, and `C_DecryptFinal`: Decryption in chunks and as a complete block
- `C_GenerateRandom`: Generate random bytes using the token
- `C_DestroyObject`: Delete objects in the token or session
- `C_GetMechanismList`: List cryptographic mechanisms supported by token
- `C_GetMechanismInfo`: Retrieve information about a mechanism
- `C_SignInit`, `C_Sign`, `C_SignUpdate`, `C_SignFinal`: Sign data in chunks and as a complete block
- `C_VerifyInit`, `C_Verify`: Verify a signature
- `C_DigestInit`, `C_Digest`, `C_DigestUpdate`, `C_DigestFinal`: Compute a hash digest in the token
- `C_GenKeyPair`: Generate asymmetric key pair
- `C_WrapKey`: Encrypt an extractable key and make it exportable
- `C_UnwrapKey`: Decrypt an exported key into the token

Some PKCS#11 functions require mechanism parameters as arguments. Common parameter types are supported and documented in the Elixir documentation.

The implementation is automatically tested with [SoftHSM](https://github.com/softhsm/softHSMv2) on Linux (AMD64 and ARM64) and macOS (ARM64). Additional tests are available for the [Yubikey PKCS#11 module](https://developers.yubico.com/yubico-piv-tool/YKCS11/), though these do not run automatically as part of the build.

## p11ex_cli --- CLI program to use PKCS#11 tokens

The project also includes a CLI program named `p11ex_cli` for working with cryptographic tokens. This program provides access to key `p11ex` functions.
