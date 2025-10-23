# P11ex CLI Tool Documentation

The `p11ex_cli` is a command-line interface for interacting with PKCS#11 cryptographic tokens and modules. It provides a commands for managing slots, objects, and key generation on PKCS#11-compliant hardware security modules (HSMs). 

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Global Options](#global-options)
- [Commands](#commands)
  - [list-slots](#list-slots)
  - [list-objects](#list-objects)
  - [key-gen-aes](#key-gen-aes)
  - [key-wrap](#key-wrap)
  - [key-unwrap](#key-unwrap)
  - [help](#help)
- [Usage Examples](#usage-examples)
- [Environment Variables](#environment-variables)
- [Error Handling](#error-handling)

## Installation

The CLI tool is part of the p11ex test applications. To build and run it:

```bash
cd test_apps/p11ex_cli
mix deps.get
mix compile
```

## Configuration

Before using the CLI, you need to configure the PKCS#11 module and authentication credentials. This can be done through:

1. **Environment variables** (recommended for automation)
2. **Command-line options** (recommended for interactive use)

### Required Configuration

- **PKCS#11 Module**: Path to the PKCS#11 library (.so or.dylib file)
- **Token Label**: Label of the token/slot to use
- **PIN**: Authentication PIN for the token

## Global Options

These options are available for all commands:

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--verbose` | `-v` | boolean | false | Output verbose information |
| `--module` | `-m` | string | - | Path to PKCS#11 module file |

### Token Authentication Options

Available for commands that require token access:

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--token-label` | `-l` | string | - | Token label to use |
| `--pin-file` | - | string | - | PIN file to use |

`p11ex_cli` either reads the Token PIN from a file or the environment variable `P11EX_PIN`
as shown below:

```
# from environment variable
env P11EX_PIN=1234 p11ex_cli list-objects --module /somewhere/libsofthsm2.so -l Token_0

# from file
echo -n 1234 > /ramdisk/.pin.txt
p11ex_cli list-objects --module /somewhere/libsofthsm2.so -l Token_0
```

Be careful with PIN files: `p11ex_cli` uses the complete file content including newline characters
as the password. 

### Output Options

Available for commands that produce output:

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--output-format` | `-f` | string | text | Output format (json, text) |

## Commands

### list-slots

Lists available PKCS#11 slots and their associated tokens.

**Usage:**
```bash
p11ex list-slots [OPTIONS]
```

**Options:**
- `--with-token` / `-t` (boolean, default: true): List only slots that contain a token

**Example Output:**
```
Slot 0:
  Description: SoftHSM slot 0
  Manufacturer: SoftHSM project
  Hardware Version: 2.0
  Firmware Version: 2.0
  Flags: [:removable_device, :hw_slot]
  Token Info:
    Label: MyToken
    Manufacturer: SoftHSM project
    Model: SoftHSM v2
    Serial Number: 1234567890
    Hardware Version: 2.0
    Firmware Version: 2.0
    Min. PIN Length: 4
    Max. PIN Length: 256
    Max. Session Count: 1
    Session Count: 0
    Max. R/W Session Count: 1
    Session R/W Count: 0
    Total Private Memory: 65536
    Free Private Memory: 65536
    Total Public Memory: 65536
    Free Public Memory: 65536
    UTC Time: 20240101120000Z
    Flags: [:rng, :login_required, :user_pin_initialized]
```

### list-objects

Lists cryptographic objects (keys, certificates) stored in a token.

**Usage:**
```bash
p11ex list-objects [OPTIONS] <object_type>
```

**Arguments:**
- `object_type` (required): Type of objects to list
  - `seck`: Secret keys
  - `prvk`: Private keys  
  - `pubk`: Public keys

**Options:**
- All global and token authentication options
- `--output-format` / `-f`: Output format (json, text)

**Example Usage:**
```bash
# List all secret keys in text format
p11ex list-objects -m /usr/lib/softhsm/libsofthsm2.so -l MyToken -f text seck

# List all private keys in JSON format
p11ex list-objects -m /usr/lib/softhsm/libsofthsm2.so -l MyToken -f json prvk
```

**Example Output (text format):**
```
Object handle: 1234567890
  :cka_class: :cko_secret_key
  :cka_key_type: :ck_aes
  :cka_label: "MyAESKey"
  :cka_id: 48656C6C6F576F726C64
  :cka_encrypt: true
  :cka_decrypt: true
  :cka_token: true
```

**Example Output (JSON format):**
```json
{
  "handle": 1234567890,
  "attribs": [
    {"attrib": ":cka_class", "value": ":cko_secret_key"},
    {"attrib": ":cka_key_type", "value": ":ck_aes"},
    {"attrib": ":cka_label", "value": "MyAESKey"},
    {"attrib": ":cka_id", "value": "48656C6C6F576F726C64"},
    {"attrib": ":cka_encrypt", "value": "true"},
    {"attrib": ":cka_decrypt", "value": "true"},
    {"attrib": ":cka_token", "value": "true"}
  ]
}
```

### key-gen-aes

Generates new AES key in the token.

**Usage:**
```bash
p11ex key-gen-aes [OPTIONS] <key_label> <key_length>
```

**Arguments:**
- `key_label` (required): Label for the generated key
- `key_length` (required): Key length in bits

**Options:**
- All global and token authentication options
- `--key-id`: Key ID for the key (hex string, random if not provided)
- `--encrypt`: Allow key for encryption (default: true)
- `--decrypt`: Allow key for decryption (default: true)
- `--sign`: Allow key for signing (default: false)
- `--verify`: Allow key for verification (default: false)
- `--wrap`: Allow key for wrapping (default: false)
- `--unwrap`: Allow key for unwrapping (default: false)
- `--derive`: Allow key for deriving (default: false)
- `--extract`: Allow key for extracting (default: false)

**Example Usage:**
```bash
# Generate a 256-bit AES key for encryption/decryption
p11ex key-gen-aes -m /usr/lib/softhsm/libsofthsm2.so -l MyToken "MyAESKey" 256

# Generate a key with specific ID and signing capabilities
p11ex key-gen-aes -m /usr/lib/softhsm/libsofthsm2.so -l MyToken \
  --key-id 48656C6C6F576F726C64 \
  --sign --verify \
  "MySigningKey" 256
```

**Example Output:**
```
Generated new key ID: 48656c6c6f576f726c64
Key generated. Object handle: 1234567890abcdef
```

### key-wrap

Wraps (encrypts) a cryptographic key using another key (the wrapping key). The wrapped key is exported as encrypted bytes that can be stored externally or transferred to another token.

**Usage:**
```bash
p11ex key-wrap [OPTIONS] <mechanism> <wrapping_key_ref> <key_ref> <output_file>
```

**Arguments:**
- `mechanism` (required): Wrapping mechanism to use
  - `ckm_aes_key_wrap_pad`: AES key wrapping with padding
  - `ckm_rsa_pkcs`: RSA PKCS#1 v1.5 encryption
  - `ckm_rsa_pkcs_oaep`: RSA PKCS#1 OAEP encryption
- `wrapping_key_ref` (required): Reference to the wrapping key
  - Format: `label:name`, `id:hexstring`, or `handle:number`
  - The key must have `CKA_WRAP` attribute set to true
- `key_ref` (required): Reference to the key to wrap
  - Format: `label:name`, `id:hexstring`, or `handle:number`
  - The key must have `CKA_EXTRACTABLE` attribute set to true
- `output_file` (required): Path where wrapped key will be written

**Options:**
- All global and token authentication options
- `--output-format` / `-f`: Output format for wrapped key (default: hex)
  - `binary`: Raw binary format
  - `hex`: Hexadecimal encoding (lowercase)
  - `base64`: Base64 encoding

**Example Usage:**
```bash
# Wrap an AES key using another AES key, output as hex
p11ex key-wrap -m /usr/lib/softhsm/libsofthsm2.so -l MyToken \
  ckm_aes_key_wrap_pad \
  label:MyWrappingKey \
  label:MyKeyToWrap \
  wrapped_key.hex

# Wrap a private key using RSA public key, output as base64
p11ex key-wrap -m /usr/lib/softhsm/libsofthsm2.so -l MyToken \
  --output-format base64 \
  ckm_rsa_pkcs_oaep \
  label:MyRSAPublicKey \
  id:48656c6c6f \
  wrapped_key.b64
```

**Example Output:**
```
Wrapped key written to: wrapped_key.hex
```

**Notes:**
- The wrapping key must be marked with `CKA_WRAP=true` during key generation
- The key to wrap must be marked with `CKA_EXTRACTABLE=true` during key generation
- Supported key combinations depend on the token implementation
- Common use cases:
  - Wrapping AES keys with AES keys
  - Wrapping RSA/EC private keys with AES keys
  - Wrapping AES/RSA keys with RSA public keys

### key-unwrap

Unwraps (decrypts) a previously wrapped key and imports it into the token as a new key object.

**Usage:**
```bash
p11ex key-unwrap [OPTIONS] <mechanism> <unwrapping_key_ref> <input_file>
```

**Arguments:**
- `mechanism` (required): Unwrapping mechanism (must match the mechanism used for wrapping)
  - `ckm_aes_key_wrap_pad`: AES key unwrapping with padding
  - `ckm_rsa_pkcs`: RSA PKCS#1 v1.5 decryption
  - `ckm_rsa_pkcs_oaep`: RSA PKCS#1 OAEP decryption
- `unwrapping_key_ref` (required): Reference to the unwrapping key
  - Format: `label:name`, `id:hexstring`, or `handle:number`
  - The key must have `CKA_UNWRAP` attribute set to true
- `input_file` (required): Path to file containing wrapped key bytes

**Options:**
- All global and token authentication options
- `--input-format` / `-f`: Input format for wrapped key (default: hex)
  - `binary`: Raw binary format
  - `hex`: Hexadecimal encoding
  - `base64`: Base64 encoding
- `--key-label` (required): Label for the unwrapped key
- `--key-id`: Key ID for the unwrapped key (hex string, random if not provided)
- `--key-type` (required): Type of key being unwrapped
  - `aes`: AES secret key
  - `rsa`: RSA key
  - `ec`: Elliptic curve key
- `--key-class` (required): Object class of key being unwrapped
  - `seck`: Secret key
  - `prvk`: Private key
  - `pubk`: Public key
- `--encrypt`: Allow key for encryption (default: false)
- `--decrypt`: Allow key for decryption (default: false)
- `--sign`: Allow key for signing (default: false)
- `--verify`: Allow key for verification (default: false)
- `--wrap`: Allow key for wrapping (default: false)
- `--unwrap`: Allow key for unwrapping (default: false)
- `--derive`: Allow key for key derivation (default: false)
- `--extract`: Mark key as extractable (default: false)
- `--token`: Store key on token (persistent) (default: true)

**Example Usage:**
```bash
# Unwrap an AES key from hex file
p11ex key-unwrap -m /usr/lib/softhsm/libsofthsm2.so -l MyToken \
  --key-label "ImportedAESKey" \
  --key-type aes \
  --key-class seck \
  --encrypt --decrypt \
  ckm_aes_key_wrap_pad \
  label:MyWrappingKey \
  wrapped_key.hex

# Unwrap an RSA private key from base64 file with specific attributes
p11ex key-unwrap -m /usr/lib/softhsm/libsofthsm2.so -l MyToken \
  --input-format base64 \
  --key-label "ImportedRSAKey" \
  --key-id 48656c6c6f \
  --key-type rsa \
  --key-class prvk \
  --sign --decrypt \
  ckm_rsa_pkcs_oaep \
  label:MyRSAPrivateKey \
  wrapped_key.b64
```

**Example Output:**
```
Generated new key ID: a3f2c8d4e5b6f7a8
Key unwrapped successfully
Object handle: 1a2b3c4d5e6f7890
```

**Notes:**
- The unwrapping key must be marked with `CKA_UNWRAP=true` during key generation
- The unwrapping mechanism must match the wrapping mechanism used
- You must specify the correct key type and class for the unwrapped key
- Key attributes (encrypt, decrypt, sign, etc.) can be set during unwrap
- The unwrapped key is a completely new key object with a new handle

### help

Shows help information for commands.

**Usage:**
```bash
p11ex help [subcommand]
```

**Arguments:**
- `subcommand` (optional): Specific command to get help for

**Examples:**
```bash
# Show general usage
p11ex help

# Show help for specific command
p11ex help list-objects
p11ex help key-gen-aes
```

## Usage Examples

### Basic Workflow

1. **List available slots:**
   ```bash
   p11ex list-slots -m /usr/lib/softhsm/libsofthsm2.so
   ```

2. **List objects in a token:**
   ```bash
   p11ex list-objects -m /usr/lib/softhsm/libsofthsm2.so -l MyToken seck
   ```

3. **Generate a new key:**
   ```bash
   p11ex key-gen-aes -m /usr/lib/softhsm/libsofthsm2.so -l MyToken "NewKey" 256
   ```

### Using Environment Variables

For automation and scripts, use environment variables:

```bash
export P11EX_MODULE=/usr/lib/softhsm/libsofthsm2.so
export P11EX_PIN=1234

p11ex list-slots
p11ex list-objects -l MyToken seck
```

### Using PIN Files

For enhanced security, store PINs in files:

```bash
echo "1234" > /secure/path/pin.txt
chmod 600 /secure/path/pin.txt

p11ex list-objects -m /usr/lib/softhsm/libsofthsm2.so \
  -l MyToken \
  --pin-file /secure/path/pin.txt \
  seck
```

### JSON Output for Scripting

Use JSON output format for programmatic processing:

```bash
p11ex list-objects -m /usr/lib/softhsm/libsofthsm2.so \
  -l MyToken \
  -f json \
  seck | jq '.[] | select(.attribs[] | select(.attrib == ":cka_label") | .value == "MyKey")'
```

### Key Wrapping and Unwrapping Workflow

This example demonstrates how to wrap a key for export and then unwrap it back into the token:

```bash
# Step 1: Generate a wrapping key with wrap/unwrap capabilities
p11ex key-gen-aes -m /usr/lib/softhsm/libsofthsm2.so -l MyToken \
  --wrap --unwrap \
  "MyWrappingKey" 256

# Step 2: Generate a key to be wrapped (must be extractable)
p11ex key-gen-aes -m /usr/lib/softhsm/libsofthsm2.so -l MyToken \
  --encrypt --decrypt --extract \
  "MySecretKey" 256

# Step 3: Wrap the key for export (outputs to hex file by default)
p11ex key-wrap -m /usr/lib/softhsm/libsofthsm2.so -l MyToken \
  ckm_aes_key_wrap_pad \
  label:MyWrappingKey \
  label:MySecretKey \
  exported_key.hex

# Step 4: The wrapped key can now be stored externally or transferred
# Later, unwrap it back into the token with new attributes
p11ex key-unwrap -m /usr/lib/softhsm/libsofthsm2.so -l MyToken \
  --key-label "ImportedSecretKey" \
  --key-type aes \
  --key-class seck \
  --encrypt --decrypt \
  ckm_aes_key_wrap_pad \
  label:MyWrappingKey \
  exported_key.hex
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `P11EX_MODULE` | Path to PKCS#11 module file | Yes* |
| `P11EX_PIN` | Authentication PIN for token | Yes* |

*Required if not specified via command-line options

## Error Handling

The CLI provides detailed error messages for common issues:

- **Module loading errors**: Invalid module path or incompatible library
- **Authentication errors**: Invalid PIN or token access issues
- **Token errors**: Token not found, insufficient permissions
- **Object errors**: Invalid object types, object not found
- **Validation errors**: Invalid arguments or options

**Exit Codes:**
- `0`: Success
- `1`: General error (module loading, authentication, etc.)
- `2`: Validation error (invalid arguments, options, etc.)
