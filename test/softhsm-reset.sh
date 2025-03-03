#!/usr/bin/env bash

set -e
rm -rf /var/lib/softhsm/tokens
mkdir -p /var/lib/softhsm/tokens

softhsm2-util --init-token --slot 0 --label Token_0 --pin 1234 --so-pin 12345678

softhsm2-util --show-slots

export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export PKCS11_TOKEN_LABEL=Token_0
export PKCS11_TOKEN_PIN=1234
export PKCS11_TOKEN_SO_PIN=12345678

pkcs11-tool --module ${PKCS11_MODULE} --list-mechanisms

echo "### Generating AES keys"
pkcs11-tool --module ${PKCS11_MODULE} \
  --login --pin ${PKCS11_TOKEN_PIN} --token ${PKCS11_TOKEN_LABEL} \
  --keygen --label "aes_128" --id 10 \
  --key-type AES:16

pkcs11-tool --module ${PKCS11_MODULE} \
  --login --pin ${PKCS11_TOKEN_PIN} --token ${PKCS11_TOKEN_LABEL} \
  --keygen --label "aes_192" --id 11 \
  --key-type AES:24

pkcs11-tool --module ${PKCS11_MODULE} \
  --login --pin ${PKCS11_TOKEN_PIN} --token ${PKCS11_TOKEN_LABEL} \
  --keygen --label "aes_256" --id 12 \
  --key-type AES:32

echo "### Listing objects"
pkcs11-tool --module ${PKCS11_MODULE} --token ${PKCS11_TOKEN_LABEL} \
  --login --pin ${PKCS11_TOKEN_PIN} \
  --list-objects

echo "### Done"
exit 0
