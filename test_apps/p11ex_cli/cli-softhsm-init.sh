#!/usr/bin/env bash

set -e

rm -rfv token/*

${SOFTHSM_PREFIX}/bin/softhsm2-util --init-token \
  --slot 0 --label "${TEST_P11EX_TOKEN_LABEL}" \
  --so-pin ${TEST_P11EX_PIN}${TEST_P11EX_PIN} \
  --pin ${TEST_P11EX_PIN}

echo
echo "### Generating AES keys"
${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${TEST_P11EX_MODULE} \
  --login --pin ${TEST_P11EX_PIN} --token ${TEST_P11EX_TOKEN_LABEL} \
  --keygen --label "aes_128" --id 10 \
  --key-type AES:16

${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${TEST_P11EX_MODULE} \
  --login --pin ${TEST_P11EX_PIN} --token ${TEST_P11EX_TOKEN_LABEL} \
  --keygen --label "aes_192" --id 11 \
  --key-type AES:24

${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${TEST_P11EX_MODULE} \
  --login --pin ${TEST_P11EX_PIN} --token ${TEST_P11EX_TOKEN_LABEL} \
  --keygen --label "aes_256" --id 12 \
  --key-type AES:32

echo
echo "### Wrapping keys"

# an extractable AES key
${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${TEST_P11EX_MODULE} \
  --login --pin ${TEST_P11EX_PIN} --token ${TEST_P11EX_TOKEN_LABEL} \
  --keygen --label "extractable_aes" --id 20 \
  --key-type AES:32 --extractable

# a AES key that can be used for wrapping
${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${TEST_P11EX_MODULE} \
  --login --pin ${TEST_P11EX_PIN} --token ${TEST_P11EX_TOKEN_LABEL} \
  --keygen --label "wrapping_aes" --id 21 \
  --key-type AES:32 --usage-wrap 

# a RSA key that can be used for wrapping
${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${TEST_P11EX_MODULE} \
  --login --pin ${TEST_P11EX_PIN} --token ${TEST_P11EX_TOKEN_LABEL} \
  --keypairgen --label "wrapping_rsa" --id 22 \
  --key-type RSA:2048 --usage-wrap
