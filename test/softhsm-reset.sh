#!/usr/bin/env bash

set -e

export PKCS11_MODULE=${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}
export PKCS11_TOKEN_LABEL=${PKCS11_TOKEN_LABEL:-Token_0}
export PKCS11_TOKEN_PIN=${PKCS11_TOKEN_PIN:-1234}
export PKCS11_TOKEN_SO_PIN=${PKCS11_TOKEN_SO_PIN:-12345678}

if [ -n "${MAKE_TOKEN_DIR}" ]; then

  export TOKEN_DIR=${TOKEN_DIR:-$(mktemp -d)}
  export SOFTHSM2_CONF=${SOFTHSM2_CONF:-$(mktemp)}

  echo "### Creating SoftHSM token data in ${TOKEN_DIR}"

  cat > ${SOFTHSM2_CONF} <<EOF
directories.tokendir = ${TOKEN_DIR}
objectstore.backend = file
EOF

  echo "### env"
  echo "env PKCS11_MODULE=${PKCS11_MODULE} SOFTHSM2_CONF=${SOFTHSM2_CONF}"
  echo "${SOFTHSM2_CONF}" > sofhsm-conf.path
fi

export SOFTHSM_PREFIX=${SOFTHSM_PREFIX:-/usr}
export P11TOOL_PREFIX=${P11TOOL_PREFIX:-/usr}

echo "### Initializing SoftHSM token"
${SOFTHSM_PREFIX}/bin/softhsm2-util --init-token --slot 0 \
  --label "$PKCS11_TOKEN_LABEL" \
  --pin "$PKCS11_TOKEN_PIN" \
  --so-pin "$PKCS11_TOKEN_SO_PIN"

${SOFTHSM_PREFIX}/bin/softhsm2-util --show-slots

${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${PKCS11_MODULE} --list-mechanisms

echo
echo "### Generating AES keys"
${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${PKCS11_MODULE} \
  --login --pin ${PKCS11_TOKEN_PIN} --token ${PKCS11_TOKEN_LABEL} \
  --keygen --label "aes_128" --id 10 \
  --key-type AES:16

${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${PKCS11_MODULE} \
  --login --pin ${PKCS11_TOKEN_PIN} --token ${PKCS11_TOKEN_LABEL} \
  --keygen --label "aes_192" --id 11 \
  --key-type AES:24

${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${PKCS11_MODULE} \
  --login --pin ${PKCS11_TOKEN_PIN} --token ${PKCS11_TOKEN_LABEL} \
  --keygen --label "aes_256" --id 12 \
  --key-type AES:32

echo
echo "### Listing objects"
${P11TOOL_PREFIX}/bin/pkcs11-tool --module ${PKCS11_MODULE} --token ${PKCS11_TOKEN_LABEL} \
  --login --pin ${PKCS11_TOKEN_PIN} \
  --list-objects

echo "### Done"

exit 0
