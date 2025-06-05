#!/usr/bin/env bash

export SOFTHSM2_CONF=$(mktemp)
export SOFTHSM_PREFIX=${SOFTHSM_PREFIX:-/Users/eric/hack/softhsm-2.6.1}
export PKCS11_MODULE=${SOFTHSM_PREFIX}/lib/softhsm/libsofthsm2.so
export P11TOOL_PREFIX=${P11TOOL_PREFIX:-/opt/homebrew}
export MAKE_TOKEN_DIR=true

./test/softhsm-reset.sh

mix test --cover --exclude yubikey
