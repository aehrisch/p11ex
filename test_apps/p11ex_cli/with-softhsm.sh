#!/usr/bin/env bash

export SOFTHSM_PREFIX=${SOFTHSM_PREFIX:-/Users/eric/hack/softhsm-2.6.1}
export P11TOOL_PREFIX=${P11TOOL_PREFIX:-/opt/homebrew}

export SOFTHSM2_CONF=cli-softhsm.conf

export P11EX_PIN=1234
export P11EX_MODULE=${P11EX_MODULE:-${SOFTHSM_PREFIX}/lib/softhsm/libsofthsm2.so}
export P11EX_TOKEN_LABEL=Token_0

if [ ! -d "token" ]; then
  echo "### token directory does not exist, initializing"
  mkdir -p token
  source ./cli-softhsm-init.sh
fi

echo "### Running tests with existing token"

exec ./p11ex_cli $@
