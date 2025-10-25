#!/usr/bin/env bash

export TEST_P11EX_PIN=1234
export TEST_P11EX_MODULE=${TEST_P11EX_MODULE:-/Users/eric/hack/softhsm/lib/softhsm/libsofthsm2.so}
export TEST_P11EX_TOKEN_LABEL=Token_0

export SOFTHSM_PREFIX=${SOFTHSM_PREFIX:-/Users/eric/hack/softhsm-2.6.1}
export P11TOOL_PREFIX=${P11TOOL_PREFIX:-/opt/homebrew}

export SOFTHSM2_CONF=cli-softhsm.conf

if [ ! -d "token" ]; then
  echo "### token directory does not exist, initializing"
  mkdir -p token
  source ./cli-softhsm-init.sh
fi

echo "### Running tests with existing token"

#exec env MIX_ENV=test mix test --cover $@
exec env MIX_ENV=test mix coveralls.html $@
