#!/usr/bin/env bash

export P11TOOL_PREFIX=${P11TOOL_PREFIX:-/opt/homebrew}

if [ -n "${DO_SPY:-}" ]; then
echo "### Running with spy"
  export P11EX_MODULE=/opt/homebrew/Cellar/opensc/0.26.1/lib/pkcs11-spy.so
  export PKCS11SPY="/opt/homebrew/lib/libykcs11.dylib"
  # Optional, stderr will be used for logging if not set
  # export PKCS11SPY_OUTPUT="/path/to/pkcs11-spy.log"
else
  export P11EX_MODULE=/opt/homebrew/lib/libykcs11.dylib
fi

export P11EX_TOKEN_LABEL="YubiKey PIV #19666192"

exec ./p11ex_cli $@

