#!/usr/bin/env bash

export PKCS11_MODULE=${PKCS11_MODULE:-/opt/homebrew/lib/libykcs11.dylib}
export P11TOOL_PREFIX=/opt/homebrew
export MAKE_TOKEN_DIR=true

mix test --cover --only yubikey
