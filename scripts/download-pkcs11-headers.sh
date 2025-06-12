#!/bin/bash
set -e

# Download PKCS11 headers
cd c_src
curl -z pkcs11.h -O https://raw.githubusercontent.com/oasis-tcs/pkcs11/master/published/3-01/pkcs11.h
curl -z pkcs11t.h -O https://raw.githubusercontent.com/oasis-tcs/pkcs11/master/published/3-01/pkcs11t.h
curl -z pkcs11f.h -O https://raw.githubusercontent.com/oasis-tcs/pkcs11/master/published/3-01/pkcs11f.h
cd .. 
