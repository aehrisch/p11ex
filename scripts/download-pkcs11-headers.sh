#!/bin/bash
set -e

url=https://raw.githubusercontent.com/oasis-tcs/pkcs11/master/published/3-01
files=(pkcs11.h pkcs11t.h pkcs11f.h)

for file in "${files[@]}"; do
  curl -L --no-progress-meter -o $1/$file $url/$file
done
