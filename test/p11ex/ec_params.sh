#!/usr/bin/env bash

set -e

curves=(
  "secp192r1:1.2.840.10045.3.1.1"
  "secp224r1:1.3.132.0.33"
  "secp256r1:1.2.840.10045.3.1.7"
  "secp384r1:1.3.132.0.34"
  "secp521r1:1.3.132.0.35"
  "brainpoolP256r1:1.3.36.3.3.2.8.1.1.7"
  "brainpoolP384r1:1.3.36.3.3.2.8.1.1.11"
  "brainpoolP512r1:1.3.36.3.3.2.8.1.1.13"
  "X25519:1.3.101.110"
  "Ed25519:1.3.101.112")

for entry in "${curves[@]}"; do
  IFS=":" read -r name oid <<< "$entry"

  # Convert OID string to Erlang/Elixir list format
  erlang_oid=$(echo $oid | tr '.' ',' | sed 's/^/{/' | sed 's/$/}/')

  openssl asn1parse -noout -genconf <(echo -e "asn1=OID:$oid") -out /tmp/ec_params.der

  # Convert hex to 0x-prefixed bytes with commas
  hex=$(cat /tmp/ec_params.der | xxd -p)

  # Split into pairs of hex digits and format with 0x prefix
  formatted=$(echo $hex | sed 's/\(..\)/0x\1, /g' | sed 's/, $//')
  echo "{:$name, $erlang_oid, <<$formatted>>}"
done
