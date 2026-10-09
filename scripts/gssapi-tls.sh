#!/usr/bin/env bash
# Generate the TLS material the GSSAPI comparison needs.
#
# Olivine is TLS-only, so the GSSAPI bind it serves runs over
# ldaps — which is the configuration slapd is happy with too:
# connection.c:1400-1419 hands the TLS state to the SASL layer
# rather than refusing the pairing.
#
# Separate from gssapi-compare.sh only because the oracle image
# ships no openssl, so the certificates have to be made on the
# host and mounted in.
set -euo pipefail

dir=$1
host=$2

openssl req -x509 -newkey ec \
	-pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$dir/key.pem" -out "$dir/cert.pem" -days 1 \
	-subj "/CN=$host" \
	-addext "subjectAltName=DNS:$host" 2>/dev/null
chmod 644 "$dir/key.pem" "$dir/cert.pem"
