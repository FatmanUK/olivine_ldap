#!/usr/bin/env bash
# Derive the schema Olivine ships with.
#
# Everything slapd emits from cn=Subschema for the schema files
# the oracle loads: the definitions hardcoded in schema_init.c
# plus core, cosine and nis. Embedding it means a Go-only binary
# can resolve dc, ou and person without the submodule — which the
# CI checkout does not fetch, and which a deployed container has
# no business carrying.
#
# Derived rather than transcribed, like builtin.ldif, so it cannot
# drift from the upstream it came from. Regenerate after bumping
# the submodule:
#
#   make golden-build
#   scripts/capture-subschema.sh
#   scripts/derive-standard.sh
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

sub=internal/schema/testdata/subschema.ldif
out=internal/schema/standard.ldif

if [ ! -f "$sub" ]; then
	echo "missing $sub; run scripts/capture-subschema.sh" >&2
	exit 1
fi

{
	echo "# Derived by scripts/derive-standard.sh from"
	echo "# slapd's own cn=Subschema. Do not edit by hand."
	echo "#"
	echo "# Every definition slapd registers for the schema"
	echo "# files the oracle loads, hardcoded ones included."
	for key in attributeTypes objectClasses; do
		grep "^${key}:" "$sub" | while IFS= read -r line; do
			printf '%s %s\n' "$key" "${line#*: }"
		done
	done
} > "$out"

echo "derive-standard: wrote $out"
grep -c '^attributeTypes ' "$out" | sed 's/^/  attributeTypes: /'
grep -c '^objectClasses ' "$out" | sed 's/^/  objectClasses:  /'
