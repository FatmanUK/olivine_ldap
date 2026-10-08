#!/usr/bin/env bash
# Derive the schema slapd hardcodes in schema_init.c.
#
# core.schema comments out cn, name and others because
# schema_init.c defines them in C, so a server that loads only
# the .schema files is missing attributes every DN needs.
#
# The hardcoded set is exactly what slapd emits from
# cn=Subschema minus what the .schema files define. Computing it
# beats transcribing 6,979 lines of schema_init.c by hand, and
# it cannot drift from the submodule it was derived from.
#
# Needs internal/schema/testdata/subschema.ldif; run
# scripts/capture-subschema.sh first.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

sub=internal/schema/testdata/subschema.ldif
out=internal/schema/builtin.ldif
schemas=openldap/servers/slapd/schema

if [ ! -f "$sub" ]; then
	echo "missing $sub; run scripts/capture-subschema.sh" >&2
	exit 1
fi

# OIDs the .schema files define. A commented-out definition
# does not count, which is the whole point.
grep -h -E '^(attributetype|objectclass|attributeType|objectClass)' \
	"$schemas"/*.schema \
	| sed -E 's/^[a-zA-Z]+[[:space:]]*\([[:space:]]*//' \
	| awk '{print $1}' | sort -u > /tmp/olivine-file-oids.$$

trap 'rm -f /tmp/olivine-file-oids.$$' EXIT

{
	echo "# Derived by scripts/derive-builtin.sh."
	echo "# The schema slapd hardcodes in schema_init.c:"
	echo "# what it emits from cn=Subschema minus what the"
	echo "# .schema files define. Do not edit by hand."
	for key in attributeTypes objectClasses; do
		grep "^${key}:" "$sub" | while IFS= read -r line; do
			def=${line#*: }
			oid=$(printf '%s' "$def" \
				| sed -E 's/^\([[:space:]]*//' \
				| awk '{print $1}')
			if ! grep -qxF "$oid" /tmp/olivine-file-oids.$$
			then
				printf '%s %s\n' "$key" "$def"
			fi
		done
	done
} > "$out"

echo "derive-builtin: wrote $out"
grep -c '^attributeTypes ' "$out" | sed 's/^/  attributeTypes: /'
grep -c '^objectClasses ' "$out" | sed 's/^/  objectClasses:  /'
