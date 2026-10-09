#!/usr/bin/env bash
# Bind to one server with upstream's ldapwhoami over GSSAPI, as
# one principal, and print what the server says the identity is.
#
# -O maxssf=0 asks for no SASL security layer. Olivine offers
# only that, because it is TLS-only and a second layer inside
# TLS protects nothing; the oracle is asked for the same so the
# two are compared doing the same thing.
set -euo pipefail

. /data/env.sh
uri=$1
principal=$2

# A fresh cache per bind: the point of the cross-realm case is
# which principal is presented, so a leftover ticket for the
# other one would quietly compare the same thing twice.
kdestroy >/dev/null 2>&1 || true
echo testpw | kinit "$principal" >/dev/null 2>&1

# -N turns off SASL host-name canonicalization. Nothing to do
# with the protocol: podman's DNS answers with its own search
# domain appended, so the client would ask for a ticket for
# ldap/<host>.dns.podman and then derive a realm named after it.
# Without -N the error is "Server krbtgt/DNS.PODMAN not found in
# Kerberos database", which reads like a KDC fault and is not.
LDAPTLS_REQCERT=never /opt/openldap/bin/ldapwhoami \
	-H "$uri" -Y GSSAPI -O maxssf=0 -N 2>&1 \
	| grep '^dn:' || true
