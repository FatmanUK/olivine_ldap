#!/usr/bin/env bash
# Stand up a KDC and a GSSAPI-accepting slapd, inside the oracle
# container. Runs as the container's unprivileged uid: every path
# is under /data and the KDC listens above 1024, so none of this
# needs root.
#
# Two realms, from one krb5kdc process serving both. The second
# exists to compare the cross-realm case, where the identity a
# bind produces is not the one reading the C suggests — see
# saslDN in internal/store/saslgssapi.go.
set -euo pipefail

realm=$1
other=$2
self=$3
peer=$4
export KRB5_CONFIG=/data/krb5.conf
export KRB5_KDC_PROFILE=/data/kdc.conf
mkdir -p /data/krb5

# Braces go on their own lines. MIT's profile parser does not
# read `REALM = { kdc = host }`, and it does not complain either:
# the realm simply has no kdc, and kinit says "Cannot find KDC
# for realm", which reads like a missing realm rather than a
# syntax error.
cat > "$KRB5_CONFIG" <<EOF
[libdefaults]
  default_realm = $realm
  dns_lookup_kdc = false
  dns_lookup_realm = false
  dns_canonicalize_hostname = false
  rdns = false
  udp_preference_limit = 1
[realms]
  $realm = {
    kdc = 127.0.0.1:18088
  }
  $other = {
    kdc = 127.0.0.1:18088
  }
# Without this the client derives a realm from the host's domain
# — podman's search domain is dns.podman — and asks the KDC for
# krbtgt/DNS.PODMAN, which does not exist. Mapping the domain is
# what every real deployment does and what the error is telling
# you to do.
[domain_realm]
  .olivine.test = $realm
  olivine.test = $realm
# The direct cross-realm path, in both directions.
[capaths]
  $other = {
    $realm = .
  }
  $realm = {
    $other = .
  }
EOF
cat > "$KRB5_KDC_PROFILE" <<EOF
[kdcdefaults]
  kdc_ports = 18088
  kdc_tcp_ports = 18088
[realms]
  $realm = {
    database_name = /data/krb5/principal
    key_stash_file = /data/krb5/.k5.$realm
    acl_file = /data/krb5/kadm5.acl
    max_life = 1h
  }
  $other = {
    database_name = /data/krb5/principal-other
    key_stash_file = /data/krb5/.k5.$other
    acl_file = /data/krb5/kadm5.acl
    max_life = 1h
  }
EOF

ka() {
	/usr/sbin/kadmin.local -r "$1" -q "$2" >/dev/null 2>&1
}

/usr/sbin/kdb5_util -r "$realm" create -s -P masterA \
	>/dev/null 2>&1
/usr/sbin/kdb5_util -r "$other" create -s -P masterB \
	>/dev/null 2>&1

# A service principal and keytab for each server, both in the
# first realm: the service is what the realms are crossed *to*.
ka "$realm" "addprinc -randkey ldap/$self@$realm"
ka "$realm" "addprinc -randkey ldap/$peer@$realm"
ka "$realm" \
	"ktadd -k /data/krb5/oracle.keytab ldap/$self@$realm"
ka "$realm" \
	"ktadd -k /shared/olivine.keytab ldap/$peer@$realm"

# The cross-realm trust: one principal, the same key in both
# realms. Same password and the same principal name means the
# same salt, so the keys agree without being copied about.
ka "$realm" "addprinc -pw crosskey krbtgt/$realm@$other"
ka "$other" "addprinc -pw crosskey krbtgt/$realm@$other"

ka "$realm" "addprinc -pw testpw tester@$realm"
ka "$other" "addprinc -pw testpw tester@$other"

/usr/sbin/krb5kdc -r "$realm" -r "$other" -n >/dev/null 2>&1 &

cat > /data/slapd.conf <<EOF
include /opt/openldap/etc/openldap/schema/core.schema
pidfile /data/slapd.pid
argsfile /data/slapd.args
database mdb
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory /data
EOF
export KRB5_KTNAME=/data/krb5/oracle.keytab
/opt/openldap/libexec/slapd -f /data/slapd.conf \
	-h "ldap://0.0.0.0:10389/" -d 0 &

# The client script runs later, through podman exec, which gets
# none of this environment — so it is written down for it.
cat > /data/env.sh <<EOF
export KRB5_CONFIG=$KRB5_CONFIG
export KRB5_KDC_PROFILE=$KRB5_KDC_PROFILE
EOF

sleep 2
touch /shared/ready
wait
