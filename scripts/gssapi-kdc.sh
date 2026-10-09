#!/usr/bin/env bash
# Stand up a KDC and a GSSAPI-accepting slapd, inside the oracle
# container. Runs as the container's unprivileged uid: every
# path is under /data and the KDC listens above 1024, so none of
# this needs root.
set -euo pipefail

realm=$1
self=$2
other=$3
export KRB5_CONFIG=/data/krb5.conf
export KRB5_KDC_PROFILE=/data/kdc.conf
mkdir -p /data/krb5

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
# Without this the client derives a realm from the host's domain
# — podman's search domain is dns.podman — and asks the KDC for
# krbtgt/DNS.PODMAN, which does not exist. Mapping the domain is
# what every real deployment does and what the error is telling
# you to do.
[domain_realm]
  .olivine.test = $realm
  olivine.test = $realm
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
EOF

kadm() { /usr/sbin/kadmin.local -q "$1" >/dev/null 2>&1; }

/usr/sbin/kdb5_util create -s -P masterpw >/dev/null 2>&1
kadm "addprinc -pw testpw tester@$realm"
kadm "addprinc -randkey ldap/$self@$realm"
kadm "addprinc -randkey ldap/$other@$realm"
kadm "ktadd -k /data/krb5/oracle.keytab ldap/$self@$realm"
kadm "ktadd -k /shared/olivine.keytab ldap/$other@$realm"
/usr/sbin/krb5kdc -n >/dev/null 2>&1 &

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
