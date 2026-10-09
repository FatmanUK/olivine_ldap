#!/usr/bin/env bash
# Compare a SASL GSSAPI bind against slapd and against Olivine.
#
# The client is upstream's own ldapwhoami, driven at each server
# in turn, because a GSSAPI *initiator* written in Go would be a
# second implementation of the thing under test. What is compared
# is the DN each server says the bind produced.
#
# Three containers on one network: the oracle, which also runs
# the KDC and the client; Olivine; and Postgres for Olivine to
# talk to. Olivine never contacts the KDC — an acceptor decrypts
# the ticket with its own keytab — so only the client needs it.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

oracle="olivine-oracle:$(git -C openldap describe \
	--tags --always 2>/dev/null || echo none)"
image=${IMAGE:-ghcr.io/fatmanuk/olivine-ldap}
tag=$(git describe --tags --always --dirty 2>/dev/null \
	|| echo dev)
net=olivine-gss
kdc=olivine-gss-kdc
srv=olivine-gss-srv
pg=olivine-gss-pg
realm=OLIVINE.TEST
# Fully-qualified names in a domain the KDC maps to the realm.
# A bare container name sends the client looking for a realm
# named after podman's own search domain.
kdcHost=oracle.olivine.test
srvHost=olivine.olivine.test

if ! podman image exists "$oracle"; then
	echo "gssapi: $oracle absent; run make golden-build" >&2
	exit 1
fi
if ! podman image exists "$image:$tag"; then
	echo "gssapi: $image:$tag absent; run make pod-build" >&2
	exit 1
fi

purge() {
	podman rm -f "$srv" "$kdc" "$pg" >/dev/null 2>&1 || true
	podman network rm -f "$net" >/dev/null 2>&1 || true
}
purge

dir=$(mktemp -d)
# 0777 so the container's uid — a subuid on the host — can write
# the keytabs it generates into the shared directory.
chmod 777 "$dir"
cleanup() {
	purge
	rm -rf "$dir"
}
trap cleanup EXIT

./scripts/gssapi-tls.sh "$dir" "$srvHost"
cp scripts/gssapi-kdc.sh "$dir/kdc.sh"
cp scripts/gssapi-client.sh "$dir/client.sh"
chmod 755 "$dir"/*.sh

podman network create "$net" >/dev/null

echo "gssapi: starting Postgres"
podman run -d --name "$pg" --network "$net" \
	-e POSTGRES_USER=olivine \
	-e POSTGRES_PASSWORD=olivine \
	-e POSTGRES_DB=olivine \
	docker.io/library/postgres:17-alpine >/dev/null
for _ in $(seq 1 120); do
	podman exec "$pg" pg_isready -U olivine \
		>/dev/null 2>&1 && break
	sleep 0.5
done

echo "gssapi: starting the KDC and the oracle"
podman run -d --name "$kdc" --network "$net" \
	--hostname "$kdcHost" \
	--volume "$dir:/shared" \
	--entrypoint /bin/bash "$oracle" \
	/shared/kdc.sh "$realm" "$kdcHost" "$srvHost" \
	>/dev/null

for _ in $(seq 1 120); do
	[ -f "$dir/ready" ] && break
	sleep 0.5
done
if [ ! -f "$dir/ready" ]; then
	echo "gssapi: the KDC did not come up" >&2
	podman logs "$kdc" 2>&1 | tail -30 >&2
	exit 1
fi

hash=$(go run ./cmd/olivined -hash gsstest)
echo "gssapi: starting Olivine"
podman run -d --name "$srv" --network "$net" \
	--hostname "$srvHost" \
	--volume "$dir:/shared:ro" \
	--env OLIVINE_TLS_CERT=/shared/cert.pem \
	--env OLIVINE_TLS_KEY=/shared/key.pem \
	--env OLIVINE_KRB5_KEYTAB=/shared/olivine.keytab \
	--env OLIVINE_DSN="host=${pg} port=5432 user=olivine \
password=olivine dbname=olivine sslmode=disable" \
	--env OLIVINE_SUFFIX="dc=example,dc=com" \
	--env OLIVINE_ROOT_DN="cn=admin,dc=example,dc=com" \
	--env OLIVINE_ROOT_PASSWORD_HASH="$hash" \
	"$image:$tag" >/dev/null

echo "gssapi: binding to each server with upstream ldapwhoami"
run_client() {
	podman exec "$kdc" /bin/bash /shared/client.sh "$1" \
		2>&1 || true
}
want=$(run_client "ldap://${kdcHost}:10389")
got=$(run_client "ldaps://${srvHost}:6360")

printf 'oracle:  %s\n' "$want"
printf 'olivine: %s\n' "$got"

if ! printf '%s' "$want" | grep -q '^dn:'; then
	echo "gssapi: the oracle did not answer a GSSAPI bind" >&2
	podman logs "$kdc" 2>&1 | tail -30 >&2
	exit 1
fi
if [ "$want" != "$got" ]; then
	echo "gssapi: the two servers disagree" >&2
	podman logs "$srv" 2>&1 | tail -30 >&2
	exit 1
fi
echo "gssapi: ok — both answered $got"
