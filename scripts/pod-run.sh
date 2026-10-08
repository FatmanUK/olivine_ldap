#!/usr/bin/env bash
# Smoke-test the Olivine image.
#
# Stands up a dedicated network, a throwaway Postgres on it, and
# the server image, then checks the server serves TLS. Everything
# it creates is removed afterwards, and it touches neither the
# test database from `make store` nor any other project's
# containers.
#
# Container to container over a bridge network, not through the
# host: `make store`'s Postgres runs with rootless Podman's
# default pasta networking, which cannot join a bridge, and its
# port is published to 127.0.0.1 where a container cannot reach
# it. Addressing Postgres by container name is also closer to how
# this is actually deployed.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

image=${IMAGE:-ghcr.io/fatmanuk/olivine-ldap}
tag=$(git describe --tags --always --dirty 2>/dev/null \
	|| echo dev)
net=olivine-smoke
pg=olivine-smoke-pg
srv=olivine-smoke-srv
port=${OLIVINE_POD_PORT:-16636}

# Clearing leftovers and tearing down are separate: a single
# cleanup function called up front would delete the temporary
# directory it had just been given.
purge() {
	podman rm -f "$srv" "$pg" >/dev/null 2>&1 || true
	podman network rm -f "$net" >/dev/null 2>&1 || true
}
purge

dir=$(mktemp -d)
chmod 755 "$dir"
cleanup() {
	purge
	rm -rf "$dir"
}
trap cleanup EXIT

openssl req -x509 -newkey ec \
	-pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$dir/key.pem" -out "$dir/cert.pem" \
	-days 1 -subj /CN=localhost 2>/dev/null
chmod 644 "$dir"/*.pem

podman network create "$net" >/dev/null

echo "pod-run: starting Postgres"
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

hash=$(go run ./cmd/olivined -hash smoketest)

echo "pod-run: starting $image:$tag"
podman run -d --name "$srv" --network "$net" \
	--publish "127.0.0.1:${port}:6360" \
	--volume "$dir:/tls:ro" \
	--env OLIVINE_TLS_CERT=/tls/cert.pem \
	--env OLIVINE_TLS_KEY=/tls/key.pem \
	--env OLIVINE_DSN="host=${pg} port=5432 user=olivine \
password=olivine dbname=olivine sslmode=disable" \
	--env OLIVINE_SUFFIX="dc=example,dc=com" \
	--env OLIVINE_ROOT_DN="cn=root,dc=example,dc=com" \
	--env OLIVINE_ROOT_PASSWORD_HASH="$hash" \
	"$image:$tag" >/dev/null

ready=0
for _ in $(seq 1 60); do
	if echo | openssl s_client \
		-connect "127.0.0.1:${port}" 2>/dev/null \
		| grep -q "Protocol"
	then
		ready=1
		break
	fi
	sleep 0.5
done
if [ "$ready" -ne 1 ]; then
	echo "pod-run: the container did not serve TLS" >&2
	podman logs "$srv" 2>&1 | tail -20 >&2
	exit 1
fi
echo "pod-run: serving TLS on ${port}"

# The strongest check available: drive upstream's own ldapsearch,
# from the oracle image, at Olivine's container over the shared
# network. A TLS handshake only proves a socket answers; this
# proves the server speaks LDAP to the client it is meant to be
# compatible with.
oracle="olivine-oracle:$(git -C openldap describe \
	--tags --always 2>/dev/null || echo none)"
if ! podman image exists "$oracle"; then
	echo "pod-run: $oracle absent; skipping the LDAP check"
	echo "pod-run: run \`make golden-build\` for it"
	exit 0
fi

echo "pod-run: querying the root DSE with upstream ldapsearch"
out=$(podman run --rm --network "$net" \
	--entrypoint /bin/sh "$oracle" -c \
	"LDAPTLS_REQCERT=never /opt/openldap/bin/ldapsearch \
		-H ldaps://${srv}:6360 -x -b '' -s base -LLL \
		'(objectClass=*)' namingContexts 2>&1") || true

printf '%s\n' "$out" | sed 's/^/  /'
if ! printf '%s' "$out" | grep -q "dc=example,dc=com"; then
	echo "pod-run: the root DSE did not name the suffix" >&2
	podman logs "$srv" 2>&1 | tail -20 >&2
	exit 1
fi
echo "pod-run: ok"
