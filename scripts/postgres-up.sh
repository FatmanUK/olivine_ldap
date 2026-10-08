#!/usr/bin/env bash
# Start a throwaway Postgres for the store tests.
#
# Rootless Podman, bound to localhost only, on a non-default
# port so it cannot be mistaken for — or collide with — a real
# instance. Prints the connection string on stdout so a caller
# can eval it.
#
# The data lives inside the container. It is meant to be thrown
# away: `scripts/postgres-down.sh` removes it.
set -euo pipefail

name=${OLIVINE_PG_NAME:-olivine-pg}
port=${OLIVINE_PG_PORT:-15432}
image=${OLIVINE_PG_IMAGE:-docker.io/library/postgres:17-alpine}

if ! podman container exists "$name"; then
	podman run -d --name "$name" \
		-e POSTGRES_PASSWORD=olivine \
		-e POSTGRES_USER=olivine \
		-e POSTGRES_DB=olivine \
		-p "127.0.0.1:${port}:5432" \
		"$image" >/dev/null
elif [ "$(podman inspect -f '{{.State.Running}}' "$name")" \
	!= true ]; then
	podman start "$name" >/dev/null
fi

for _ in $(seq 1 120); do
	if podman exec "$name" pg_isready -U olivine \
		>/dev/null 2>&1
	then
		printf 'host=127.0.0.1 port=%s user=olivine password=olivine dbname=olivine sslmode=disable\n' "$port"
		exit 0
	fi
	sleep 0.5
done

echo "postgres-up: $name did not become ready" >&2
podman logs --tail 20 "$name" >&2
exit 1
