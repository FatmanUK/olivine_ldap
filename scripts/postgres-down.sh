#!/usr/bin/env bash
# Remove the throwaway Postgres started by postgres-up.sh.
#
# Only the container this project named: other projects on this
# machine run their own Postgres containers, and they are none of
# our business.
set -euo pipefail
name=${OLIVINE_PG_NAME:-olivine-pg}
podman rm -f "$name" >/dev/null 2>&1 || true
echo "postgres-down: removed $name"
