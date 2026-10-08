#!/usr/bin/env bash
# Build the golden oracle: OpenLDAP's slapd from the pinned
# submodule, in a rootless Podman image.
#
# The submodule is read-only reference. This script only reads
# it, and tags the image with the upstream release so a stale
# image cannot be mistaken for a current one.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

if [ ! -f openldap/configure ]; then
	echo "openldap/ is empty. Run:" >&2
	echo "  git submodule update --init openldap" >&2
	exit 1
fi

tag=$(git -C openldap describe --tags --always)
image="olivine-oracle:${tag}"

if podman image exists "$image" && [ "${FORCE:-}" != 1 ]; then
	echo "golden-build: $image already built"
	echo "golden-build: FORCE=1 to rebuild"
	exit 0
fi

# Podman needs the source inside the build context, and the
# submodule must not be touched, so stage a copy.
ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT
cp internal/golden/oracle/Containerfile "$ctx/"
mkdir -p "$ctx/src"
# Archive-through-pipe copies tracked content without
# following into .git.
git -C openldap archive HEAD | tar -x -C "$ctx/src"

echo "golden-build: building $image from $tag"
podman build -t "$image" -f "$ctx/Containerfile" "$ctx"
echo "golden-build: built $image"
