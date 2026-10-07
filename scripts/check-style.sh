#!/usr/bin/env bash
# Enforce the source invariants from CLAUDE.md:
#   - Go source is 70 columns wide, a tab counted as 8.
#   - Functions are 40 lines at most.
#
# The openldap submodule is read-only C reference and is
# never checked.
set -uo pipefail

status=0

# --others --exclude-standard so files that are written but
# not yet staged are checked too; otherwise new code passes
# the check only until someone stages it.
files=$(git ls-files --cached --others --exclude-standard \
	'*.go' | grep -v '^openldap/' | sort -u) || true
if [ -z "$files" ]; then
	echo "check-style: no Go files yet"
	exit 0
fi

# Width. Expand tabs to 8 before measuring, so the count
# matches what CLAUDE.md actually specifies.
while IFS= read -r f; do
	expand -t 8 "$f" | awk -v f="$f" '
		length($0) > 70 {
			printf "%s:%d: %d columns (max 70)\n",
				f, FNR, length($0)
			bad = 1
		}
		END { exit bad ? 1 : 0 }
	' || status=1
done <<< "$files"

# Function length. Accurate for gofmt'd source, where a
# top-level func opens at column 0 and closes on a lone "}".
while IFS= read -r f; do
	awk -v f="$f" '
		/^func / { start = FNR; name = $0; next }
		start && /^}/ {
			n = FNR - start + 1
			if (n > 40) {
				printf "%s:%d: %d lines (max 40): %s\n",
					f, start, n, name
				bad = 1
			}
			start = 0
		}
		END { exit bad ? 1 : 0 }
	' "$f" || status=1
done <<< "$files"

if [ "$status" -eq 0 ]; then
	echo "check-style: ok"
fi
exit "$status"
