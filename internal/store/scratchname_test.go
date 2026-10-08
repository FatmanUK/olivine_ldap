package store

import (
	"strings"
	"testing"
)

// scratchName builds a schema name from the test's name.
//
// Postgres identifiers cap at 63 bytes and the name has to be a
// valid quoted identifier, so anything exotic in a subtest name
// is flattened.
func scratchName(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("olivine_test_")
	for _, r := range strings.ToLower(t.Name()) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := b.String()
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}
