package store

import (
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/schema"
)

// testSchema loads the schema Olivine ships with.
//
// Embedded, not read from the submodule: the CI checks out without
// submodules, so a test that read core.schema from disk would skip
// there and the Postgres service the workflow stands up would do
// nothing at all.
func testSchema(t *testing.T) *schema.Registry {
	t.Helper()
	reg, err := schema.NewStandardRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return reg
}
