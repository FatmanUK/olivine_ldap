package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/schema"
)

// testSchema loads the built-in schema plus core.schema.
//
// Both are needed, and the split is informative: schema.Builtin
// carries what schema_init.c hardcodes (cn, name, objectClass),
// while dc, ou and person come from core.schema. A server built
// from the Go alone therefore cannot yet resolve dc — Olivine
// needs its own embedded standard schema, which belongs with
// configuration at plan step 10. Until then the tests read the
// submodule, as internal/dn's do.
func testSchema(t *testing.T) *schema.Registry {
	t.Helper()
	reg, err := schema.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(coreSchemaPath(t))
	if err != nil {
		t.Skip("openldap submodule not initialised")
	}
	defer f.Close()
	if err := schema.LoadFile(reg, f); err != nil {
		t.Fatal(err)
	}
	return reg
}

// coreSchemaPath locates core.schema in the submodule.
func coreSchemaPath(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse",
		"--show-toplevel").Output()
	if err != nil {
		t.Skipf("not in a git checkout: %v", err)
	}
	root := strings.TrimSpace(string(out))
	return filepath.Join(root, "openldap", "servers",
		"slapd", "schema", "core.schema")
}
