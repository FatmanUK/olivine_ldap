package schema

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// schemaDir finds the submodule's schema directory. go test
// runs with the package directory as its working directory, so
// the path has to come from git.
func schemaDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse",
		"--show-toplevel").Output()
	if err != nil {
		t.Skipf("not in a git checkout: %v", err)
	}
	root := strings.TrimSpace(string(out))
	dir := filepath.Join(root, "openldap", "servers",
		"slapd", "schema")
	if _, err := os.Stat(dir); err != nil {
		t.Skip("openldap submodule not initialised")
	}
	return dir
}

// TestParseEverySchemaFile is the real test of the parser:
// upstream's own schema files, which slapd itself reads.
//
// A parser that handles invented examples proves nothing. These
// are the definitions the oracle loads.
func TestParseEverySchemaFile(t *testing.T) {
	dir := schemaDir(t)
	files, err := filepath.Glob(
		filepath.Join(dir, "*.schema"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no .schema files found")
	}
	var attrs, ocs int
	for _, path := range files {
		a, o := loadOne(t, path)
		attrs += a
		ocs += o
	}
	t.Logf("parsed %d files: %d attribute types, "+
		"%d object classes", len(files), attrs, ocs)
	// core.schema alone has dozens; a parser that silently
	// matched nothing would otherwise pass.
	if attrs < 500 {
		t.Errorf("only %d attribute types; expected 500+",
			attrs)
	}
	if ocs < 50 {
		t.Errorf("only %d object classes; expected 50+", ocs)
	}
}

// loadOne parses one file into its own registry, so a
// duplicate across files is not mistaken for a parse error.
func loadOne(t *testing.T, path string) (int, int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := NewRegistry()
	if err := LoadFile(r, f); err != nil {
		t.Errorf("%s: %v", filepath.Base(path), err)
		return 0, 0
	}
	return r.CountAttributeTypes(), r.CountObjectClasses()
}

// TestCoreSchemaSpecifics checks definitions whose exact
// content is known, so a parser that produces structurally
// valid nonsense is caught.
func TestCoreSchemaSpecifics(t *testing.T) {
	dir := schemaDir(t)
	f, err := os.Open(filepath.Join(dir, "core.schema"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := NewRegistry()
	if err := LoadFile(r, f); err != nil {
		t.Fatal(err)
	}
	checkSurname(t, r)
	checkPerson(t, r)
}

// checkSurname checks the two-name, SUP-only form.
func checkSurname(t *testing.T, r *Registry) {
	t.Helper()
	// attributetype ( 2.5.4.4 NAME ( 'sn' 'surname' )
	//	SUP name )
	at, ok := r.AttributeType("sn")
	if !ok {
		t.Fatal("sn not registered")
	}
	if at.OID != "2.5.4.4" {
		t.Errorf("sn OID = %q", at.OID)
	}
	if at.SuperiorOID != "name" {
		t.Errorf("sn SUP = %q", at.SuperiorOID)
	}
	// The second name must resolve too, and so must the OID.
	if _, ok := r.AttributeType("surname"); !ok {
		t.Error("surname alias not registered")
	}
	if _, ok := r.AttributeType("2.5.4.4"); !ok {
		t.Error("sn not resolvable by OID")
	}
	// Descriptors are case-insensitive, RFC 4512 2.5.
	if _, ok := r.AttributeType("SurName"); !ok {
		t.Error("lookup should be case-insensitive")
	}
}

// checkPerson checks MUST/MAY and the kind.
func checkPerson(t *testing.T, r *Registry) {
	t.Helper()
	// objectclass ( 2.5.6.6 NAME 'person'
	//	SUP top STRUCTURAL
	//	MUST ( sn $ cn )
	//	MAY ( userPassword $ telephoneNumber $ seeAlso
	//	      $ description ) )
	oc, ok := r.ObjectClass("person")
	if !ok {
		t.Fatal("person not registered")
	}
	if oc.Kind != Structural {
		t.Errorf("person kind = %v", oc.Kind)
	}
	if len(oc.SuperiorOIDs) != 1 ||
		oc.SuperiorOIDs[0] != "top" {
		t.Errorf("person SUP = %v", oc.SuperiorOIDs)
	}
	if strings.Join(oc.Must, ",") != "sn,cn" {
		t.Errorf("person MUST = %v", oc.Must)
	}
	if len(oc.May) != 4 {
		t.Errorf("person MAY = %v", oc.May)
	}
}
