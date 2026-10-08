package schema

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// subschemaPath is slapd's own output, captured by
// scripts/capture-subschema.sh.
const subschemaPath = "testdata/subschema.ldif"

// TestParseSlapdSubschema reads every definition slapd itself
// emits.
//
// This is the sharpest oracle available for the parser short of
// a live comparison: slapd emits RFC 4512 descriptions for
// everything it has registered, including the operational
// attributes hardcoded in schema_init.c that appear in no
// .schema file. If Olivine cannot read what slapd emits,
// Olivine cannot agree with slapd about the schema.
func TestParseSlapdSubschema(t *testing.T) {
	attrs, ocs := readSubschema(t)
	if len(attrs) < 300 {
		t.Fatalf("only %d attributeTypes in %s",
			len(attrs), subschemaPath)
	}
	r := NewRegistry()
	for _, def := range attrs {
		at, err := ParseAttributeType(def)
		if err != nil {
			t.Errorf("attributeType: %v\n  %s", err, def)
			continue
		}
		if err := r.AddAttributeType(at); err != nil {
			t.Errorf("registering: %v\n  %s", err, def)
		}
	}
	for _, def := range ocs {
		oc, err := ParseObjectClass(def)
		if err != nil {
			t.Errorf("objectClass: %v\n  %s", err, def)
			continue
		}
		if err := r.AddObjectClass(oc); err != nil {
			t.Errorf("registering: %v\n  %s", err, def)
		}
	}
	if r.CountAttributeTypes() != len(attrs) {
		t.Errorf("registered %d of %d attributeTypes",
			r.CountAttributeTypes(), len(attrs))
	}
	if r.CountObjectClasses() != len(ocs) {
		t.Errorf("registered %d of %d objectClasses",
			r.CountObjectClasses(), len(ocs))
	}
	t.Logf("parsed slapd's own schema: %d attributeTypes, "+
		"%d objectClasses", len(attrs), len(ocs))
}

// readSubschema pulls the two attribute lists out of the LDIF.
//
// ldif-wrap=no was used at capture time, so no line is folded
// and a simple prefix match is enough.
func readSubschema(t *testing.T) ([]string, []string) {
	t.Helper()
	f, err := os.Open(subschemaPath)
	if err != nil {
		t.Skipf("%s missing; run "+
			"scripts/capture-subschema.sh", subschemaPath)
	}
	defer f.Close()
	var attrs, ocs []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := after(line, "attributeTypes:"); ok {
			attrs = append(attrs, v)
		}
		if v, ok := after(line, "objectClasses:"); ok {
			ocs = append(ocs, v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return attrs, ocs
}

// after returns the trimmed remainder if line has the prefix.
func after(line, prefix string) (string, bool) {
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	return strings.TrimSpace(
		strings.TrimPrefix(line, prefix)), true
}

// TestSubschemaRoundTripsNames checks that definitions slapd
// emits are findable by the names slapd gave them, not merely
// parseable.
func TestSubschemaRoundTripsNames(t *testing.T) {
	attrs, _ := readSubschema(t)
	r := NewRegistry()
	for _, def := range attrs {
		at, err := ParseAttributeType(def)
		if err != nil {
			continue
		}
		_ = r.AddAttributeType(at)
	}
	// Operational attributes that exist only in
	// schema_init.c, so a files-only parser would miss them.
	for _, name := range []string{
		"objectClass", "structuralObjectClass", "entryDN",
		"subschemaSubentry", "createTimestamp",
		"modifyTimestamp", "creatorsName",
	} {
		if _, ok := r.AttributeType(name); !ok {
			t.Errorf("%s not resolvable", name)
		}
	}
}
