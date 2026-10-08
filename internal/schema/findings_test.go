package schema

import (
	"errors"
	"strings"
	"testing"
)

// Each test here pins a behaviour taken from upstream rather
// than from the RFC, so a later tidy-up cannot quietly undo it.

// slapd silently ignores an unknown directive in a schema
// file: slaptest reports success and the definition is simply
// absent. Upstream's own dsee.schema:96 says "attributeype",
// so targetUniqueId is missing from every slapd that loads it.
// Verified by running slaptest against a deliberately
// misspelled keyword in the oracle container.
func TestUnknownKeywordIsSkippedNotRefused(t *testing.T) {
	src := strings.NewReader(
		"attributeype ( 1.3.6.1.4.1.99999.2.1\n" +
			"\tNAME 'bogusTypo' )\n")
	r := NewRegistry()
	if err := LoadFile(r, src); err != nil {
		t.Fatalf("should not refuse the file: %v", err)
	}
	if _, ok := r.AttributeType("bogusTypo"); ok {
		t.Error("the definition must not be registered")
	}
	if len(r.Skipped) != 1 {
		t.Fatalf("Skipped = %v", r.Skipped)
	}
	if r.Skipped[0].Keyword != "attributeype" {
		t.Errorf("keyword = %q", r.Skipped[0].Keyword)
	}
}

// OID macros are an OpenLDAP extension, not RFC 4512, and they
// nest.
func TestOIDMacrosNest(t *testing.T) {
	src := strings.NewReader(
		"objectIdentifier Base 1.3.6.1.4.1.4203.666.4\n" +
			"objectIdentifier Attr Base:1\n" +
			"attributetype ( Attr:3 " +
			"NAME 'dgMemberOf' )\n")
	r := NewRegistry()
	if err := LoadFile(r, src); err != nil {
		t.Fatal(err)
	}
	at, ok := r.AttributeType("dgMemberOf")
	if !ok {
		t.Fatal("dgMemberOf not registered")
	}
	want := "1.3.6.1.4.1.4203.666.4.1.3"
	if at.OID != want {
		t.Errorf("OID = %q, want %q", at.OID, want)
	}
}

// slapd refuses a redefined macro, which is why dsee.schema and
// dyngroup.schema cannot both be loaded: both define
// NetscapeRoot.
func TestDuplicateMacroIsRefused(t *testing.T) {
	src := strings.NewReader(
		"objectIdentifier NetscapeRoot 2.16.840.1.113730\n" +
			"objectIdentifier NetscapeRoot 1.2.3\n")
	r := NewRegistry()
	err := LoadFile(r, src)
	if !errors.Is(err, ErrDup) {
		t.Fatalf("err = %v, want ErrDup", err)
	}
}

// msuser.schema writes SYNTAX in quotes, which the ABNF does
// not allow and slapd accepts.
func TestQuotedSyntaxOID(t *testing.T) {
	at, err := ParseAttributeType(
		"( 1.2.3 NAME 'x' " +
			"SYNTAX '1.3.6.1.4.1.1466.115.121.1.12' )")
	if err != nil {
		t.Fatal(err)
	}
	if at.SyntaxOID != "1.3.6.1.4.1.1466.115.121.1.12" {
		t.Errorf("SyntaxOID = %q", at.SyntaxOID)
	}
}

// A {len} suffix is an upper bound on value length and is not
// part of the OID.
func TestSyntaxLengthSuffix(t *testing.T) {
	at, err := ParseAttributeType(
		"( 1.2.3 NAME 'x' " +
			"SYNTAX " +
			"1.3.6.1.4.1.1466.115.121.1.15{32768} )")
	if err != nil {
		t.Fatal(err)
	}
	if at.SyntaxOID != "1.3.6.1.4.1.1466.115.121.1.15" {
		t.Errorf("SyntaxOID = %q", at.SyntaxOID)
	}
	if at.SyntaxLen != 32768 {
		t.Errorf("SyntaxLen = %d, want 32768", at.SyntaxLen)
	}
}

// Keywords are case-insensitive: dyngroup.schema writes both
// attributetype and attributeType.
func TestKeywordCaseInsensitive(t *testing.T) {
	src := strings.NewReader(
		"attributeType ( 1.2.3 NAME 'mixedCase' )\n" +
			"OBJECTCLASS ( 1.2.4 NAME 'shouty' )\n")
	r := NewRegistry()
	if err := LoadFile(r, src); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.AttributeType("mixedCase"); !ok {
		t.Error("attributeType not accepted")
	}
	if _, ok := r.ObjectClass("shouty"); !ok {
		t.Error("OBJECTCLASS not accepted")
	}
}

// STRUCTURAL is the default kind, RFC 4512 4.1.1.
func TestObjectClassKindDefaultsStructural(t *testing.T) {
	oc, err := ParseObjectClass("( 1.2.3 NAME 'x' )")
	if err != nil {
		t.Fatal(err)
	}
	if oc.Kind != Structural {
		t.Errorf("kind = %v, want STRUCTURAL", oc.Kind)
	}
}

// core.schema comments out cn and name because schema_init.c
// defines them in C. A registry built from the files alone
// cannot resolve cn, and every DN needs it.
func TestBuiltinSuppliesCN(t *testing.T) {
	r, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"cn", "commonName", "name", "objectClass",
		"2.5.4.3",
	} {
		if _, ok := r.AttributeType(name); !ok {
			t.Errorf("%s missing from builtin", name)
		}
	}
	if _, ok := r.ObjectClass("top"); !ok {
		t.Error("top missing from the built-in schema")
	}
}

// The embedded standard schema must be enough on its own: the CI
// checks out without submodules, so anything that reads
// core.schema from disk skips there.
func TestStandardSchemaIsSelfSufficient(t *testing.T) {
	r, err := NewStandardRegistry()
	if err != nil {
		t.Fatal(err)
	}
	// From schema_init.c.
	for _, n := range []string{"cn", "objectClass", "name"} {
		if _, ok := r.AttributeType(n); !ok {
			t.Errorf("%s missing", n)
		}
	}
	// From core.schema, which the built-in set lacks.
	for _, n := range []string{"dc", "ou", "o", "sn"} {
		if _, ok := r.AttributeType(n); !ok {
			t.Errorf("%s missing", n)
		}
	}
	// From cosine and nis.
	for _, n := range []string{"uidNumber", "uid"} {
		if _, ok := r.AttributeType(n); !ok {
			t.Errorf("%s missing", n)
		}
	}
	for _, n := range []string{
		"top", "person", "organizationalUnit", "dcObject",
		"extensibleObject",
	} {
		if _, ok := r.ObjectClass(n); !ok {
			t.Errorf("objectClass %s missing", n)
		}
	}
}
