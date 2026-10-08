package schema

import (
	"errors"
	"os"
	"testing"
)

// checkRegistry is the built-in set plus core.schema, matching
// what the oracle loaded when these codes were captured.
func checkRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(coreSchemaFile(t))
	if err != nil {
		t.Skip("openldap submodule not initialised")
	}
	defer f.Close()
	if err := LoadFile(reg, f); err != nil {
		t.Fatal(err)
	}
	return reg
}

// entry builds a check Entry from pairs.
func entry(pairs ...[2]string) Entry {
	e := Entry{Attributes: map[string][]string{}}
	for _, p := range pairs {
		e.Attributes[p[0]] = append(
			e.Attributes[p[0]], p[1])
	}
	return e
}

// Every code and diagnostic below was taken from the oracle by
// adding a deliberately bad entry and reading what slapd said.
// They are asserted exactly, because a plausible-looking
// substitute is how compatibility is lost.
func TestCheckMatchesSlapd(t *testing.T) {
	reg := checkRegistry(t)
	for _, c := range slapdCases() {
		t.Run(c.name, func(t *testing.T) {
			checkOne(t, reg, c.in, c.code, c.text)
		})
	}
}

// slapdCase is one captured expectation.
type slapdCase struct {
	name string
	in   Entry
	code int32
	text string
}

// slapdCases are the codes and diagnostics slapd produced.
func slapdCases() []slapdCase {
	return append(objectClassCases(), attributeCases()...)
}

// objectClassCases are the failures about classes.
func objectClassCases() []slapdCase {
	return []slapdCase{
		{
			name: "undefined objectClass",
			in:   entry([2]string{"objectclass", "nope"}),
			// Surprising: invalidSyntax, not
			// objectClassViolation. slapd validates the
			// value against the objectClass syntax before
			// it considers the hierarchy.
			code: codeInvalidSyntax,
			text: "objectClass: value #0 " +
				"invalid per syntax",
		},
		{
			name: "missing MUST",
			in: entry(
				[2]string{"objectclass", "person"},
				[2]string{"cn", "b"}),
			code: codeObjectClassViolation,
			text: "object class 'person' requires " +
				"attribute 'sn'",
		},
		{
			name: "no structural class",
			in: entry(
				[2]string{"objectclass", "dcObject"},
				[2]string{"dc", "c"}),
			code: codeObjectClassViolation,
			text: "no structural object class provided",
		},
	}
}

// attributeCases are the failures about attributes.
func attributeCases() []slapdCase {
	return []slapdCase{
		{
			name: "attribute not allowed",
			in: entry(
				[2]string{"objectclass", "person"},
				[2]string{"cn", "d"},
				[2]string{"sn", "D"},
				[2]string{"dc", "nope"}),
			code: codeObjectClassViolation,
			text: "attribute 'dc' not allowed",
		},
		{
			name: "undefined attribute",
			in: entry(
				[2]string{"objectclass", "person"},
				[2]string{"cn", "f"},
				[2]string{"sn", "F"},
				[2]string{"nosuchattr", "x"}),
			code: codeUndefinedType,
			text: "nosuchattr: attribute type undefined",
		},
	}
}

// checkOne asserts the code and diagnostic.
func checkOne(
	t *testing.T, reg *Registry, in Entry,
	code int32, text string,
) {
	t.Helper()
	err := reg.Check(in)
	if err == nil {
		t.Fatal("expected a violation")
	}
	var v *Violation
	if !errors.As(err, &v) {
		t.Fatalf("err = %v, want *Violation", err)
	}
	if v.Code != code {
		t.Errorf("code = %d, want %d", v.Code, code)
	}
	if v.Text != text {
		t.Errorf("text = %q,\n want %q", v.Text, text)
	}
}

// Two unrelated structural classes are refused; a chain is not.
func TestStructuralChain(t *testing.T) {
	reg := checkRegistry(t)
	// person and organizationalUnit are unrelated.
	err := reg.Check(entry(
		[2]string{"objectclass", "person"},
		[2]string{"objectclass", "organizationalUnit"},
		[2]string{"cn", "e"},
		[2]string{"sn", "E"},
		[2]string{"ou", "e"}))
	if err == nil {
		t.Error("unrelated structural classes allowed")
	}
	// organizationalPerson descends from person, so the pair
	// is a chain and must be accepted.
	err = reg.Check(entry(
		[2]string{"objectclass", "person"},
		[2]string{"objectclass", "organizationalPerson"},
		[2]string{"cn", "e"},
		[2]string{"sn", "E"}))
	if err != nil {
		t.Errorf("a valid chain was refused: %v", err)
	}
}

// A MUST attribute inherited through SUP still counts.
func TestInheritedMustAndMay(t *testing.T) {
	reg := checkRegistry(t)
	// organizationalPerson inherits MUST (sn, cn) from person.
	err := reg.Check(entry(
		[2]string{"objectclass", "organizationalPerson"},
		[2]string{"cn", "x"}))
	if err == nil {
		t.Error("inherited MUST not enforced")
	}
	// And inherited MAY permits the attribute.
	err = reg.Check(entry(
		[2]string{"objectclass", "organizationalPerson"},
		[2]string{"cn", "x"},
		[2]string{"sn", "X"},
		[2]string{"description", "ok"}))
	if err != nil {
		t.Errorf("inherited MAY refused: %v", err)
	}
}

// A valid entry passes.
func TestCheckAcceptsValidEntry(t *testing.T) {
	reg := checkRegistry(t)
	err := reg.Check(entry(
		[2]string{"objectclass", "top"},
		[2]string{"objectclass", "organization"},
		[2]string{"objectclass", "dcObject"},
		[2]string{"o", "example"},
		[2]string{"dc", "example"}))
	if err != nil {
		t.Errorf("valid entry refused: %v", err)
	}
}
