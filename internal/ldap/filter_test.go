package ldap

import (
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/ber"
)

func TestParseFilterSubstrings(t *testing.T) {
	e := ber.NewEncoder()
	e.Begin(FilterSubstrings)
	e.String(ber.TagOctetString, "cn")
	e.Begin(ber.TagSequence)
	e.String(SubstringInitial, "Al")
	e.String(SubstringAny, "ic")
	e.String(SubstringFinal, "e")
	e.End()
	e.End()
	packet, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	tag, content, err := ber.NewDecoder(packet).Next()
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseFilter(tag, content)
	if err != nil {
		t.Fatal(err)
	}
	if f.Attribute != "cn" {
		t.Errorf("attribute = %q", f.Attribute)
	}
	s := f.Substrings
	if s.Initial != "Al" || s.Final != "e" {
		t.Errorf("substrings = %+v", s)
	}
	if len(s.Any) != 1 || s.Any[0] != "ic" {
		t.Errorf("any = %v", s.Any)
	}
}

func TestParseFilterNested(t *testing.T) {
	// (&(objectClass=*)(|(cn=a)(!(sn=b))))
	e := ber.NewEncoder()
	e.Begin(FilterAnd)
	e.String(FilterPresent, "objectClass")
	e.Begin(FilterOr)
	writeEquality(e, "cn", "a")
	e.Begin(FilterNot)
	writeEquality(e, "sn", "b")
	e.End()
	e.End()
	e.End()
	packet, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	tag, content, err := ber.NewDecoder(packet).Next()
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseFilter(tag, content)
	if err != nil {
		t.Fatal(err)
	}
	if f.Tag != FilterAnd || len(f.Sub) != 2 {
		t.Fatalf("top = %+v", f)
	}
	or := f.Sub[1]
	if or.Tag != FilterOr || len(or.Sub) != 2 {
		t.Fatalf("or = %+v", or)
	}
	not := or.Sub[1]
	if not.Tag != FilterNot || len(not.Sub) != 1 {
		t.Fatalf("not = %+v", not)
	}
	if not.Sub[0].Value != "b" {
		t.Errorf("inner value = %q", not.Sub[0].Value)
	}
}

// writeEquality writes an (attr=value) filter.
func writeEquality(e *ber.Encoder, attr, value string) {
	e.Begin(FilterEquality)
	e.String(ber.TagOctetString, attr)
	e.String(ber.TagOctetString, value)
	e.End()
}

func TestParseFilterUnknownTag(t *testing.T) {
	if _, err := ParseFilter(0xaf, nil); err == nil {
		t.Fatal("an unknown filter tag should not parse")
	}
}

// An extensibleMatch filter is recognised as a tag but not
// implemented, so it must be refused rather than silently
// treated as something else.
func TestParseFilterExtensibleRefused(t *testing.T) {
	if _, err := ParseFilter(
		FilterExtensible, nil); err == nil {
		t.Fatal("extensibleMatch should be refused")
	}
}
