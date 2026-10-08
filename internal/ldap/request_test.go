package ldap

import (
	"errors"
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
)

func TestParseSearchRequest(t *testing.T) {
	e := ber.NewEncoder()
	e.String(TagLDAPDN, "dc=example,dc=com")
	e.Enum(ber.TagEnumerated, int32(ScopeSubtree))
	e.Enum(ber.TagEnumerated, 3)
	e.Int32(ber.TagInteger, 100)
	e.Int32(ber.TagInteger, 30)
	e.Bool(ber.TagBoolean, true)
	e.String(FilterPresent, "objectClass")
	e.Begin(ber.TagSequence)
	e.String(ber.TagOctetString, "cn")
	e.String(ber.TagOctetString, "sn")
	e.End()
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseSearchRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	checkSearchFields(t, r)
}

// checkSearchFields asserts every decoded field.
func checkSearchFields(t *testing.T, r *SearchRequest) {
	t.Helper()
	if r.BaseObject != "dc=example,dc=com" {
		t.Errorf("base = %q", r.BaseObject)
	}
	if r.Scope != ScopeSubtree {
		t.Errorf("scope = %v", r.Scope)
	}
	if r.SizeLimit != 100 || r.TimeLimit != 30 {
		t.Errorf("limits = %d/%d",
			r.SizeLimit, r.TimeLimit)
	}
	if !r.TypesOnly {
		t.Error("typesOnly not read")
	}
	if r.Filter.Tag != FilterPresent ||
		r.Filter.Attribute != "objectClass" {
		t.Errorf("filter = %+v", r.Filter)
	}
	if len(r.Attributes) != 2 {
		t.Errorf("attributes = %v", r.Attributes)
	}
}

func TestParseSearchRequestTruncated(t *testing.T) {
	e := ber.NewEncoder()
	e.String(TagLDAPDN, "dc=example,dc=com")
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSearchRequest(body); err == nil {
		t.Fatal("a truncated request should not parse")
	}
}

func TestParseBindRequestSimple(t *testing.T) {
	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, 3)
	e.String(TagLDAPDN, "cn=admin,dc=example,dc=com")
	e.String(AuthSimple, "secret")
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseBindRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != 3 {
		t.Errorf("version = %d", r.Version)
	}
	if r.Simple != "secret" || r.IsSASL {
		t.Errorf("got %+v", r)
	}
}

func TestParseBindRequestSASL(t *testing.T) {
	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, 3)
	e.String(TagLDAPDN, "")
	e.Begin(AuthSASL)
	e.String(ber.TagOctetString, "GSSAPI")
	e.End()
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseBindRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsSASL || r.Mechanism != "GSSAPI" {
		t.Errorf("got %+v", r)
	}
}

// An authentication choice that is neither simple nor SASL is a
// malformed request, not an anonymous bind.
func TestParseBindRequestBadChoice(t *testing.T) {
	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, 3)
	e.String(TagLDAPDN, "")
	e.String(0x8f, "mystery")
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBindRequest(body); !errors.Is(
		err, ErrBadRequest) {
		t.Fatalf("err = %v, want ErrBadRequest", err)
	}
}

func TestParseAddRequest(t *testing.T) {
	e := ber.NewEncoder()
	e.String(TagLDAPDN, "cn=a,dc=example,dc=com")
	e.Begin(ber.TagSequence)
	e.Begin(ber.TagSequence)
	e.String(ber.TagOctetString, "objectClass")
	e.Begin(ber.TagSet)
	e.String(ber.TagOctetString, "top")
	e.String(ber.TagOctetString, "person")
	e.End()
	e.End()
	e.End()
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseAddRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Entry != "cn=a,dc=example,dc=com" {
		t.Errorf("entry = %q", r.Entry)
	}
	if len(r.Attributes) != 1 ||
		len(r.Attributes[0].Values) != 2 {
		t.Fatalf("attributes = %+v", r.Attributes)
	}
}

func TestParseModifyRequest(t *testing.T) {
	e := ber.NewEncoder()
	e.String(TagLDAPDN, "cn=a,dc=example,dc=com")
	e.Begin(ber.TagSequence)
	e.Begin(ber.TagSequence)
	e.Enum(ber.TagEnumerated, int32(ModifyReplace))
	e.Begin(ber.TagSequence)
	e.String(ber.TagOctetString, "sn")
	e.Begin(ber.TagSet)
	e.String(ber.TagOctetString, "New")
	e.End()
	e.End()
	e.End()
	e.End()
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseModifyRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Modifications) != 1 {
		t.Fatalf("mods = %+v", r.Modifications)
	}
	m := r.Modifications[0]
	if m.Op != ModifyReplace || m.Attribute.Type != "sn" {
		t.Errorf("mod = %+v", m)
	}
}

func TestParseCompareRequest(t *testing.T) {
	e := ber.NewEncoder()
	e.String(TagLDAPDN, "cn=a,dc=example,dc=com")
	e.Begin(ber.TagSequence)
	e.String(ber.TagOctetString, "sn")
	e.String(ber.TagOctetString, "Smith")
	e.End()
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseCompareRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Attribute != "sn" || r.Value != "Smith" {
		t.Errorf("got %+v", r)
	}
}
