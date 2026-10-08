package store

import (
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// rootSearch is a base search of the empty DN.
func rootSearch(attrs ...string) *ldap.SearchRequest {
	r := searchReq("", ldap.ScopeBase,
		presentFilter("objectClass"))
	r.Attributes = attrs
	return r
}

// attrNames lists the types a reply carries.
func attrNames(e ldap.SearchEntry) []string {
	out := make([]string, 0, len(e.Attributes))
	for _, a := range e.Attributes {
		out = append(out, a.Type)
	}
	return out
}

// has reports whether a reply carries one attribute.
func has(e ldap.SearchEntry, typ string) bool {
	for _, a := range e.Attributes {
		if a.Type == typ {
			return true
		}
	}
	return false
}

// A plain search returns user attributes only: objectClass and
// nothing else, matching slapd.
func TestRootDSEPlainSearch(t *testing.T) {
	s := testStore(t)
	got, res := s.BackendSearch(rootSearch(), anyone)
	if res.Code != ldap.Success || len(got) != 1 {
		t.Fatalf("code = %v, %d entries",
			res.Code, len(got))
	}
	if names := attrNames(got[0]); len(names) != 1 ||
		names[0] != "objectClass" {
		t.Errorf("attributes = %v, want [objectClass]",
			names)
	}
}

// "+" returns operational attributes and *only* those, which is
// why slapd's "+" output carries no objectClass line.
func TestRootDSEOperationalOnly(t *testing.T) {
	s := testStore(t)
	got, _ := s.BackendSearch(rootSearch("+"), anyone)
	if len(got) != 1 {
		t.Fatalf("%d entries", len(got))
	}
	if has(got[0], "objectClass") {
		t.Error("+ should not return user attributes")
	}
	if !has(got[0], "namingContexts") {
		t.Error("+ should return namingContexts")
	}
}

// An explicitly named operational attribute comes back whatever
// its usage. The container smoke test found this: upstream's
// ldapsearch asking for namingContexts alone got an empty entry,
// because only "+" was being honoured.
func TestRootDSENamedOperationalAttribute(t *testing.T) {
	s := testStore(t)
	if err := s.AddSuffix("dc=example,dc=com"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.BackendSearch(
		rootSearch("namingContexts"), anyone)
	if len(got) != 1 {
		t.Fatalf("%d entries", len(got))
	}
	if !has(got[0], "namingContexts") {
		t.Fatalf("attributes = %v", attrNames(got[0]))
	}
	// And nothing it did not ask for.
	if has(got[0], "objectClass") {
		t.Error("objectClass was not requested")
	}
}

// The root DSE is base-scope only: a one-level or subtree search
// from an empty base answers noSuchObject.
func TestRootDSEBaseScopeOnly(t *testing.T) {
	s := testStore(t)
	for _, scope := range []ldap.Scope{
		ldap.ScopeOneLevel, ldap.ScopeSubtree,
	} {
		r := rootSearch()
		r.Scope = scope
		_, res := s.BackendSearch(r, anyone)
		if res.Code != ldap.NoSuchObject {
			t.Errorf("%v: code = %v, want noSuchObject",
				scope, res.Code)
		}
	}
}
