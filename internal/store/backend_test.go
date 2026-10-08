package store

import (
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// searchReq builds a SearchRequest for the tests.
func searchReq(
	base string, scope ldap.Scope, f ldap.Filter,
) *ldap.SearchRequest {
	return &ldap.SearchRequest{
		BaseObject: base, Scope: scope, Filter: f,
	}
}

// present builds a (attr=*) filter.
func presentFilter(attr string) ldap.Filter {
	return ldap.Filter{
		Tag: ldap.FilterPresent, Attribute: attr,
	}
}

// eq builds an (attr=value) filter.
func eq(attr, value string) ldap.Filter {
	return ldap.Filter{
		Tag:       ldap.FilterEquality,
		Attribute: attr, Value: value,
	}
}

func TestBackendSearchFilters(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	base := "dc=example,dc=com"

	cases := []struct {
		name   string
		filter ldap.Filter
		want   int
	}{
		{"present cn", presentFilter("cn"), 2},
		{"present objectClass",
			presentFilter("objectClass"), 5},
		{"equality cn=Alice", eq("cn", "Alice"), 1},
		// cn inherits caseIgnoreMatch from name, so the
		// spelling in the filter should not matter.
		{"equality cn=alice", eq("cn", "alice"), 1},
		{"equality cn=ALICE", eq("cn", "ALICE"), 1},
		{"equality no match", eq("cn", "Nobody"), 0},
		{"unknown attribute", presentFilter("nosuch"), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, res := s.BackendSearch(searchReq(
				base, ldap.ScopeSubtree, c.filter))
			if res.Code != ldap.Success {
				t.Fatalf("result = %v", res.Code)
			}
			if len(got) != c.want {
				t.Errorf("%d entries, want %d",
					len(got), c.want)
			}
		})
	}
}

// RFC 4526: an empty and is TRUE, an empty or is FALSE.
func TestEmptyAndOr(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	base := "dc=example,dc=com"

	got, res := s.BackendSearch(searchReq(base,
		ldap.ScopeSubtree,
		ldap.Filter{Tag: ldap.FilterAnd}))
	if res.Code != ldap.Success {
		t.Fatalf("and: %v", res.Code)
	}
	if len(got) != 5 {
		t.Errorf("empty and matched %d, want all 5",
			len(got))
	}
	got, res = s.BackendSearch(searchReq(base,
		ldap.ScopeSubtree,
		ldap.Filter{Tag: ldap.FilterOr}))
	if res.Code != ldap.Success {
		t.Fatalf("or: %v", res.Code)
	}
	if len(got) != 0 {
		t.Errorf("empty or matched %d, want none", len(got))
	}
}

// RFC 4511 4.5.3: a search whose base does not exist is
// noSuchObject, even when the scope would return nothing anyway.
func TestBackendSearchMissingBase(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	_, res := s.BackendSearch(searchReq(
		"dc=absent,dc=com", ldap.ScopeSubtree,
		presentFilter("objectClass")))
	if res.Code != ldap.NoSuchObject {
		t.Errorf("code = %v, want noSuchObject", res.Code)
	}
}

// RFC 4511 4.5.1.8: "1.1" means no attributes at all.
func TestProjectionNoAttributes(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	req := searchReq("cn=Alice,ou=people,dc=example,dc=com",
		ldap.ScopeBase, presentFilter("objectClass"))
	req.Attributes = []string{ldap.NoAttributes}
	got, res := s.BackendSearch(req)
	if res.Code != ldap.Success {
		t.Fatal(res.Code)
	}
	if len(got) != 1 {
		t.Fatalf("%d entries", len(got))
	}
	if len(got[0].Attributes) != 0 {
		t.Errorf("attributes = %v", got[0].Attributes)
	}
	// The DN still comes back; only attributes are withheld.
	if got[0].DN == "" {
		t.Error("DN should still be returned")
	}
}

func TestProjectionSelectsAttributes(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	req := searchReq("cn=Alice,ou=people,dc=example,dc=com",
		ldap.ScopeBase, presentFilter("objectClass"))
	req.Attributes = []string{"sn"}
	got, _ := s.BackendSearch(req)
	if len(got) != 1 || len(got[0].Attributes) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Attributes[0].Type != "sn" {
		t.Errorf("type = %q", got[0].Attributes[0].Type)
	}
}

// TypesOnly withholds the values but keeps the types.
func TestProjectionTypesOnly(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	req := searchReq("cn=Alice,ou=people,dc=example,dc=com",
		ldap.ScopeBase, presentFilter("objectClass"))
	req.TypesOnly = true
	got, _ := s.BackendSearch(req)
	if len(got) != 1 {
		t.Fatalf("%d entries", len(got))
	}
	for _, a := range got[0].Attributes {
		if len(a.Values) != 0 {
			t.Errorf("%s carried values %v",
				a.Type, a.Values)
		}
	}
}
