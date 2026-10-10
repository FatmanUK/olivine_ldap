package store

import (
	"errors"
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// seed builds a small tree:
//
//	dc=example,dc=com
//	  ou=people,dc=example,dc=com
//	    cn=Alice,ou=people,dc=example,dc=com
//	    cn=Bob,ou=people,dc=example,dc=com
//	  ou=groups,dc=example,dc=com
func seed(t *testing.T, s *Store) {
	t.Helper()
	add := func(dn string, attrs ...Attribute) {
		t.Helper()
		if _, err := s.Add(dn, attrs); err != nil {
			t.Fatalf("add %s: %v", dn, err)
		}
	}
	// top + organization is the structural pair and dcObject
	// the auxiliary that permits dc. `domain` would be the
	// obvious choice and lives in cosine.schema, not
	// core.schema, so the schema check refuses it — as slapd
	// does, with "objectClass: value #1 invalid per syntax".
	add("dc=example,dc=com",
		Attribute{"objectClass", []string{
			"top", "organization", "dcObject"}},
		Attribute{"o", []string{"example"}},
		Attribute{"dc", []string{"example"}})
	ou := Attribute{"objectClass",
		[]string{"organizationalUnit"}}
	add("ou=people,dc=example,dc=com", ou,
		Attribute{"ou", []string{"people"}})
	add("cn=Alice,ou=people,dc=example,dc=com",
		Attribute{"objectClass", []string{"person"}},
		Attribute{"cn", []string{"Alice"}},
		Attribute{"sn", []string{"Anderson"}})
	add("cn=Bob,ou=people,dc=example,dc=com",
		Attribute{"objectClass", []string{"person"}},
		Attribute{"cn", []string{"Bob"}},
		Attribute{"sn", []string{"Brown"}})
	add("ou=groups,dc=example,dc=com", ou,
		Attribute{"ou", []string{"groups"}})
}

func TestAddAndGet(t *testing.T) {
	s := testStore(t)
	seed(t, s)

	e, err := s.Get("DC=Example,DC=COM")
	if err != nil {
		t.Fatal(err)
	}
	// Lookup is by normalised DN, so the spelling used to
	// fetch it need not match the spelling used to store it.
	if e.DN != "dc=example,dc=com" {
		t.Errorf("DN = %q", e.DN)
	}
	if len(e.Values) != 5 {
		t.Errorf("values = %d, want 5", len(e.Values))
	}
}

// validBase is a schema-valid attribute set for a dc entry.
func validBase(dc string) []Attribute {
	return []Attribute{
		{"objectClass", []string{
			"top", "organization", "dcObject"}},
		{"o", []string{dc}},
		{"dc", []string{dc}},
	}
}

func TestAddRejectsDuplicate(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	_, err := s.Add("dc=example,dc=com",
		validBase("example"))
	if !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v, want ErrExists", err)
	}
	// And a differently-spelled duplicate is still a
	// duplicate, because the key is the normalised form.
	_, err = s.Add("DC=EXAMPLE,DC=COM", validBase("example"))
	if !errors.Is(err, ErrExists) {
		t.Fatalf("respelled: err = %v, want ErrExists", err)
	}
}

// slapd checks the schema before it checks whether the entry
// exists or whether its parent does. Verified against the
// oracle: a duplicate DN carrying an undefined objectClass comes
// back as invalidSyntax (21), not entryAlreadyExists (68), and a
// missing parent with the same bad class is 21 rather than
// noSuchObject (32).
func TestSchemaCheckedBeforeExistence(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	bad := []Attribute{
		{"objectClass", []string{"nosuchclass"}},
	}
	_, err := s.Add("dc=example,dc=com", bad)
	if errors.Is(err, ErrExists) {
		t.Error("existence was checked before the schema")
	}
	res := resultFor(err)
	if res.Code != ldap.InvalidSyntax {
		t.Errorf("code = %v, want invalidSyntax", res.Code)
	}
	_, err = s.Add("cn=x,ou=absent,dc=example,dc=com", bad)
	if errors.Is(err, ErrNoParent) {
		t.Error("parent was checked before the schema")
	}
}

func TestAddRequiresParent(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	_, err := s.Add("cn=orphan,ou=absent,dc=example,dc=com",
		[]Attribute{
			{"objectClass", []string{"person"}},
			{"cn", []string{"orphan"}},
			{"sn", []string{"Orphan"}},
		})
	if !errors.Is(err, ErrNoParent) {
		t.Fatalf("err = %v, want ErrNoParent", err)
	}
}

func TestGetMissing(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	if _, err := s.Get("cn=nobody,dc=example,dc=com"); !errors.Is(
		err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// The four scopes, from back-mdb/search.c:874-895. The
// distinction that matters: SUBTREE includes the base entry,
// ONELEVEL and SUBORDINATE do not.
func TestSearchScopes(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	base := "dc=example,dc=com"
	cases := []struct {
		scope ldap.Scope
		want  int
	}{
		{ldap.ScopeBase, 1},
		{ldap.ScopeOneLevel, 2},
		{ldap.ScopeSubtree, 5},
		{ldap.ScopeSubordinate, 4},
	}
	for _, c := range cases {
		t.Run(c.scope.String(), func(t *testing.T) {
			got, err := s.Search(base, c.scope)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != c.want {
				t.Errorf("%d entries, want %d: %v",
					len(got), c.want, dns(got))
			}
		})
	}
}

// dns lists entry DNs, for failure messages.
func dns(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.DN)
	}
	return out
}

// A sibling whose DN shares a textual prefix with the base must
// not appear in its subtree. This is what the separator in the
// LIKE pattern is for: without it, dc=com,dc=example would also
// match dc=com,dc=examplecorp.
func TestSubtreeDoesNotMatchPrefixSibling(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	// Its own suffix: it is a sibling naming context, not a
	// child, which is exactly the shape that would leak
	// through a prefix test with no separator.
	if err := s.AddSuffix("dc=examplecorp,dc=com"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Add("dc=examplecorp,dc=com", []Attribute{
		{"objectClass", []string{
			"top", "organization", "dcObject"}},
		{"o", []string{"examplecorp"}},
		{"dc", []string{"examplecorp"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Search("dc=example,dc=com",
		ldap.ScopeSubtree)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got {
		if e.DN == "dc=examplecorp,dc=com" {
			t.Fatal("prefix sibling leaked into subtree")
		}
	}
	if len(got) != 5 {
		t.Errorf("%d entries, want 5: %v", len(got), dns(got))
	}
}
