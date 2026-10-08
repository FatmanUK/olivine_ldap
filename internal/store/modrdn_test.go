package store

import (
	"errors"
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// admin is the configured root identity in these tests.
//
// Every update below binds as it, because an update needs write
// access and the default policy grants only read — so an ordinary
// authenticated DN cannot rename anything.
var admin = Identity{DN: "cn=root,dc=example,dc=com"}

// withRoot configures the administrator.
func withRoot(t *testing.T, s *Store) {
	t.Helper()
	hashed, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	err = s.SetRootDN("cn=root,dc=example,dc=com", hashed)
	if err != nil {
		t.Fatal(err)
	}
}

// renameTo builds a ModDNRequest.
func renameTo(
	entry, newRDN string, deleteOld bool,
) *ldap.ModDNRequest {
	return &ldap.ModDNRequest{
		Entry: entry, NewRDN: newRDN,
		DeleteOldRDN: deleteOld,
	}
}

// slapd replaces the RDN attribute value: renaming cn=Alice to
// cn=Alicia leaves the entry carrying cn: Alicia. Moving only the
// DN leaves an entry whose cn does not match its own name, and a
// search for the new name finds nothing.
func TestModDNReplacesRDNValue(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	withRoot(t, s)
	res := s.BackendModDN(
		renameTo(alice, "cn=Alicia", true), admin)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v", res.Code)
	}
	e, err := s.Get("cn=Alicia,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	got := valuesOf(e, "cn")
	if len(got) != 1 || got[0] != "Alicia" {
		t.Errorf("cn = %v, want [Alicia]", got)
	}
}

// With deleteoldrdn false the entry keeps both values.
func TestModDNKeepsOldRDNValue(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	withRoot(t, s)
	res := s.BackendModDN(
		renameTo(alice, "cn=Alicia", false), admin)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v", res.Code)
	}
	e, err := s.Get("cn=Alicia,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	if got := valuesOf(e, "cn"); len(got) != 2 {
		t.Errorf("cn = %v, want both values", got)
	}
}

// back-mdb renames a whole subtree, verified against the oracle.
// An earlier version refused a non-leaf on an assumption.
func TestModDNRenamesSubtree(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	withRoot(t, s)
	res := s.BackendModDN(renameTo(
		"ou=people,dc=example,dc=com", "ou=humans", true),
		admin)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v", res.Code)
	}
	moved, err := s.Search("ou=humans,dc=example,dc=com",
		ldap.ScopeSubtree)
	if err != nil {
		t.Fatal(err)
	}
	// The ou itself plus its two children.
	if len(moved) != 3 {
		t.Errorf("%d entries under the new DN, want 3",
			len(moved))
	}
	// And nothing is left behind.
	if _, err := s.Get(
		"cn=Alice,ou=people,dc=example,dc=com"); err == nil {
		t.Error("a descendant was left at the old DN")
	}
}

// A descendant keeps its own spelling: only the moved suffix
// changes. Rebuilding from the normal form gives cn=alice where
// slapd gives cn=Alice.
func TestModDNPreservesDescendantSpelling(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	withRoot(t, s)
	res := s.BackendModDN(renameTo(
		"ou=people,dc=example,dc=com", "ou=humans", true),
		admin)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v", res.Code)
	}
	e, err := s.Get("cn=Alice,ou=humans,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	want := "cn=Alice,ou=humans,dc=example,dc=com"
	if e.PrettyDN != want {
		t.Errorf("pretty = %q, want %q", e.PrettyDN, want)
	}
}

func TestModDNRefusesExistingDN(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	withRoot(t, s)
	res := s.BackendModDN(
		renameTo(alice, "cn=Bob", true), admin)
	if res.Code != ldap.AlreadyExists {
		t.Errorf("code = %v, want entryAlreadyExists",
			res.Code)
	}
}

// The administrator has no entry and bypasses the policy: that is
// what lets a directory be administered before it holds anything,
// and why `by * none` does not lock out the administrator.
func TestRootDNBypassesPolicyAndNeedsNoEntry(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	withRoot(t, s)
	s.SetPolicy(policy(t, `access to * by * none`))

	id, res := s.BackendBind(&ldap.BindRequest{
		Version: 3,
		Name:    "cn=root,dc=example,dc=com",
		Simple:  "secret",
	}, anyone)
	if res.Code != ldap.Success {
		t.Fatalf("bind: %v", res.Code)
	}
	if id.DN != "cn=root,dc=example,dc=com" {
		t.Errorf("identity = %q", id.DN)
	}
	// No entry exists for it.
	if _, err := s.Get(
		"cn=root,dc=example,dc=com"); !errors.Is(
		err, ErrNotFound) {
		t.Error("the rootdn should have no entry")
	}
	// And it can still read under a deny-all policy.
	got, sres := s.BackendSearch(baseSearch(), id)
	if sres.Code != ldap.Success || len(got) != 1 {
		t.Errorf("root read: %v, %d entries",
			sres.Code, len(got))
	}
}

func TestRootDNWrongPassword(t *testing.T) {
	s := testStore(t)
	withRoot(t, s)
	_, res := s.BackendBind(&ldap.BindRequest{
		Version: 3,
		Name:    "cn=root,dc=example,dc=com",
		Simple:  "wrong",
	}, anyone)
	if res.Code != ldap.InvalidCredentials {
		t.Errorf("code = %v, want invalidCredentials",
			res.Code)
	}
}
