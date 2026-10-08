package store

import (
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// withPassword adds an entry carrying a hashed password.
func withPassword(t *testing.T, s *Store, dn, pw string) {
	t.Helper()
	hashed, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Add(dn, []Attribute{
		{"objectClass", []string{"person"}},
		{"cn", []string{"admin"}},
		{"sn", []string{"Admin"}},
		{"userPassword", []string{hashed}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBindSucceeds(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	dn := "cn=admin,dc=example,dc=com"
	withPassword(t, s, dn, "secret")

	res := s.BackendBind(&ldap.BindRequest{
		Version: 3, Name: dn, Simple: "secret",
	})
	if res.Code != ldap.Success {
		t.Errorf("code = %v, want success", res.Code)
	}
}

func TestBindWrongPassword(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	dn := "cn=admin,dc=example,dc=com"
	withPassword(t, s, dn, "secret")

	res := s.BackendBind(&ldap.BindRequest{
		Version: 3, Name: dn, Simple: "wrong",
	})
	if res.Code != ldap.InvalidCredentials {
		t.Errorf("code = %v, want invalidCredentials",
			res.Code)
	}
}

// A missing entry gives invalidCredentials, not noSuchObject:
// telling an unauthenticated caller which DNs exist is a
// disclosure.
func TestBindMissingEntryDoesNotDisclose(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	res := s.BackendBind(&ldap.BindRequest{
		Version: 3,
		Name:    "cn=nobody,dc=example,dc=com",
		Simple:  "secret",
	})
	if res.Code != ldap.InvalidCredentials {
		t.Errorf("code = %v, want invalidCredentials",
			res.Code)
	}
}

// RFC 4513 5.1.1: an empty name and empty password is an
// anonymous bind and succeeds.
func TestAnonymousBind(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	res := s.BackendBind(&ldap.BindRequest{Version: 3})
	if res.Code != ldap.Success {
		t.Errorf("code = %v, want success", res.Code)
	}
}

// RFC 4513 5.1.2: a name with an empty password is an
// unauthenticated bind, which a server should reject — accepting
// it would authenticate anyone who knows a DN.
func TestUnauthenticatedBindRejected(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	dn := "cn=admin,dc=example,dc=com"
	withPassword(t, s, dn, "secret")

	res := s.BackendBind(&ldap.BindRequest{
		Version: 3, Name: dn,
	})
	if res.Code == ldap.Success {
		t.Error("unauthenticated bind must not succeed")
	}
}

func TestSASLRefusedByName(t *testing.T) {
	s := testStore(t)
	res := s.BackendBind(&ldap.BindRequest{
		Version: 3, IsSASL: true, Mechanism: "GSSAPI",
	})
	if res.Code != ldap.AuthMethodNotSupported {
		t.Errorf("code = %v, want authMethodNotSupported",
			res.Code)
	}
}

func TestCompareTrueAndFalse(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	alice := "cn=Alice,ou=people,dc=example,dc=com"

	res := s.BackendCompare(&ldap.CompareRequest{
		Entry: alice, Attribute: "sn", Value: "Anderson",
	})
	if res.Code != ldap.CompareTrue {
		t.Errorf("code = %v, want compareTrue", res.Code)
	}
	res = s.BackendCompare(&ldap.CompareRequest{
		Entry: alice, Attribute: "sn", Value: "Other",
	})
	if res.Code != ldap.CompareFalse {
		t.Errorf("code = %v, want compareFalse", res.Code)
	}
	// Both are successes.
	if !ldap.CompareFalse.IsSuccess() {
		t.Error("compareFalse should count as success")
	}
}
