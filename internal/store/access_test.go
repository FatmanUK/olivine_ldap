package store

import (
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/acl"
	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// policy parses an access policy or fails the test.
func policy(t *testing.T, text string) *acl.Policy {
	t.Helper()
	p, err := acl.Parse(text)
	if err != nil {
		t.Fatalf("parsing policy: %v", err)
	}
	return p
}

// baseSearch is a base-scope search of Alice.
func baseSearch() *ldap.SearchRequest {
	return searchReq(alice, ldap.ScopeBase,
		presentFilter("objectClass"))
}

// Every expectation below was taken from the oracle: slapd was
// configured with the directive and the result code observed.

// Without disclose, an unreadable entry answers noSuchObject and
// so stays hidden. With disclose it answers insufficientAccess
// and admits it exists. That distinction is what disclose is for.
func TestDiscloseSwitchesTheRefusal(t *testing.T) {
	s := testStore(t)
	seed(t, s)

	s.SetPolicy(policy(t, `access to * by * none`))
	_, res, _ := s.BackendSearch(baseSearch(), anyone)
	if res.Code != ldap.NoSuchObject {
		t.Errorf("none: code = %v, want noSuchObject",
			res.Code)
	}

	s.SetPolicy(policy(t, `access to * by * disclose`))
	_, res, _ = s.BackendSearch(baseSearch(), anyone)
	if res.Code != ldap.InsufficientAccess {
		t.Errorf("disclose: code = %v, want "+
			"insufficientAccess", res.Code)
	}
}

// Search access lets the search succeed but returns no entries;
// read returns them. The oracle gave rc=0/entries=0 and
// rc=0/entries=1 respectively.
func TestSearchWithoutRead(t *testing.T) {
	s := testStore(t)
	seed(t, s)

	s.SetPolicy(policy(t, `access to * by * search`))
	got, res, _ := s.BackendSearch(baseSearch(), anyone)
	if res.Code != ldap.Success {
		t.Errorf("search: code = %v, want success",
			res.Code)
	}
	if len(got) != 0 {
		t.Errorf("search: %d entries, want 0", len(got))
	}

	s.SetPolicy(policy(t, `access to * by * read`))
	got, res, _ = s.BackendSearch(baseSearch(), anyone)
	if res.Code != ldap.Success || len(got) != 1 {
		t.Errorf("read: code = %v, %d entries",
			res.Code, len(got))
	}
}

// Selection is per attribute, so one clause hides description
// while a later one grants the rest.
func TestPerAttributeHiding(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	addDescription(t, s)

	s.SetPolicy(policy(t,
		`access to attrs=description by * none
access to * by * read`))
	got, _, _ := s.BackendSearch(baseSearch(), anyone)
	if len(got) != 1 {
		t.Fatalf("%d entries", len(got))
	}
	for _, a := range got[0].Attributes {
		if a.Type == "description" {
			t.Error("description should be hidden")
		}
	}
	if len(got[0].Attributes) == 0 {
		t.Error("the other attributes should be visible")
	}
}

// someone is an authenticated requester. Updates need one: see
// TestAnonymousUpdateRefused.
var someone = Identity{
	DN: "cn=admin,dc=example,dc=com",
}

// A write needs write access, and read is not enough.
func TestWriteRequiresWrite(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	s.SetPolicy(policy(t, `access to * by * read`))

	if res := s.BackendModify(setDesc(), someone); res.Code ==
		ldap.Success {
		t.Error("read access should not permit a modify")
	}

	s.SetPolicy(policy(t, `access to * by * write`))
	if res := s.BackendModify(setDesc(), someone); res.Code !=
		ldap.Success {
		t.Errorf("write should permit a modify: %v",
			res.Code)
	}
}

// An anonymous update is refused before the ACLs are consulted,
// and with strongerAuthRequired (8) rather than
// insufficientAccess (50). slapd gives
// "Strong(er) authentication required" for an anonymous add of a
// schema-valid entry even under default ACLs, and grants of
// `by * write` do not change it: it is a restriction on the
// connection, not a judgement about the target.
func TestAnonymousUpdateRefused(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	s.SetPolicy(policy(t, `access to * by * write`))

	res := s.BackendModify(setDesc(), anyone)
	if res.Code != ldap.StrongerAuthRequired {
		t.Errorf("modify: code = %v, want "+
			"strongerAuthRequired", res.Code)
	}
	res = s.BackendDelete(alice, anyone)
	if res.Code != ldap.StrongerAuthRequired {
		t.Errorf("delete: code = %v, want "+
			"strongerAuthRequired", res.Code)
	}
	res = s.BackendAdd(&ldap.AddRequest{
		Entry: "cn=New,dc=example,dc=com",
		Attributes: []ldap.AttributeChange{
			{Type: "objectClass",
				Values: []string{"person"}},
			{Type: "cn", Values: []string{"New"}},
			{Type: "sn", Values: []string{"N"}},
		},
	}, anyone)
	if res.Code != ldap.StrongerAuthRequired {
		t.Errorf("add: code = %v, want "+
			"strongerAuthRequired", res.Code)
	}
}

// But the schema is checked before even that: an anonymous add
// of an entry with an undefined objectClass answers invalidSyntax
// (21), not strongerAuthRequired (8).
func TestSchemaCheckedBeforeAuthRestriction(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	res := s.BackendAdd(&ldap.AddRequest{
		Entry: "cn=Bad,dc=example,dc=com",
		Attributes: []ldap.AttributeChange{
			{Type: "objectClass",
				Values: []string{"nosuchclass"}},
		},
	}, anyone)
	if res.Code != ldap.InvalidSyntax {
		t.Errorf("code = %v, want invalidSyntax", res.Code)
	}
}

// setDesc builds a modify that replaces description.
func setDesc() *ldap.ModifyRequest {
	return &ldap.ModifyRequest{
		Object: alice,
		Modifications: []ldap.Modification{{
			Op: ldap.ModifyReplace,
			Attribute: ldap.AttributeChange{
				Type:   "description",
				Values: []string{"x"},
			},
		}},
	}
}

// Compare needs compare access, which read implies and disclose
// does not.
func TestCompareRequiresCompare(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	req := &ldap.CompareRequest{
		Entry: alice, Attribute: "sn", Value: "Anderson",
	}

	s.SetPolicy(policy(t, `access to * by * disclose`))
	if res := s.BackendCompare(req, anyone); res.Code !=
		ldap.InsufficientAccess {
		t.Errorf("disclose: code = %v", res.Code)
	}
	s.SetPolicy(policy(t, `access to * by * compare`))
	if res := s.BackendCompare(req, anyone); res.Code !=
		ldap.CompareTrue {
		t.Errorf("compare: code = %v", res.Code)
	}
}

// The footgun, end to end: this policy stops everyone binding,
// because at bind time the requester is still anonymous. slapd
// answers invalidCredentials under exactly this configuration.
func TestSelfWritePolicyBreaksBind(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	withPassword(t, s, "cn=admin,dc=example,dc=com", "secret")

	s.SetPolicy(policy(t,
		`access to * by self write by users read by * none`))
	_, res := s.BackendBind(&ldap.BindRequest{
		Version: 3,
		Name:    "cn=admin,dc=example,dc=com",
		Simple:  "secret",
	}, anyone)
	if res.Code != ldap.InvalidCredentials {
		t.Errorf("code = %v, want invalidCredentials",
			res.Code)
	}
}

// And the canonical pattern that works.
func TestAuthGrantAllowsBind(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	withPassword(t, s, "cn=admin,dc=example,dc=com", "secret")

	s.SetPolicy(policy(t,
		`access to attrs=userPassword by * auth
access to * by * none`))
	_, res := s.BackendBind(&ldap.BindRequest{
		Version: 3,
		Name:    "cn=admin,dc=example,dc=com",
		Simple:  "secret",
	}, anyone)
	if res.Code != ldap.Success {
		t.Errorf("code = %v, want success", res.Code)
	}
	// And the entry is still not readable.
	_, sres, _ := s.BackendSearch(searchReq(
		"cn=admin,dc=example,dc=com", ldap.ScopeBase,
		presentFilter("objectClass")), anyone)
	if sres.Code == ldap.Success {
		t.Error("the entry should not be readable")
	}
}

// Bound as itself, self matches.
func TestSelfMatchesWhenBound(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	s.SetPolicy(policy(t,
		`access to * by self read by * none`))

	_, res, _ := s.BackendSearch(baseSearch(), anyone)
	if res.Code == ldap.Success {
		t.Error("anonymous should be refused")
	}
	// The normalised form, which is what a bind would have
	// recorded: a client's own spelling does not compare.
	me := Identity{DN: "cn=alice,ou=people,dc=example,dc=com"}
	got, res, _ := s.BackendSearch(baseSearch(), me)
	if res.Code != ldap.Success || len(got) != 1 {
		t.Errorf("self: code = %v, %d entries",
			res.Code, len(got))
	}
}
