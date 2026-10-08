package store

import (
	"strings"
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// configSearch searches the configuration tree.
func configSearch(
	base string, scope ldap.Scope,
) *ldap.SearchRequest {
	return searchReq(base, scope,
		presentFilter("objectClass"))
}

// withConfig sets up a store with a root DN and limits, so the
// projection has something to show.
func withConfig(t *testing.T, s *Store) {
	t.Helper()
	withRoot(t, s)
	s.SetLimits(Limits{Size: 42, Time: 99})
}

// cn=config is readable by the administrator and invisible to
// everyone else — not refused, invisible: an anonymous caller
// learns nothing, not even that the tree is there.
func TestConfigVisibleOnlyToRoot(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)

	_, res, _ := s.BackendSearch(
		configSearch(ConfigDN, ldap.ScopeBase), anyone)
	if res.Code != ldap.NoSuchObject {
		t.Errorf("anonymous: code = %v, want noSuchObject",
			res.Code)
	}
	got, res, _ := s.BackendSearch(
		configSearch(ConfigDN, ldap.ScopeBase), admin)
	if res.Code != ldap.Success || len(got) != 1 {
		t.Fatalf("root: code = %v, %d entries",
			res.Code, len(got))
	}
}

// The projection shows what is in force, under slapd's attribute
// names so a client that already reads cn=config finds it.
func TestConfigShowsTheRunningSettings(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)

	got, _, _ := s.BackendSearch(
		configSearch(ConfigDN, ldap.ScopeBase), admin)
	if len(got) != 1 {
		t.Fatalf("%d entries", len(got))
	}
	want := map[string]string{
		"olcSizeLimit": "42",
		"olcTimeLimit": "99",
		"cn":           "config",
	}
	for _, a := range got[0].Attributes {
		if expect, ok := want[a.Type]; ok {
			if len(a.Values) != 1 ||
				a.Values[0] != expect {
				t.Errorf("%s = %v, want %q",
					a.Type, a.Values, expect)
			}
			delete(want, a.Type)
		}
	}
	for typ := range want {
		t.Errorf("%s missing", typ)
	}
}

// The database entry names the suffixes and the root DN.
func TestConfigDatabaseEntry(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)
	if err := s.AddSuffix("dc=example,dc=com"); err != nil {
		t.Fatal(err)
	}
	got, res, _ := s.BackendSearch(
		configSearch(ConfigDN, ldap.ScopeOneLevel), admin)
	if res.Code != ldap.Success || len(got) != 1 {
		t.Fatalf("code = %v, %d entries",
			res.Code, len(got))
	}
	var suffix, rootdn string
	for _, a := range got[0].Attributes {
		switch a.Type {
		case "olcSuffix":
			suffix = a.Values[0]
		case "olcRootDN":
			rootdn = a.Values[0]
		}
	}
	if suffix != "dc=example,dc=com" {
		t.Errorf("olcSuffix = %q", suffix)
	}
	if rootdn != "cn=root,dc=example,dc=com" {
		t.Errorf("olcRootDN = %q", rootdn)
	}
}

// The root password is never shown, hashed or otherwise. slapd
// hands back olcRootPW to a reader of cn=config; a hash is still
// something to attack offline, and nothing needs to read it back.
func TestConfigNeverShowsThePassword(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)
	got, _, _ := s.BackendSearch(
		configSearch(ConfigDN, ldap.ScopeSubtree), admin)
	for _, e := range got {
		for _, a := range e.Attributes {
			if a.Type == "olcRootPW" {
				t.Error("olcRootPW was returned")
			}
			for _, v := range a.Values {
				if strings.HasPrefix(
					v, "{ARGON2}") {
					t.Errorf("hash in %s", a.Type)
				}
			}
		}
	}
}

// Every write is refused, naming the environment instead. Two
// sources of truth that can disagree is worse than one that cannot
// be edited live.
func TestConfigIsReadOnly(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)

	res := s.BackendModify(&ldap.ModifyRequest{
		Object: ConfigDN,
		Modifications: []ldap.Modification{{
			Op: ldap.ModifyReplace,
			Attribute: ldap.AttributeChange{
				Type:   "olcSizeLimit",
				Values: []string{"1"},
			},
		}},
	}, admin)
	if res.Code != ldap.UnwillingToPerform {
		t.Errorf("modify: code = %v, want "+
			"unwillingToPerform", res.Code)
	}
	res = s.BackendDelete(databaseDN, admin)
	if res.Code != ldap.UnwillingToPerform {
		t.Errorf("delete: code = %v, want "+
			"unwillingToPerform", res.Code)
	}
	res = s.BackendAdd(&ldap.AddRequest{
		Entry: "cn=new,cn=config",
	}, admin)
	if res.Code != ldap.UnwillingToPerform {
		t.Errorf("add: code = %v, want "+
			"unwillingToPerform", res.Code)
	}
}

// A subtree search returns both entries.
func TestConfigSubtree(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)
	got, res, _ := s.BackendSearch(
		configSearch(ConfigDN, ldap.ScopeSubtree), admin)
	if res.Code != ldap.Success {
		t.Fatal(res.Code)
	}
	if len(got) != 2 {
		t.Errorf("%d entries, want 2", len(got))
	}
}
