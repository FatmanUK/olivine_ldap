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

// withConfig stores a configuration, so the projection has
// something to show and a write has something to change.
//
// Through Bootstrap rather than the in-memory setters, because
// the database is the authority: a write to cn=config republishes
// the whole configuration from it, and a setting that was only
// ever in memory would vanish at that point.
func withConfig(t *testing.T, s *Store) {
	t.Helper()
	hashed, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	err = s.Bootstrap(Config{
		Suffixes:         []string{"dc=example,dc=com"},
		RootDN:           "cn=root,dc=example,dc=com",
		RootPasswordHash: hashed,
		Limits:           Limits{Size: 42, Time: 99},
	})
	if err != nil {
		t.Fatal(err)
	}
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

// The shape of the tree is fixed: there is one database, so no
// entry can be added and none can go away. Only values change.
func TestConfigEntriesCannotBeAddedOrRemoved(
	t *testing.T,
) {
	s := testStore(t)
	withConfig(t, s)

	res := s.BackendDelete(databaseDN, admin)
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
