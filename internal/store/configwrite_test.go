package store

import (
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// configMod builds a modification of one configuration
// attribute.
func configMod(
	entry string, op ldap.ModifyOp, typ string,
	values ...string,
) *ldap.ModifyRequest {
	return &ldap.ModifyRequest{
		Object: entry,
		Modifications: []ldap.Modification{{
			Op: op,
			Attribute: ldap.AttributeChange{
				Type: typ, Values: values,
			},
		}},
	}
}

// A change made over LDAP takes effect at once, which is the
// whole point of the configuration being writable.
func TestConfigModifyTakesEffect(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)

	res := s.BackendModify(configMod(ConfigDN,
		ldap.ModifyReplace, "olcSizeLimit", "7"), admin)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v (%s)", res.Code,
			res.Diagnostic)
	}
	if got := s.limitsOrDefault().Size; got != 7 {
		t.Errorf("size limit = %d, want 7", got)
	}
}

// And it reaches another replica, which is the reason the
// settings live in Postgres rather than in the environment: a
// second process reading the same database adopts the change
// without being redeployed.
func TestConfigReachesAnotherReplica(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)
	other, err := New(s.db, s.schema)
	if err != nil {
		t.Fatal(err)
	}

	res := s.BackendModify(configMod(ConfigDN,
		ldap.ModifyReplace, "olcTimeLimit", "11"), admin)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v (%s)", res.Code,
			res.Diagnostic)
	}
	if err := other.LoadConfig(); err != nil {
		t.Fatal(err)
	}
	if got := other.limitsOrDefault().Time; got != 11 {
		t.Errorf("replica time limit = %d, want 11", got)
	}
}

// A new suffix is adopted by the running server: an entry under
// it can be added immediately afterwards.
func TestConfigAddsASuffix(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)

	res := s.BackendModify(configMod(databaseDN,
		ldap.ModifyAdd, "olcSuffix", "dc=other,dc=test"),
		admin)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v (%s)", res.Code,
			res.Diagnostic)
	}
	_, err := s.Add("dc=other,dc=test", []Attribute{
		{Type: "objectClass", Values: []string{
			"top", "domain"}},
		{Type: "dc", Values: []string{"other"}},
	})
	if err != nil {
		t.Errorf("adding under the new suffix: %v", err)
	}
}

// The access policy is a configuration setting like any other,
// so a directive written over LDAP changes what the next search
// may see.
func TestConfigChangesTheAccessPolicy(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)

	res := s.BackendModify(configMod(databaseDN,
		ldap.ModifyReplace, "olcAccess",
		"to * by * none"), admin)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v (%s)", res.Code,
			res.Diagnostic)
	}
	_, got, _ := s.BackendSearch(searchReq(
		"dc=example,dc=com", ldap.ScopeSubtree,
		presentFilter("objectClass")), anyone)
	if got.Code == ldap.Success {
		t.Error("`by * none` still permitted a search")
	}
}

// olcAccess is ordered and its order is its meaning, so the
// projection hands it back indexed and a {n} prefix places an
// added value.
func TestConfigAccessKeepsItsOrder(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)
	add := func(v string) {
		t.Helper()
		res := s.BackendModify(configMod(databaseDN,
			ldap.ModifyAdd, "olcAccess", v), admin)
		if res.Code != ldap.Success {
			t.Fatalf("%s: %v (%s)", v, res.Code,
				res.Diagnostic)
		}
	}
	add("to dn.base=\"dc=example,dc=com\" by * read")
	add("{0}to * by * none")

	got := configValuesOf(t, s, "olcAccess")
	want := []string{
		"{0}to * by * none",
		"{1}to dn.base=\"dc=example,dc=com\" by * read",
	}
	if len(got) != len(want) {
		t.Fatalf("olcAccess = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("olcAccess[%d] = %q, want %q",
				i, got[i], want[i])
		}
	}
}

// configValuesOf reads one attribute back out of the projection.
func configValuesOf(
	t *testing.T, s *Store, typ string,
) []string {
	t.Helper()
	got, res, _ := s.BackendSearch(searchReq(
		databaseDN, ldap.ScopeBase,
		presentFilter("objectClass")), admin)
	if res.Code != ldap.Success || len(got) != 1 {
		t.Fatalf("reading back: %v, %d entries",
			res.Code, len(got))
	}
	for _, a := range got[0].Attributes {
		if a.Type == typ {
			return a.Values
		}
	}
	return nil
}

// Hidden from everyone but the administrator on the write side
// too, with the same answer the read side gives: a caller who
// cannot see cn=config learns nothing from trying to change it.
func TestConfigWriteHiddenFromOthers(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)

	res := s.BackendModify(configMod(ConfigDN,
		ldap.ModifyReplace, "olcSizeLimit", "1"), anyone)
	if res.Code != ldap.NoSuchObject {
		t.Errorf("code = %v, want noSuchObject",
			res.Code)
	}
}

// Only what a running server can adopt is settable, and
// everything else is refused rather than stored and ignored.
func TestConfigRefusals(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)
	cases := append(refusalCases(),
		moreRefusalCases()...)
	for _, c := range cases {
		res := s.BackendModify(c.req, admin)
		if res.Code != c.want {
			t.Errorf("%s: code = %v, want %v",
				c.name, res.Code, c.want)
		}
	}
}

// refusalCase is one write that must be refused, and the code it
// must be refused with.
type refusalCase struct {
	name string
	req  *ldap.ModifyRequest
	want ldap.ResultCode
}

// refusalCases are the refusals, kept out of the test body for
// the sake of the function-length rule.
func refusalCases() []refusalCase {
	return []refusalCase{{
		name: "unknown attribute",
		req: configMod(ConfigDN, ldap.ModifyReplace,
			"olcLogLevel", "stats"),
		want: ldap.UnwillingToPerform,
	}, {
		name: "objectClass",
		req: configMod(ConfigDN, ldap.ModifyReplace,
			"objectClass", "olcGlobal"),
		want: ldap.UnwillingToPerform,
	}, {
		name: "right attribute, wrong entry",
		req: configMod(ConfigDN, ldap.ModifyReplace,
			"olcSuffix", "dc=x,dc=test"),
		want: ldap.UnwillingToPerform,
	}, {
		name: "not a number",
		req: configMod(ConfigDN, ldap.ModifyReplace,
			"olcSizeLimit", "lots"),
		want: ldap.InvalidSyntax,
	}, {
		name: "two values for a single-valued setting",
		req: configMod(ConfigDN, ldap.ModifyReplace,
			"olcSizeLimit", "1", "2"),
		want: ldap.ConstraintViolation,
	}}
}

// moreRefusalCases continues refusalCases.
func moreRefusalCases() []refusalCase {
	return []refusalCase{{
		// other, not unwillingToPerform, and that is
		// upstream's answer too: aclparse.c never sets
		// reply.err, so config_parse_add's failure falls
		// through to LDAP_OTHER at bconfig.c:6034.
		name: "malformed access directive",
		req: configMod(databaseDN, ldap.ModifyReplace,
			"olcAccess", "to * by * sideways"),
		want: ldap.Other,
	}, {
		name: "deleting a value that is not there",
		req: configMod(databaseDN, ldap.ModifyDelete,
			"olcSuffix", "dc=absent,dc=test"),
		want: ldap.NoSuchAttribute,
	}, {
		name: "unknown configuration entry",
		req: configMod("cn=other,cn=config",
			ldap.ModifyReplace, "olcSizeLimit", "1"),
		want: ldap.NoSuchObject,
	}}
}

// A refused write changes nothing: the whole configuration is
// compiled before any of it is stored, so a modification that
// would not load is not written.
func TestConfigRefusalLeavesSettingsAlone(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)

	s.BackendModify(configMod(databaseDN,
		ldap.ModifyReplace, "olcAccess",
		"to * by * sideways"), admin)
	if got := s.conf().access; len(got) != 0 {
		t.Errorf("access = %v, want none", got)
	}
	if got := s.limitsOrDefault().Size; got != 42 {
		t.Errorf("size limit = %d, want 42", got)
	}
}

// The administrator cannot be removed, because nothing else may
// write cn=config and the environment's defaults only apply to a
// setting that is absent at boot. slapd permits the equivalent;
// it has a second rootdn to fall back on.
func TestConfigWillNotRemoveTheAdministrator(
	t *testing.T,
) {
	s := testStore(t)
	withConfig(t, s)

	res := s.BackendModify(configMod(databaseDN,
		ldap.ModifyDelete, "olcRootDN"), admin)
	if res.Code != ldap.UnwillingToPerform {
		t.Errorf("code = %v, want unwillingToPerform",
			res.Code)
	}
	if !s.isRoot(admin) {
		t.Error("the administrator was dropped anyway")
	}
}

// A root password set over LDAP is hashed on the way in, which
// slapd does not do: it stores olcRootPW as given, cleartext
// included.
func TestConfigHashesTheRootPassword(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)

	res := s.BackendModify(configMod(databaseDN,
		ldap.ModifyReplace, "olcRootPW", "hunter2"), admin)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v (%s)", res.Code,
			res.Diagnostic)
	}
	stored := s.conf().rootPassword
	if stored == "hunter2" {
		t.Error("stored in the clear")
	}
	if !VerifyPassword(stored, "hunter2") {
		t.Error("the new password does not verify")
	}
}

// The environment is defaults for first boot, not the authority:
// a value already in the database survives a restart with a
// different environment, or a change made over LDAP would be
// undone by the next deploy.
func TestBootstrapDoesNotOverwrite(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)

	res := s.BackendModify(configMod(ConfigDN,
		ldap.ModifyReplace, "olcSizeLimit", "3"), admin)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v (%s)", res.Code,
			res.Diagnostic)
	}
	// As a restarting replica would, with the old environment.
	withConfig(t, s)
	if got := s.limitsOrDefault().Size; got != 3 {
		t.Errorf("size limit = %d, want 3 — the "+
			"environment overwrote a stored setting",
			got)
	}
}

// A configuration change lands while searches are in flight,
// which is the whole reason the settings sit behind an atomic
// pointer rather than in fields. Written for the race detector:
// it passes trivially without -race and is the point of running
// with it.
func TestConfigChangesDuringSearches(t *testing.T) {
	s := testStore(t)
	withConfig(t, s)
	req := searchReq("dc=example,dc=com",
		ldap.ScopeSubtree, presentFilter("objectClass"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			s.BackendSearch(req, admin)
		}
	}()
	for i := 0; i < 10; i++ {
		res := s.BackendModify(configMod(ConfigDN,
			ldap.ModifyReplace, "olcSizeLimit",
			itoa32(int32(i+1))), admin)
		if res.Code != ldap.Success {
			t.Fatalf("code = %v (%s)", res.Code,
				res.Diagnostic)
		}
	}
	<-done
}
