//go:build golden

package golden

import (
	"os"
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/acl"
	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// aclPort keeps this test off the other oracles' ports.
const aclPort = oraclePort + 20

// aclCase is one policy applied to both implementations.
type aclCase struct {
	name   string
	policy string
}

// aclCases are the policies compared. Each is installed verbatim
// in slapd.conf and parsed by internal/acl, so a difference in
// the transcript is a difference in how the two read the same
// directive.
func aclCases() []aclCase {
	return []aclCase{
		{"default", ""},
		{"read-all", "access to * by * read"},
		{"none-all", "access to * by * none"},
		{"disclose-all", "access to * by * disclose"},
		{"search-only", "access to * by * search"},
		{"compare-only", "access to * by * compare"},
		{"no-matching-by", `access to * ` +
			`by dn="cn=nobody,dc=example,dc=com" read`},
		{"hide-one-attribute",
			"access to attrs=sn by * none\n" +
				"access to * by * read"},
		{"subtree-scoped",
			`access to dn.subtree=` +
				`"ou=people,dc=example,dc=com" ` +
				"by * none\n" +
				"access to * by * read"},
	}
}

// TestGoldenACL compares access-control behaviour.
//
// This is where the ACL work is actually checked: the semantics
// are too surprising to assert from the manual page, and several
// — the disclose switch, the deny-on-no-matching-by, the
// per-attribute selection — were established by probing slapd in
// the first place.
func TestGoldenACL(t *testing.T) {
	if os.Getenv("OLIVINE_TEST_DSN") == "" {
		t.Skip("OLIVINE_TEST_DSN not set; " +
			"run `make golden-acl`")
	}
	for _, c := range aclCases() {
		t.Run(c.name, func(t *testing.T) {
			compareACL(t, c)
		})
	}
}

// compareACL runs the read scripts under one policy on both.
func compareACL(t *testing.T, c aclCase) {
	t.Helper()
	oracle, err := StartOracleWith(aclPort, c.policy)
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	defer oracle.Stop()
	if err := oracle.Seed(); err != nil {
		t.Fatalf("seeding: %v\n%s", err, oracle.Logs())
	}

	st, err := OpenStore()
	if err != nil || st == nil {
		t.Skipf("no store: %v", err)
	}
	policy, err := acl.Parse(c.policy)
	if err != nil {
		t.Fatalf("parsing %q: %v", c.policy, err)
	}
	st.SetPolicy(policy)

	olivine, err := StartOlivineWith(NewBackend(st))
	if err != nil {
		t.Fatal(err)
	}
	defer olivine.Stop()

	for _, script := range aclScripts() {
		runPair(t, oracle, olivine, script)
	}
}

// runPair compares one script under the installed policy.
func runPair(
	t *testing.T, oracle *Oracle, olivine *Olivine,
	script Script,
) {
	t.Helper()
	want, err := Run(oracle.Addr, script)
	if err != nil {
		t.Fatalf("oracle %s: %v\n%s",
			script.Name, err, oracle.Logs())
	}
	got, err := Run(olivine.Addr, script)
	if err != nil {
		t.Fatalf("olivine %s: %v", script.Name, err)
	}
	if got.Render(script.ResultsOnly) !=
		want.Render(script.ResultsOnly) {
		t.Errorf("%s differs\n"+
			"--- oracle (C) ---\n%s"+
			"--- olivine (Go) ---\n%s",
			script.Name,
			want.Render(script.ResultsOnly),
			got.Render(script.ResultsOnly))
	}
}

// aclScripts are the reads used to observe a policy's effect.
func aclScripts() []Script {
	alice := "cn=Alice,ou=people," + baseDN
	return []Script{
		{Name: "base-alice", Requests: []Request{{
			Name: "base", Op: ldap.ReqSearch,
			Body: searchBody(alice, ldap.ScopeBase,
				presentFilter("objectClass"), nil),
		}}},
		{Name: "sub-base", Requests: []Request{{
			Name: "sub", Op: ldap.ReqSearch,
			Body: searchBody(baseDN, ldap.ScopeSubtree,
				presentFilter("objectClass"),
				[]string{"cn", "sn"}),
		}}},
		{Name: "compare-alice", Requests: []Request{{
			Name: "compare", Op: ldap.ReqCompare,
			Body: compareBody(alice, "sn", "Anderson"),
		}}},
	}
}
