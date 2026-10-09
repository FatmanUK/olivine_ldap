//go:build golden

package golden

import (
	"os"
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/acl"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// saslPort keeps this test off the other oracles' ports.
const saslPort = oraclePort + 60

// TestGoldenSASLExternal compares a SASL EXTERNAL bind.
//
// Both sides are given the same CA and the same client
// certificate, and both are then asked a question only the right
// identity can answer: an access policy grants read to the
// certificate's DN alone, so a search succeeding proves the two
// derived the same DN from the same certificate.
//
// Comparing the bind result alone would not prove that. Success
// says a bind happened, not who as — and the DN is where this
// could go wrong, because an X.509 subject runs most-general-first
// and an LDAP DN runs the other way.
func TestGoldenSASLExternal(t *testing.T) {
	if os.Getenv("OLIVINE_TEST_DSN") == "" &&
		os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("needs a test database; " +
			"run `make golden-sasl`")
	}
	// Only the certificate's own DN may read.
	policy := `access to * by dn.exact="` +
		normalisedClientDN + `" read by * none`

	oracle, err := StartOracleWith(saslPort, policy)
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
	parsed, err := acl.Parse(policy)
	if err != nil {
		t.Fatalf("parsing %q: %v", policy, err)
	}
	st.SetPolicy(parsed)

	olivine, err := StartOlivineWith(NewBackend(st))
	if err != nil {
		t.Fatal(err)
	}
	defer olivine.Stop()

	compareExternal(t, oracle, olivine)
}

// normalisedClientDN is ClientSubjectDN as a DN comparison sees
// it: attribute types and caseIgnoreMatch values folded.
const normalisedClientDN = "cn=olivine-client,o=olivine,c=gb"

// compareExternal binds EXTERNAL on both and compares what each
// identity can then read.
func compareExternal(
	t *testing.T, oracle *Oracle, olivine *Olivine,
) {
	t.Helper()
	after := Script{
		Name: "read as the certificate",
		Requests: []Request{{
			Name: "read", Op: ldap.ReqSearch,
			Body: searchBody(baseDN, ldap.ScopeBase,
				presentFilter("objectClass"),
				[]string{"dc"}),
		}},
	}
	wantOut, want, err := RunExternal(oracle.Addr, after)
	if err != nil {
		t.Fatalf("oracle: %v\n%s", err, oracle.Logs())
	}
	gotOut, got, err := RunExternal(olivine.Addr, after)
	if err != nil {
		t.Fatalf("olivine: %v", err)
	}
	checkOutcome(t, gotOut, wantOut)
	checkReads(t, got, want)
}

// checkOutcome compares where the exchange ended, not how many
// rounds it took.
func checkOutcome(t *testing.T, got, want SASLOutcome) {
	t.Helper()
	if got.Result != want.Result {
		t.Errorf("bind ended %q, oracle ended %q",
			got.Result, want.Result)
	}
	t.Logf("rounds: olivine %d, oracle %d (not compared: "+
		"RFC 4422 3 leaves it to the mechanism)",
		got.Steps, want.Steps)
}

// checkReads compares what the bound identity could read.
func checkReads(t *testing.T, got, want *Transcript) {
	t.Helper()
	if got.String() != want.String() {
		t.Errorf("the bound identity reads differently\n"+
			"--- oracle (C) ---\n%s"+
			"--- olivine (Go) ---\n%s",
			want.String(), got.String())
	}
	// And it must actually have read something, or this is two
	// servers agreeing about a refusal.
	if len(got.Steps) == 0 ||
		len(got.Steps[0].Entries) == 0 {
		t.Errorf("the bound identity read nothing; "+
			"transcript:\n%s", got.String())
	}
}
