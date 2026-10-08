//go:build golden

package golden

import (
	"os"
	"testing"
)

// expectedEmpty are the scripts whose correct answer returns no
// entries, so they are exempt from the check below.
//
// filter-ordering is the interesting member: serialNumber
// declares no ORDERING rule, so slapd answers
// inappropriateMatching and the search succeeds with nothing.
// Zero entries *is* the behaviour under test there.
var expectedEmpty = map[string]bool{
	"search-missing-base":       true,
	"compare":                   true,
	"add-undefined-objectclass": true,
	"filter-ordering":           true,
	"add-anonymous":             true,
	"rootdse-scope":             true,
}

// TestDataScriptsAreNotVacuous guards against a comparison that
// passes because both sides returned nothing.
//
// Two servers agreeing about silence proves very little, and a
// script can start returning nothing without anyone noticing —
// a renamed attribute in the fixture would do it. This fails if
// a script that should match something stops matching.
func TestDataScriptsAreNotVacuous(t *testing.T) {
	if os.Getenv("OLIVINE_TEST_DSN") == "" {
		t.Skip("needs OLIVINE_TEST_DSN")
	}
	st, err := OpenStore()
	if err != nil || st == nil {
		t.Skipf("no store: %v", err)
	}
	olivine, err := StartOlivineWith(NewBackend(st))
	if err != nil {
		t.Fatal(err)
	}
	defer olivine.Stop()

	for _, script := range DataScripts() {
		checkNotVacuous(t, olivine, script)
	}
}

// checkNotVacuous runs one script and reports its entry counts.
func checkNotVacuous(
	t *testing.T, olivine *Olivine, script Script,
) {
	t.Helper()
	tr, err := Run(olivine.Addr, script)
	if err != nil {
		t.Errorf("%s: %v", script.Name, err)
		return
	}
	total := 0
	for _, s := range tr.Steps {
		total += len(s.Entries)
		t.Logf("%-26s %-22s %-22s entries=%d",
			script.Name, s.Op, s.Result, len(s.Entries))
	}
	if total == 0 && !expectedEmpty[script.Name] {
		t.Errorf("%s matched nothing; either the fixture "+
			"changed or the script is now vacuous",
			script.Name)
	}
}
