//go:build golden

package golden

import (
	"os"
	"testing"
)

// dataPort keeps the seeded oracle off the protocol oracle's
// port so the two tests can run in one `go test`.
const dataPort = oraclePort + 10

// TestGoldenData is the comparison that matters: identical
// requests against identically seeded trees, one in slapd and
// one in Olivine over Postgres.
//
// Skips without OLIVINE_TEST_DSN, because only this half needs a
// database. `make golden-data` sets it.
func TestGoldenData(t *testing.T) {
	if os.Getenv("OLIVINE_TEST_DSN") == "" {
		t.Skip("OLIVINE_TEST_DSN not set; " +
			"run `make golden-data`")
	}
	st, err := OpenStore()
	if err != nil {
		t.Fatalf("seeding Olivine: %v", err)
	}
	if st == nil {
		t.Skip("no store")
	}
	oracle, err := StartOracle(dataPort)
	if err != nil {
		t.Fatalf("starting oracle: %v\n"+
			"Run `make golden-build` first.", err)
	}
	defer oracle.Stop()
	if err := oracle.Seed(); err != nil {
		t.Fatalf("%v\n%s", err, oracle.Logs())
	}

	olivine, err := StartOlivineWith(NewBackend(st))
	if err != nil {
		t.Fatalf("starting olivine: %v", err)
	}
	defer olivine.Stop()

	for _, script := range DataScripts() {
		t.Run(script.Name, func(t *testing.T) {
			compare(t, oracle, olivine, script)
		})
	}
}
