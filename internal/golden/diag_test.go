//go:build golden

package golden

import "testing"

// TestOracleDiagnostics prints what the C says, text and all.
//
// Diagnostics are implementation-defined (RFC 4511 4.1.9) so
// they are not compared, but when a result code differs the
// C's own wording is usually the fastest route to why.
func TestOracleDiagnostics(t *testing.T) {
	oracle, err := StartOracle(oraclePort + 1)
	if err != nil {
		t.Fatalf("starting oracle: %v", err)
	}
	defer oracle.Stop()

	for _, script := range Scripts() {
		tr, err := Run(oracle.Addr, script)
		if err != nil {
			t.Errorf("%s: %v\n%s",
				script.Name, err, oracle.Logs())
			continue
		}
		for _, s := range tr.Steps {
			t.Logf("%s / %s -> %s %q",
				script.Name, s.Op, s.Result,
				s.Diagnostic)
		}
	}
}
