//go:build golden

package golden

import (
	"testing"
)

// oraclePort is fixed rather than ephemeral, because the port
// has to be published into the container before anything can
// bind it to learn what it got.
const oraclePort = 14636

// TestGolden drives every script through both implementations
// and diffs the transcripts.
//
// Behind the `golden` build tag: it needs the oracle image and
// takes seconds rather than milliseconds. `make golden` runs
// it, `make test` does not.
func TestGolden(t *testing.T) {
	oracle, err := StartOracle(oraclePort)
	if err != nil {
		t.Fatalf("starting oracle: %v\n"+
			"Run `make golden-build` first.", err)
	}
	defer oracle.Stop()

	olivine, err := StartOlivine()
	if err != nil {
		t.Fatalf("starting olivine: %v", err)
	}
	defer olivine.Stop()

	for _, script := range Scripts() {
		t.Run(script.Name, func(t *testing.T) {
			compare(t, oracle, olivine, script)
		})
	}
}

// compare runs one script against both and reports a diff.
func compare(
	t *testing.T, oracle *Oracle, olivine *Olivine,
	script Script,
) {
	t.Helper()
	want, err := Run(oracle.Addr, script)
	if err != nil {
		t.Fatalf("oracle: %v\n%s", err, oracle.Logs())
	}
	got, err := Run(olivine.Addr, script)
	if err != nil {
		t.Fatalf("olivine: %v", err)
	}
	same := got.Render(script.ResultsOnly) ==
		want.Render(script.ResultsOnly)

	if script.Pending != "" {
		reportPending(t, script, same, want, got)
		return
	}
	if !same {
		t.Errorf("transcripts differ\n"+
			"--- oracle (C) ---\n%s"+
			"--- olivine (Go) ---\n%s",
			want.Render(script.ResultsOnly),
			got.Render(script.ResultsOnly))
	}
}

// reportPending handles a script that is expected to differ.
//
// A match is the interesting outcome: it means the gap has
// closed and the marker is stale, which is worth failing over
// so the marker gets removed rather than quietly outliving the
// thing it documents.
func reportPending(
	t *testing.T, script Script, same bool,
	want, got *Transcript,
) {
	t.Helper()
	if same {
		t.Errorf("pending script now matches; "+
			"remove Pending from %q (%s)",
			script.Name, script.Pending)
		return
	}
	t.Logf("known difference (%s)\n"+
		"--- oracle (C) ---\n%s"+
		"--- olivine (Go) ---\n%s",
		script.Pending, want.String(), got.String())
}
