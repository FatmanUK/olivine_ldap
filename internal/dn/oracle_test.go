package dn

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/schema"
)

// corpusPath holds slapdn's answers, captured by
// scripts/capture-dn.sh.
const corpusPath = "testdata/normalised.txt"

// invalid marks a DN slapdn rejected.
const invalid = "INVALID"

// oracleCase is one row of the corpus.
type oracleCase struct {
	in, norm, pretty string
}

// TestAgainstSlapdn drives every captured case through
// Normalise and Pretty and compares with slapd's answer.
//
// This is the whole point of internal/dn: the escaping, spacing
// and case rules are too fiddly to derive from RFC 4514 with
// confidence, and slapdn runs slapd's own dnNormalize.
func TestAgainstSlapdn(t *testing.T) {
	reg := coreSchema(t)
	cases := readCorpus(t)
	if len(cases) < 30 {
		t.Fatalf("only %d cases in %s",
			len(cases), corpusPath)
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			checkOne(t, reg, c)
		})
	}
}

// checkOne compares both forms for one case.
func checkOne(
	t *testing.T, reg *schema.Registry, c oracleCase,
) {
	t.Helper()
	got, err := Normalise(reg, c.in)
	compare(t, "normalise", c.norm, got, err)
	got, err = Pretty(reg, c.in)
	compare(t, "pretty", c.pretty, got, err)
}

// compare checks one result against slapd's.
func compare(
	t *testing.T, what, want, got string, err error,
) {
	t.Helper()
	if want == invalid {
		if err == nil {
			t.Errorf("%s: got %q, slapd rejected it",
				what, got)
		}
		return
	}
	if err != nil {
		t.Errorf("%s: %v, slapd said %q", what, err, want)
		return
	}
	if got != want {
		t.Errorf("%s: got %q, slapd said %q",
			what, got, want)
	}
}

// readCorpus loads the captured answers.
func readCorpus(t *testing.T) []oracleCase {
	t.Helper()
	f, err := os.Open(corpusPath)
	if err != nil {
		t.Skipf("%s missing; run scripts/capture-dn.sh",
			corpusPath)
	}
	defer f.Close()
	var out []oracleCase
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			t.Fatalf("malformed corpus line: %q", line)
		}
		out = append(out, oracleCase{f[0], f[1], f[2]})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// coreSchema loads the schema slapdn had: the built-in set
// from schema_init.c plus core.schema.
//
// Both are needed. core.schema comments out cn and name because
// schema_init.c defines them in C, so core.schema alone cannot
// resolve cn=admin — which is how the built-in set came to be
// derived in the first place.
func coreSchema(t *testing.T) *schema.Registry {
	t.Helper()
	reg, err := schema.NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(coreSchemaPath(t))
	if err != nil {
		t.Skip("openldap submodule not initialised")
	}
	defer f.Close()
	if err := schema.LoadFile(reg, f); err != nil {
		t.Fatal(err)
	}
	return reg
}

// coreSchemaPath locates core.schema in the submodule.
func coreSchemaPath(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse",
		"--show-toplevel").Output()
	if err != nil {
		t.Skipf("not in a git checkout: %v", err)
	}
	root := strings.TrimSpace(string(out))
	return filepath.Join(root, "openldap", "servers",
		"slapd", "schema", "core.schema")
}
