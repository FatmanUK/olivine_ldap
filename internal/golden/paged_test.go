//go:build golden

package golden

import (
	"os"
	"sort"
	"testing"
)

// pagedPort keeps this test off the other oracles' ports.
const pagedPort = oraclePort + 50

// TestGoldenPaged walks a paged search to its end on both
// implementations and compares what each page contained.
//
// Driven page by page in Go rather than as a Script, because each
// request carries the cookie the previous reply returned: a fixed
// list of requests cannot express that.
//
// The cookies themselves are *not* compared. RFC 2696 2 declares
// the cookie opaque, slapd's is an index position and Olivine's
// names the last DN returned — comparing them would assert
// something neither side promises. What must agree is the sequence
// of pages.
func TestGoldenPaged(t *testing.T) {
	if os.Getenv("OLIVINE_TEST_DSN") == "" &&
		os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("needs a test database; " +
			"run `make golden-paged`")
	}
	oracle, err := StartOracle(pagedPort)
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
	olivine, err := StartOlivineWith(NewBackend(st))
	if err != nil {
		t.Fatal(err)
	}
	defer olivine.Stop()

	for _, size := range []int32{1, 2, 4, 20} {
		t.Run(pageName(size), func(t *testing.T) {
			comparePaging(t, oracle, olivine, size)
		})
	}
}

// pageName labels a subtest.
func pageName(size int32) string {
	return "page-size-" + itoa(size)
}

// itoa avoids importing strconv for one call.
func itoa(n int32) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// comparePaging walks both to the end and compares the shape.
//
// Which entries land on which page is *not* compared: that depends
// on traversal order, and slapd walks its index while Olivine
// walks in DN order. RFC 2696 pins neither, so asserting it would
// assert something neither implementation promises — the same
// reason the size-limit scripts compare counts rather than sets.
//
// What is compared is everything the control does promise: how
// many pages, how big each one is, and that the pages together are
// exactly the result set with nothing lost or repeated. A paging
// bug shows up in all three.
func comparePaging(
	t *testing.T, oracle *Oracle, olivine *Olivine,
	size int32,
) {
	t.Helper()
	want, err := WalkPages(oracle.Addr, size)
	if err != nil {
		t.Fatalf("oracle: %v\n%s", err, oracle.Logs())
	}
	got, err := WalkPages(olivine.Addr, size)
	if err != nil {
		t.Fatalf("olivine: %v", err)
	}
	if len(got) != len(want) {
		t.Errorf("%d pages, want %d", len(got), len(want))
	}
	comparePageSizes(t, got, want)
	compareUnion(t, got, want)
	checkNoDuplicates(t, got)
}

// comparePageSizes checks each page holds what it should.
func comparePageSizes(t *testing.T, got, want [][]string) {
	t.Helper()
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		if len(got[i]) != len(want[i]) {
			t.Errorf("page %d holds %d entries, want %d",
				i, len(got[i]), len(want[i]))
		}
	}
}

// compareUnion checks the pages together are the same set.
func compareUnion(t *testing.T, got, want [][]string) {
	t.Helper()
	g, w := flatten(got), flatten(want)
	if !sameDNs(g, w) {
		t.Errorf("the pages do not cover the same "+
			"entries\n got %v\nwant %v", g, w)
	}
}

// checkNoDuplicates catches an entry returned on two pages, which
// is the failure a cookie gets wrong most easily.
func checkNoDuplicates(t *testing.T, pages [][]string) {
	t.Helper()
	seen := map[string]int{}
	for i, page := range pages {
		for _, dn := range page {
			if prev, dup := seen[dn]; dup {
				t.Errorf("%s on pages %d and %d",
					dn, prev, i)
			}
			seen[dn] = i
		}
	}
}

// flatten concatenates the pages and sorts them.
func flatten(pages [][]string) []string {
	var out []string
	for _, p := range pages {
		out = append(out, p...)
	}
	sort.Strings(out)
	return out
}

// sameDNs compares two pages.
func sameDNs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
