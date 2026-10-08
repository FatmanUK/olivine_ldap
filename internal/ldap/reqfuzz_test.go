package ldap

import "testing"

// FuzzParseRequests feeds arbitrary bodies to every request
// decoder. These sit directly behind the envelope parser, so a
// panic in one is as reachable as a panic in the BER layer.
func FuzzParseRequests(f *testing.F) {
	f.Add([]byte{0x04, 0x00})
	f.Add([]byte{0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0xa3, 0x06, 0x04, 0x02, 'c', 'n',
		0x04, 0x00})

	f.Fuzz(func(t *testing.T, in []byte) {
		if r, err := ParseSearchRequest(in); err == nil {
			// A decoded filter must be self-consistent.
			checkFilter(t, r.Filter, 0)
		}
		_, _ = ParseBindRequest(in)
		_, _ = ParseAddRequest(in)
		_, _ = ParseModifyRequest(in)
		_, _ = ParseCompareRequest(in)
	})
}

// checkFilter walks a filter looking for structural nonsense.
func checkFilter(t *testing.T, f Filter, depth int) {
	t.Helper()
	if depth > 64 {
		t.Fatal("filter nested implausibly deep")
	}
	if f.Tag == FilterNot && len(f.Sub) > 1 {
		t.Fatalf("not with %d operands", len(f.Sub))
	}
	for _, s := range f.Sub {
		checkFilter(t, s, depth+1)
	}
}
