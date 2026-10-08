package dn

import "testing"

// FuzzParse feeds arbitrary strings to the DN parser. A DN
// arrives from the network on nearly every operation, so a
// panic here is remotely reachable.
func FuzzParse(f *testing.F) {
	f.Add("dc=example,dc=com")
	f.Add("cn=a\\, b,dc=x")
	f.Add("cn=a+sn=b,dc=x")
	f.Add("cn=#41,dc=z")
	f.Add("cn=\\")
	f.Add("=,")
	f.Add("cn=a;dc=x")

	f.Fuzz(func(t *testing.T, in string) {
		parsed, err := Parse(in)
		if err != nil {
			return
		}
		// Anything that parses must re-render and re-parse.
		again, err := Parse(parsed.String())
		if err != nil {
			t.Fatalf("%q rendered %q: unparseable: %v",
				in, parsed.String(), err)
		}
		if len(again) != len(parsed) {
			t.Fatalf("%q: %d RDNs became %d",
				in, len(parsed), len(again))
		}
	})
}
