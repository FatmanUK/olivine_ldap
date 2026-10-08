package golden

import "testing"

// Normalise must make entry, attribute and value order
// irrelevant, since none of the three is pinned by the
// protocol for an unsorted search.
func TestNormaliseIsOrderIndependent(t *testing.T) {
	a := &Transcript{Steps: []Step{{
		Op: "search", Result: "success",
		Entries: []Entry{
			{DN: "cn=b", Attributes: []Attribute{
				{Type: "sn",
					Values: []string{"2", "1"}},
				{Type: "cn", Values: []string{"b"}},
			}},
			{DN: "cn=a"},
		},
	}}}
	b := &Transcript{Steps: []Step{{
		Op: "search", Result: "success",
		Entries: []Entry{
			{DN: "cn=a"},
			{DN: "cn=b", Attributes: []Attribute{
				{Type: "cn", Values: []string{"b"}},
				{Type: "sn",
					Values: []string{"1", "2"}},
			}},
		},
	}}}
	a.Normalise()
	b.Normalise()
	if a.String() != b.String() {
		t.Fatalf("order leaked into the comparison:\n%s\n%s",
			a.String(), b.String())
	}
}

// Step order, by contrast, must matter: it is the one thing
// the client controls.
func TestStepOrderMatters(t *testing.T) {
	a := &Transcript{Steps: []Step{
		{Op: "bind", Result: "success"},
		{Op: "search", Result: "success"},
	}}
	b := &Transcript{Steps: []Step{
		{Op: "search", Result: "success"},
		{Op: "bind", Result: "success"},
	}}
	a.Normalise()
	b.Normalise()
	if a.String() == b.String() {
		t.Fatal("step order should not be normalised away")
	}
}

func TestScriptsEncode(t *testing.T) {
	for _, s := range Scripts() {
		for i, r := range s.Requests {
			_, err := r.Encode(int32(i + 1))
			if err != nil {
				t.Errorf("%s/%s: %v",
					s.Name, r.Name, err)
			}
		}
	}
}
