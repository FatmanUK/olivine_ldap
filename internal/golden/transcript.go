package golden

import (
	"fmt"
	"sort"
	"strings"
)

// Transcript is one run's observable output, in a form that
// can be compared between implementations.
//
// Comparing raw bytes would fail on things that are allowed to
// differ: message ids echo the request, diagnostics are
// explicitly implementation-defined by RFC 4511 4.1.9, and
// entry order is unspecified for a search without a sort
// control. A transcript keeps what the protocol pins down and
// normalises the rest.
type Transcript struct {
	Steps []Step
}

// Step is one request and what came back.
type Step struct {
	Op     string
	Result string
	// Entries are search results, sorted by DN.
	Entries []Entry
	// Diagnostic is recorded but compared only when
	// CompareDiagnostics is set, since RFC 4511 4.1.9 leaves
	// the text to the implementation.
	Diagnostic string
}

// Entry is one returned entry, attributes sorted.
type Entry struct {
	DN         string
	Attributes []Attribute
}

// Attribute is one attribute and its values, sorted.
type Attribute struct {
	Type   string
	Values []string
}

// Normalise puts a transcript into comparable order: entries
// by DN, attributes by type, values within an attribute.
//
// Steps are left in order, because operation order is the one
// thing the client controls.
func (t *Transcript) Normalise() {
	for i := range t.Steps {
		normaliseStep(&t.Steps[i])
	}
}

// normaliseStep sorts one step's entries and attributes.
func normaliseStep(s *Step) {
	sort.Slice(s.Entries, func(i, j int) bool {
		return s.Entries[i].DN < s.Entries[j].DN
	})
	for i := range s.Entries {
		e := &s.Entries[i]
		sort.Slice(e.Attributes, func(a, b int) bool {
			return e.Attributes[a].Type <
				e.Attributes[b].Type
		})
		for j := range e.Attributes {
			sort.Strings(e.Attributes[j].Values)
		}
	}
}

// String renders a transcript as stable text, so a diff reads
// like a diff rather than a struct dump.
func (t *Transcript) String() string {
	b := &strings.Builder{}
	for i, s := range t.Steps {
		fmt.Fprintf(b, "%d %s -> %s\n", i, s.Op, s.Result)
		for _, e := range s.Entries {
			fmt.Fprintf(b, "  dn: %s\n", e.DN)
			writeAttrs(b, e.Attributes)
		}
	}
	return b.String()
}

// writeAttrs renders one entry's attributes.
func writeAttrs(b *strings.Builder, attrs []Attribute) {
	for _, a := range attrs {
		for _, v := range a.Values {
			fmt.Fprintf(b, "    %s: %s\n", a.Type, v)
		}
	}
}
