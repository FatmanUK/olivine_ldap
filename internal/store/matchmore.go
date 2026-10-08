package store

import (
	"strings"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
	"github.com/FatmanUK/openldap_olivine/internal/schema"
)

// substrings is the substrings filter.
//
// Matched against the normalised value, and the asserted parts
// are normalised the same way, so (cn=AL*) finds cn=Alice under
// caseIgnoreMatch.
func substrings(
	reg *schema.Registry, e *Entry, f ldap.Filter,
) bool {
	at, ok := reg.AttributeType(f.Attribute)
	if !ok {
		return false
	}
	typ := strings.ToLower(canonicalName(at))
	for _, v := range e.Values {
		if v.Type != typ {
			continue
		}
		if matchSubstrings(reg, at, v.Norm, f.Substrings) {
			return true
		}
	}
	return false
}

// matchSubstrings tests one value against initial, any and
// final.
//
// The any parts must appear in order and must not overlap, which
// is why the search advances past each match rather than
// restarting.
func matchSubstrings(
	reg *schema.Registry, at *schema.AttributeType,
	value string, s ldap.Substrings,
) bool {
	norm := func(x string) string {
		return NormaliseValue(reg, at, x)
	}
	rest := value
	if s.Initial != "" {
		p := norm(s.Initial)
		if !strings.HasPrefix(rest, p) {
			return false
		}
		rest = rest[len(p):]
	}
	if s.Final != "" {
		p := norm(s.Final)
		if !strings.HasSuffix(rest, p) {
			return false
		}
		rest = rest[:len(rest)-len(p)]
	}
	for _, a := range s.Any {
		p := norm(a)
		i := strings.Index(rest, p)
		if i < 0 {
			return false
		}
		rest = rest[i+len(p):]
	}
	return true
}

// ordering is the >= and <= filter.
//
// Compared as strings on the normalised value. That is right for
// the caseIgnore* rules, whose ordering rule is a string
// comparison, and wrong for integerOrderingMatch, which wants
// numeric order. Correct ordering needs the matching rules from
// plan step 6's second half; until then this is honest about
// being a string compare.
func ordering(
	reg *schema.Registry, e *Entry, f ldap.Filter,
) bool {
	at, ok := reg.AttributeType(f.Attribute)
	if !ok {
		return false
	}
	typ := strings.ToLower(canonicalName(at))
	want := NormaliseValue(reg, at, f.Value)
	for _, v := range e.Values {
		if v.Type != typ {
			continue
		}
		if f.Tag == ldap.FilterGE && v.Norm >= want {
			return true
		}
		if f.Tag == ldap.FilterLE && v.Norm <= want {
			return true
		}
	}
	return false
}
