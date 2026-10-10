package store

import (
	"strings"

	"github.com/FatmanUK/olivine_ldap/internal/ldap"
	"github.com/FatmanUK/olivine_ldap/internal/schema"
)

// substrings is the substrings filter.
//
// Each asserted fragment is normalised under the attribute's
// *substrings* rule and with the use that says which fragment it
// is, because UTF8StringNormalize trims differently for each: an
// `any` fragment keeps both its edges' spaces, an `initial`
// fragment keeps its trailing one, and a `final` fragment keeps
// its leading one. Normalising all three as whole values would
// quietly drop spaces the client asserted.
func substrings(
	reg *schema.Registry, e *Entry, f ldap.Filter,
) bool {
	at, ok := reg.AttributeType(f.Attribute)
	if !ok {
		return false
	}
	rule := reg.SubstringsRule(at)
	if rule == nil {
		// No substrings rule: inappropriateMatching, which
		// makes the value not match rather than falling
		// back to equality.
		return false
	}
	typ := strings.ToLower(canonicalName(at))
	for _, v := range e.Values {
		if v.Type != typ {
			continue
		}
		stored := rule.Normalise(v.Value, schema.UseValue)
		if matchSubstrings(rule, stored, f.Substrings) {
			return true
		}
	}
	return false
}

// matchSubstrings tests one value against initial, any and final.
//
// The any fragments must appear in order and must not overlap,
// which is why the search advances past each match rather than
// restarting.
func matchSubstrings(
	rule *schema.MatchingRule, value string,
	s ldap.Substrings,
) bool {
	rest := value
	if s.Initial != "" {
		p := rule.Normalise(s.Initial,
			schema.UseSubstringInitial)
		if !strings.HasPrefix(rest, p) {
			return false
		}
		rest = rest[len(p):]
	}
	if s.Final != "" {
		p := rule.Normalise(s.Final,
			schema.UseSubstringFinal)
		if !strings.HasSuffix(rest, p) {
			return false
		}
		rest = rest[:len(rest)-len(p)]
	}
	for _, a := range s.Any {
		p := rule.Normalise(a, schema.UseSubstringAny)
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
// The comparison comes from the attribute's ordering rule, so
// integerOrderingMatch orders numerically and the caseIgnore
// family orders as strings. Comparing normalised values as
// strings regardless — which this did before the matching rules
// existed — puts "10" before "9".
func ordering(
	reg *schema.Registry, e *Entry, f ldap.Filter,
) bool {
	at, ok := reg.AttributeType(f.Attribute)
	if !ok {
		return false
	}
	rule := reg.OrderingRule(at)
	if rule == nil {
		return false
	}
	typ := strings.ToLower(canonicalName(at))
	for _, v := range e.Values {
		if v.Type != typ {
			continue
		}
		c := rule.Compare(v.Value, f.Value)
		if f.Tag == ldap.FilterGE && c >= 0 {
			return true
		}
		if f.Tag == ldap.FilterLE && c <= 0 {
			return true
		}
	}
	return false
}
