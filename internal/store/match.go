package store

import (
	"strings"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
	"github.com/FatmanUK/openldap_olivine/internal/schema"
)

// Matches reports whether an entry satisfies a filter.
//
// Evaluated in Go rather than pushed into SQL. Translating an
// arbitrary filter tree into SQL is possible, but the matching
// rules — which internal/schema does not implement yet — decide
// what equality even means, so doing it here keeps one
// definition of matching instead of two that can disagree.
// Pushing it down is an optimisation for when the rules exist.
func Matches(
	reg *schema.Registry, e *Entry, f ldap.Filter,
) bool {
	switch f.Tag {
	case ldap.FilterAnd:
		return matchAll(reg, e, f.Sub)
	case ldap.FilterOr:
		return matchAny(reg, e, f.Sub)
	case ldap.FilterNot:
		// RFC 4511 4.5.1.7: not takes exactly one operand.
		if len(f.Sub) != 1 {
			return false
		}
		return !Matches(reg, e, f.Sub[0])
	case ldap.FilterPresent:
		return present(reg, e, f.Attribute)
	case ldap.FilterEquality:
		return equality(reg, e, f)
	case ldap.FilterSubstrings:
		return substrings(reg, e, f)
	case ldap.FilterGE, ldap.FilterLE:
		return ordering(reg, e, f)
	case ldap.FilterApprox:
		// No approximate matching rules are implemented, so
		// approx falls back to equality. slapd does the
		// same when an attribute has no approx rule
		// (directoryStringApproxMatchOID is the hook it
		// would use).
		return equality(reg, e, f)
	}
	return false
}

// matchAll is the and filter. An empty and is TRUE, RFC 4526.
func matchAll(
	reg *schema.Registry, e *Entry, subs []ldap.Filter,
) bool {
	for _, s := range subs {
		if !Matches(reg, e, s) {
			return false
		}
	}
	return true
}

// matchAny is the or filter. An empty or is FALSE, RFC 4526.
func matchAny(
	reg *schema.Registry, e *Entry, subs []ldap.Filter,
) bool {
	for _, s := range subs {
		if Matches(reg, e, s) {
			return true
		}
	}
	return false
}

// present reports whether the entry has the attribute at all.
func present(
	reg *schema.Registry, e *Entry, attr string,
) bool {
	typ, ok := canonical(reg, attr)
	if !ok {
		return false
	}
	for _, v := range e.Values {
		if v.Type == typ {
			return true
		}
	}
	return false
}

// equality compares under the attribute's equality rule.
//
// The rule's own comparison is used rather than a string test on
// the stored normal form, because integerMatch orders by digit
// count before bytes: "10" and "010" would otherwise differ, and
// the normal form cannot express that on its own.
func equality(
	reg *schema.Registry, e *Entry, f ldap.Filter,
) bool {
	at, ok := reg.AttributeType(f.Attribute)
	if !ok {
		return false
	}
	rule := reg.EqualityRule(at)
	typ := strings.ToLower(canonicalName(at))
	for _, v := range e.Values {
		if v.Type != typ {
			continue
		}
		if rule.Equal(v.Value, f.Value) {
			return true
		}
	}
	return false
}

// canonical resolves an attribute description to the stored
// type name.
func canonical(
	reg *schema.Registry, attr string,
) (string, bool) {
	at, ok := reg.AttributeType(attr)
	if !ok {
		return "", false
	}
	return strings.ToLower(canonicalName(at)), true
}
