package schema

import "strings"

// registerRules loads the built-in matching rules.
func (r *Registry) registerRules() {
	for _, m := range builtinRules() {
		r.rulesByOID[m.OID] = m
		for _, n := range m.Names {
			r.rulesByName[strings.ToLower(n)] = m
		}
	}
}

// MatchingRule finds a rule by OID or name.
func (r *Registry) MatchingRule(
	key string,
) (*MatchingRule, bool) {
	if m, ok := r.rulesByOID[key]; ok {
		return m, true
	}
	m, ok := r.rulesByName[strings.ToLower(key)]
	return m, ok
}

// EqualityRule resolves an attribute type's equality matching
// rule, following SUP when the type states none itself.
//
// Not a detail. core.schema defines cn as
//
//	attributetype ( 2.5.4.3 NAME ( 'cn' 'commonName' )
//		SUP name )
//
// with no EQUALITY of its own; caseIgnoreMatch comes from
// `name`. Reading only the type's own EQUALITY leaves cn
// case-sensitive, so CN=Foo Bar would never match cn=foo bar.
func (r *Registry) EqualityRule(
	at *AttributeType,
) *MatchingRule {
	return r.inherited(at, func(
		a *AttributeType,
	) string {
		return a.EqualityOID
	})
}

// OrderingRule resolves the ordering matching rule, or nil when
// the attribute has none.
//
// Nil is the answer, not a substitute. filterentry.c:648-658
// reads the type's own sat_ordering and, when it is NULL, sets
// LDAP_INAPPROPRIATE_MATCHING and skips the value — so a >= or
// <= filter on such an attribute matches nothing and the search
// succeeds empty.
//
// serialNumber is the example that caught this: it declares
// EQUALITY caseIgnoreMatch and SUBSTR caseIgnoreSubstringsMatch
// but no ORDERING, so slapd returns nothing for
// (serialNumber>=10). An earlier version here substituted
// caseIgnoreOrderingMatch from the equality rule's family and
// returned three entries. The "associated" field in
// schema_init.c's table, which suggested that substitution, is
// about indexing and approximate matching — not about filling in
// a rule the attribute does not have.
func (r *Registry) OrderingRule(
	at *AttributeType,
) *MatchingRule {
	return r.inherited(at, func(
		a *AttributeType,
	) string {
		return a.OrderingOID
	})
}

// SubstringsRule resolves the substrings matching rule, or nil.
//
// Nil for the same reason as OrderingRule: slapd reads
// sat_substr directly and answers inappropriateMatching when it
// is absent.
func (r *Registry) SubstringsRule(
	at *AttributeType,
) *MatchingRule {
	return r.inherited(at, func(
		a *AttributeType,
	) string {
		return a.SubstrOID
	})
}

// inherited walks the SUP chain looking for a rule.
//
// The depth limit guards against a schema whose SUP chain loops.
// slapd checks for that at load time; Olivine does not yet.
func (r *Registry) inherited(
	at *AttributeType, pick func(*AttributeType) string,
) *MatchingRule {
	for depth := 0; at != nil && depth < 16; depth++ {
		if oid := pick(at); oid != "" {
			m, ok := r.MatchingRule(oid)
			if ok {
				return m
			}
			return nil
		}
		if at.SuperiorOID == "" {
			return nil
		}
		sup, ok := r.AttributeType(at.SuperiorOID)
		if !ok {
			return nil
		}
		at = sup
	}
	return nil
}
