package schema

// Use says what a value is being normalised for.
//
// It matters because UTF8StringNormalize trims differently per
// use: a substring fragment's leading or trailing space can be
// significant where a whole value's is not. See normaliseUTF8.
type Use int

const (
	// UseValue is a stored value or an equality assertion.
	UseValue Use = iota
	UseSubstringInitial
	UseSubstringAny
	UseSubstringFinal
)

// RuleKind is what a matching rule can be asked to do.
type RuleKind int

const (
	KindEquality RuleKind = 1 << iota
	KindOrdering
	KindSubstrings
)

// MatchingRule is one matching rule.
//
// Ported from the mrule_defs table in schema_init.c:6491. The
// normalizer and the comparison are separate there too: several
// rules share UTF8StringNormalize and differ only in whether
// they case-fold, which schema_init.c:1893 decides by asking
// whether the rule is associated with caseExactMatch.
type MatchingRule struct {
	OID       string
	Names     []string
	SyntaxOID string
	Kinds     RuleKind

	norm normFunc
	cmp  cmpFunc
}

// normFunc reduces a value to its comparable form.
type normFunc func(string, Use) string

// cmpFunc orders two already-normalised values.
type cmpFunc func(a, b string) int

// Name is the rule's first name, or its OID.
func (m *MatchingRule) Name() string {
	if len(m.Names) > 0 {
		return m.Names[0]
	}
	return m.OID
}

// Normalise reduces value to the form this rule compares.
func (m *MatchingRule) Normalise(
	value string, use Use,
) string {
	if m == nil || m.norm == nil {
		return value
	}
	return m.norm(value, use)
}

// Compare orders two values under this rule, returning a
// negative number, zero, or a positive number.
//
// Both sides are normalised first, so a caller may pass raw
// values.
func (m *MatchingRule) Compare(a, b string) int {
	if m == nil {
		return compareOctets(a, b)
	}
	na := m.Normalise(a, UseValue)
	nb := m.Normalise(b, UseValue)
	if m.cmp == nil {
		return compareOctets(na, nb)
	}
	return m.cmp(na, nb)
}

// Equal reports whether two values match under this rule.
func (m *MatchingRule) Equal(a, b string) bool {
	return m.Compare(a, b) == 0
}

// Has reports whether the rule serves the given kind.
func (m *MatchingRule) Has(k RuleKind) bool {
	return m != nil && m.Kinds&k != 0
}

// compareOctets is octetStringMatch and
// octetStringOrderingMatch: a plain byte comparison.
func compareOctets(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
