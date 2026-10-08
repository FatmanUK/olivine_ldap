package schema

import "strings"

// normaliseUTF8 is UTF8StringNormalize from
// schema_init.c:1875-1941, which caseIgnoreMatch, caseExactMatch
// and their ordering and substrings variants all share.
//
// Three behaviours worth stating, because each is easy to get
// wrong:
//
// Case folding is the only difference between the caseIgnore and
// caseExact families. schema_init.c:1893 picks it by asking
// whether the rule is associated with caseExactMatch.
//
// Runs of spaces collapse to one. Leading space is trimmed
// unless the use is SUBSTR_ANY or SUBSTR_FINAL, and trailing
// space unless it is SUBSTR_INITIAL or SUBSTR_ANY — a fragment
// that begins or ends mid-value has significant space at that
// edge.
//
// A value of nothing but spaces normalises to a *single space*,
// not to empty. strings.Fields would give the empty string, and
// the entry would then never match.
func normaliseUTF8(fold bool) normFunc {
	return func(value string, use Use) string {
		if value == "" {
			return ""
		}
		if fold {
			value = strings.ToLower(value)
		}
		out := collapseSpaceRuns(value,
			trimsLeading(use), trimsTrailing(use))
		if out == "" {
			// "string of all spaces is treated as one
			// space".
			return " "
		}
		return out
	}
}

// trimsLeading reports whether leading space is insignificant.
func trimsLeading(use Use) bool {
	return use != UseSubstringAny &&
		use != UseSubstringFinal
}

// trimsTrailing reports whether trailing space is
// insignificant.
func trimsTrailing(use Use) bool {
	return use != UseSubstringInitial &&
		use != UseSubstringAny
}

// collapseSpaceRuns reduces runs of ASCII space to one, trimming
// the edges as told.
func collapseSpaceRuns(
	s string, trimLead, trimTrail bool,
) string {
	var b strings.Builder
	wasSpace := trimLead
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			wasSpace = false
			b.WriteByte(s[i])
			continue
		}
		if !wasSpace {
			b.WriteByte(' ')
		}
		wasSpace = true
	}
	out := b.String()
	if trimTrail && strings.HasSuffix(out, " ") {
		out = out[:len(out)-1]
	}
	return out
}

// normaliseNumericString is numericStringNormalize: every space
// removed, and a single space when nothing is left.
func normaliseNumericString(value string, _ Use) string {
	out := strings.ReplaceAll(value, " ", "")
	if out == "" {
		return " "
	}
	return out
}

// normaliseTelephone is telephoneNumberNormalize: spaces and
// hyphens removed, and a single space when nothing is left.
//
// It does not case-fold, despite the name of the attribute's
// usual matching rule suggesting a string comparison.
func normaliseTelephone(value string, _ Use) string {
	out := strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, value)
	if out == "" {
		return " "
	}
	return out
}

// normaliseIdentity leaves a value alone, which is what the
// rules with a NULL normalizer do: octetStringMatch,
// integerMatch, booleanMatch, bitStringMatch and
// objectIdentifierMatch all rely on their syntax's validator
// having already rejected non-canonical input.
func normaliseIdentity(value string, _ Use) string {
	return value
}
