package schema

// stringRules are the rules that compare bytes, with or without
// a normalizer of their own.
func stringRules() []*MatchingRule {
	return []*MatchingRule{
		{OID: MROIDOctetString, Names: []string{
			"octetStringMatch"},
			Kinds: KindEquality, norm: normaliseIdentity},
		{OID: MROIDOctetStringOrder, Names: []string{
			"octetStringOrderingMatch"},
			Kinds: KindOrdering, norm: normaliseIdentity},
		{OID: MROIDBitString, Names: []string{
			"bitStringMatch"},
			Kinds: KindEquality, norm: normaliseIdentity},
		{OID: MROIDObjectIdentifier, Names: []string{
			"objectIdentifierMatch"},
			SyntaxOID: SyntaxOID,
			Kinds:     KindEquality,
			norm:      normaliseIdentity},
		{OID: MROIDDistinguishedName, Names: []string{
			"distinguishedNameMatch"},
			SyntaxOID: SyntaxDN,
			Kinds:     KindEquality,
			norm:      normaliseIdentity},
		{OID: MROIDUniqueMember, Names: []string{
			"uniqueMemberMatch"},
			Kinds: KindEquality, norm: normaliseIdentity},
		{OID: MROIDGeneralizedTime, Names: []string{
			"generalizedTimeMatch"},
			Kinds: KindEquality, norm: normaliseIdentity},
		{OID: MROIDGeneralizedOrder, Names: []string{
			"generalizedTimeOrderingMatch"},
			Kinds: KindOrdering, norm: normaliseIdentity},
		{OID: MROIDTelephoneNumber, Names: []string{
			"telephoneNumberMatch"},
			Kinds: KindEquality,
			norm:  normaliseTelephone},
		{OID: MROIDTelephoneSubstr, Names: []string{
			"telephoneNumberSubstringsMatch"},
			Kinds: KindSubstrings,
			norm:  normaliseTelephone},
	}
}

// numberRules are the numeric families.
//
// integerMatch carries a comparison of its own: ordering an
// integer is not ordering its digits, and "10" must sort after
// "9".
func numberRules() []*MatchingRule {
	return []*MatchingRule{
		{OID: MROIDInteger, Names: []string{
			"integerMatch"},
			SyntaxOID: SyntaxInteger,
			Kinds:     KindEquality,
			norm:      normaliseIdentity,
			cmp:       compareInteger},
		{OID: MROIDIntegerOrder, Names: []string{
			"integerOrderingMatch"},
			SyntaxOID: SyntaxInteger,
			Kinds:     KindOrdering,
			norm:      normaliseIdentity,
			cmp:       compareInteger},
		{OID: MROIDNumericString, Names: []string{
			"numericStringMatch"},
			SyntaxOID: SyntaxNumericString,
			Kinds:     KindEquality,
			norm:      normaliseNumericString},
		{OID: MROIDNumericOrder, Names: []string{
			"numericStringOrderingMatch"},
			SyntaxOID: SyntaxNumericString,
			Kinds:     KindOrdering,
			norm:      normaliseNumericString},
		{OID: MROIDNumericSubstr, Names: []string{
			"numericStringSubstringsMatch"},
			SyntaxOID: SyntaxNumericString,
			Kinds:     KindSubstrings,
			norm:      normaliseNumericString},
		{OID: MROIDBoolean, Names: []string{
			"booleanMatch"},
			SyntaxOID: SyntaxBoolean,
			Kinds:     KindEquality,
			norm:      normaliseIdentity},
	}
}
