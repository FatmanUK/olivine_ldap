package schema

// Matching rule OIDs, from the mrule_defs table in
// schema_init.c:6491 onwards.
const (
	MROIDObjectIdentifier  = "2.5.13.0"
	MROIDDistinguishedName = "2.5.13.1"
	MROIDCaseIgnore        = "2.5.13.2"
	MROIDCaseIgnoreOrder   = "2.5.13.3"
	MROIDCaseIgnoreSubstr  = "2.5.13.4"
	MROIDCaseExact         = "2.5.13.5"
	MROIDCaseExactOrder    = "2.5.13.6"
	MROIDCaseExactSubstr   = "2.5.13.7"
	MROIDNumericString     = "2.5.13.8"
	MROIDNumericOrder      = "2.5.13.9"
	MROIDNumericSubstr     = "2.5.13.10"
	MROIDCaseIgnoreList    = "2.5.13.11"
	MROIDBoolean           = "2.5.13.13"
	MROIDInteger           = "2.5.13.14"
	MROIDIntegerOrder      = "2.5.13.15"
	MROIDBitString         = "2.5.13.16"
	MROIDOctetString       = "2.5.13.17"
	MROIDOctetStringOrder  = "2.5.13.18"
	MROIDTelephoneNumber   = "2.5.13.20"
	MROIDTelephoneSubstr   = "2.5.13.21"
	MROIDUniqueMember      = "2.5.13.23"
	MROIDGeneralizedTime   = "2.5.13.27"
	MROIDGeneralizedOrder  = "2.5.13.28"
	MROIDCaseExactIA5      = "1.3.6.1.4.1.1466.109.114.1"
	MROIDCaseIgnoreIA5     = "1.3.6.1.4.1.1466.109.114.2"
)

// builtinRules is the matching rules Olivine implements.
//
// A subset of schema_init.c's table: the rules the core schema
// actually assigns, plus the IA5 pair that cosine.schema needs.
// A rule absent from here resolves to nil and comparison falls
// back to an octet comparison, which is what slapd does for a
// rule with no normalizer.
func builtinRules() []*MatchingRule {
	out := caseRules()
	out = append(out, ia5Rules()...)
	out = append(out, stringRules()...)
	return append(out, numberRules()...)
}

// caseRules are the DirectoryString families.
func caseRules() []*MatchingRule {
	ignore := normaliseUTF8(true)
	exact := normaliseUTF8(false)
	return []*MatchingRule{
		{OID: MROIDCaseIgnore, Names: []string{
			"caseIgnoreMatch"},
			SyntaxOID: SyntaxDirectoryString,
			Kinds:     KindEquality, norm: ignore},
		{OID: MROIDCaseIgnoreOrder, Names: []string{
			"caseIgnoreOrderingMatch"},
			SyntaxOID: SyntaxDirectoryString,
			Kinds:     KindOrdering, norm: ignore},
		{OID: MROIDCaseIgnoreSubstr, Names: []string{
			"caseIgnoreSubstringsMatch"},
			SyntaxOID: SyntaxDirectoryString,
			Kinds:     KindSubstrings, norm: ignore},
		{OID: MROIDCaseExact, Names: []string{
			"caseExactMatch"},
			SyntaxOID: SyntaxDirectoryString,
			Kinds:     KindEquality, norm: exact},
		{OID: MROIDCaseExactOrder, Names: []string{
			"caseExactOrderingMatch"},
			SyntaxOID: SyntaxDirectoryString,
			Kinds:     KindOrdering, norm: exact},
		{OID: MROIDCaseExactSubstr, Names: []string{
			"caseExactSubstringsMatch"},
			SyntaxOID: SyntaxDirectoryString,
			Kinds:     KindSubstrings, norm: exact},
	}
}

// ia5Rules are the IA5String families, which cosine.schema
// needs. They share UTF8StringNormalize with the DirectoryString
// rules; only the syntax differs.
func ia5Rules() []*MatchingRule {
	ignore := normaliseUTF8(true)
	exact := normaliseUTF8(false)
	return []*MatchingRule{
		{OID: MROIDCaseIgnoreIA5, Names: []string{
			"caseIgnoreIA5Match"},
			SyntaxOID: SyntaxIA5String,
			Kinds:     KindEquality, norm: ignore},
		{OID: MROIDCaseExactIA5, Names: []string{
			"caseExactIA5Match"},
			SyntaxOID: SyntaxIA5String,
			Kinds:     KindEquality, norm: exact},
		{OID: MROIDCaseIgnoreList, Names: []string{
			"caseIgnoreListMatch"},
			SyntaxOID: SyntaxDirectoryString,
			Kinds:     KindEquality, norm: ignore},
	}
}
