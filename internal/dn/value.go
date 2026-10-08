package dn

import (
	"strings"

	"github.com/FatmanUK/openldap_olivine/internal/schema"
)

// caseInsensitiveRules are the equality matching rules under
// which a value is case-folded for normalisation.
//
// Taken from the rules the core schema actually assigns to the
// attribute types that appear in DNs; schema_init.c defines
// many more, and this grows with internal/schema's matching
// rules (plan step 6's second half).
var caseInsensitiveRules = map[string]bool{
	"caseIgnoreMatch":        true,
	"caseIgnoreIA5Match":     true,
	"caseIgnoreListMatch":    true,
	"telephoneNumberMatch":   true,
	"distinguishedNameMatch": true,
	"objectIdentifierMatch":  true,
}

// normaliseValue applies the attribute's equality matching rule
// to a value.
//
// Two transformations, both observed through slapdn:
//
// Case folding, where the rule is case-insensitive. It is full
// Unicode folding, not ASCII: cn=Ω normalises to cn=ω.
//
// Insignificant space handling, RFC 4518: runs of spaces
// collapse to one and surrounding space is dropped, so
// cn=a  b becomes cn=a b. Pretty form does neither, which is
// why cn=a  b stays cn=a  b there and cn=trail\  keeps its
// escaped space as \20.
func normaliseValue(
	r *schema.Registry, at *schema.AttributeType,
	value string,
) string {
	if caseInsensitiveRules[equalityRule(r, at)] {
		// Full Unicode folding, not ASCII: slapd
		// normalises cn=Ω to cn=ω.
		value = strings.ToLower(value)
	}
	return collapseSpaces(value)
}

// equalityRule resolves an attribute's equality matching rule,
// following SUP when the type does not state one itself.
//
// This is not a detail. core.schema defines cn as
//
//	attributetype ( 2.5.4.3 NAME ( 'cn' 'commonName' )
//		SUP name )
//
// with no EQUALITY of its own; caseIgnoreMatch comes from
// `name`. Reading only the type's own EQUALITY leaves cn
// case-*sensitive*, so CN=Foo Bar normalises to cn=Foo Bar and
// never matches cn=foo bar. The golden corpus caught it.
//
// The depth limit guards against a schema whose SUP chain
// loops; slapd checks for that at load time, which Olivine does
// not do yet.
func equalityRule(
	r *schema.Registry, at *schema.AttributeType,
) string {
	for depth := 0; depth < 16; depth++ {
		if at.EqualityOID != "" {
			return at.EqualityOID
		}
		if at.SuperiorOID == "" {
			return ""
		}
		sup, ok := r.AttributeType(at.SuperiorOID)
		if !ok {
			return ""
		}
		at = sup
	}
	return ""
}

// collapseSpaces reduces runs of spaces to one and trims.
func collapseSpaces(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}
