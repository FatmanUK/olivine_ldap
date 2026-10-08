package store

import (
	"strings"

	"github.com/FatmanUK/openldap_olivine/internal/schema"
)

// caseInsensitiveRules are the equality matching rules under
// which a value is case-folded.
//
// The same list internal/dn uses, and for the same reason: the
// normalised form is what equality comparison sees, so a value
// stored unfolded under caseIgnoreMatch would never match a
// correctly-spelled filter. It lives here rather than being
// shared because the full set arrives with the matching rules
// at plan step 6's second half, and will then replace both.
var caseInsensitiveRules = map[string]bool{
	"caseIgnoreMatch":        true,
	"caseIgnoreIA5Match":     true,
	"caseIgnoreListMatch":    true,
	"telephoneNumberMatch":   true,
	"distinguishedNameMatch": true,
	"objectIdentifierMatch":  true,
}

// NormaliseValue reduces a value to the form its equality
// matching rule compares.
//
// The matching rule may be inherited: cn declares no EQUALITY
// of its own and takes caseIgnoreMatch from name, so the SUP
// chain has to be walked. Reading only the attribute's own rule
// leaves cn case-sensitive, which internal/dn found the hard
// way against slapdn.
func NormaliseValue(
	r *schema.Registry, at *schema.AttributeType,
	value string,
) string {
	if caseInsensitiveRules[equalityRule(r, at)] {
		value = strings.ToLower(value)
	}
	// RFC 4518 insignificant space handling.
	return strings.Join(strings.Fields(value), " ")
}

// equalityRule resolves an attribute's equality matching rule,
// following SUP when the type states none itself.
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

// canonicalType resolves an attribute name or OID to the
// canonical, lower-cased name used as a column value.
func (s *Store) canonicalType(name string) (string, error) {
	at, ok := s.schema.AttributeType(name)
	if !ok {
		return "", &UnknownAttributeError{Type: name}
	}
	return strings.ToLower(canonicalName(at)), nil
}
