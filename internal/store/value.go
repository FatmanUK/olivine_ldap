package store

import (
	"strings"

	"github.com/FatmanUK/olivine_ldap/internal/schema"
)

// NormaliseValue reduces a value to the form its equality
// matching rule compares.
//
// Delegates to internal/schema, which replaced the hand-written
// list of case-insensitive rule names this file used to carry.
// That list was wrong about telephoneNumberMatch, which strips
// spaces and hyphens rather than folding case, and it could not
// express the surprising part of UTF8StringNormalize at all: a
// value of nothing but spaces normalises to a *single space*, not
// to empty.
func NormaliseValue(
	r *schema.Registry, at *schema.AttributeType,
	value string,
) string {
	return r.NormaliseValue(at, value, schema.UseValue)
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
