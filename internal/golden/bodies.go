package golden

import (
	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// searchBody encodes a SearchRequest body.
func searchBody(
	base string, scope ldap.Scope,
	filter func(*ber.Encoder), attrs []string,
) []byte {
	e := ber.NewEncoder()
	e.String(ldap.TagLDAPDN, base)
	e.Enum(ber.TagEnumerated, int32(scope))
	// neverDerefAliases: aliases are not implemented on either
	// side of this comparison.
	e.Enum(ber.TagEnumerated, 0)
	e.Int32(ber.TagInteger, 0)
	e.Int32(ber.TagInteger, 0)
	e.Bool(ber.TagBoolean, false)
	filter(e)
	e.Begin(ber.TagSequence)
	for _, a := range attrs {
		e.String(ber.TagOctetString, a)
	}
	e.End()
	out, err := e.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

// presentFilter writes an (attr=*) filter.
func presentFilter(attr string) func(*ber.Encoder) {
	return func(e *ber.Encoder) {
		e.String(ldap.FilterPresent, attr)
	}
}

// equalityFilter writes an (attr=value) filter.
func equalityFilter(
	attr, value string,
) func(*ber.Encoder) {
	return func(e *ber.Encoder) {
		e.Begin(ldap.FilterEquality)
		e.String(ber.TagOctetString, attr)
		e.String(ber.TagOctetString, value)
		e.End()
	}
}

// compareBody encodes a CompareRequest body.
func compareBody(dn, attr, value string) []byte {
	e := ber.NewEncoder()
	e.String(ldap.TagLDAPDN, dn)
	e.Begin(ber.TagSequence)
	e.String(ber.TagOctetString, attr)
	e.String(ber.TagOctetString, value)
	e.End()
	out, err := e.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}
