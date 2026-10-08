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

// attr is one attribute for addBody.
type attr struct {
	Type   string
	Values []string
}

// addBody encodes an AddRequest body.
func addBody(dn string, attrs []attr) []byte {
	e := ber.NewEncoder()
	e.String(ldap.TagLDAPDN, dn)
	e.Begin(ber.TagSequence)
	for _, a := range attrs {
		e.Begin(ber.TagSequence)
		e.String(ber.TagOctetString, a.Type)
		e.Begin(ber.TagSet)
		for _, v := range a.Values {
			e.String(ber.TagOctetString, v)
		}
		e.End()
		e.End()
	}
	e.End()
	out, err := e.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

// avaFilter writes a filter carrying an
// AttributeValueAssertion, which is the shape of equality, >=,
// <= and approx.
func avaFilter(
	tag ber.Tag, attr, value string,
) func(*ber.Encoder) {
	return func(e *ber.Encoder) {
		e.Begin(tag)
		e.String(ber.TagOctetString, attr)
		e.String(ber.TagOctetString, value)
		e.End()
	}
}

// substringFilter writes a substrings filter. Empty initial or
// final parts are omitted, as RFC 4511 4.5.1.7.2 expects.
func substringFilter(
	attr, initial string, any []string, final string,
) func(*ber.Encoder) {
	return func(e *ber.Encoder) {
		e.Begin(ldap.FilterSubstrings)
		e.String(ber.TagOctetString, attr)
		e.Begin(ber.TagSequence)
		if initial != "" {
			e.String(ldap.SubstringInitial, initial)
		}
		for _, a := range any {
			e.String(ldap.SubstringAny, a)
		}
		if final != "" {
			e.String(ldap.SubstringFinal, final)
		}
		e.End()
		e.End()
	}
}
