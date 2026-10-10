package ldap

import (
	"errors"

	"github.com/FatmanUK/olivine_ldap/internal/ber"
)

// ErrBadFilter reports a filter that will not decode.
var ErrBadFilter = errors.New("ldap: malformed filter")

// parseSubstringsFilter decodes a SubstringFilter.
//
//	SubstringFilter ::= SEQUENCE {
//	type       AttributeDescription,
//	substrings SEQUENCE OF substring CHOICE {
//			initial [0] AssertionValue,
//			any     [1] AssertionValue,
//			final   [2] AssertionValue } }
func parseSubstringsFilter(
	f Filter, content []byte,
) (Filter, error) {
	d := ber.NewDecoder(content)
	_, attr, err := d.Next()
	if err != nil {
		return f, ErrBadFilter
	}
	f.Attribute = string(attr)

	_, list, err := d.Next()
	if err != nil {
		return f, ErrBadFilter
	}
	subs, err := parseSubstringList(list)
	if err != nil {
		return f, err
	}
	f.Substrings = subs
	return f, nil
}

// parseSubstringList reads the three kinds of substring.
func parseSubstringList(list []byte) (Substrings, error) {
	var s Substrings
	d := ber.NewDecoder(list)
	for !d.Done() {
		tag, part, err := d.Next()
		if err != nil {
			return s, ErrBadFilter
		}
		switch tag {
		case SubstringInitial:
			s.Initial = string(part)
		case SubstringAny:
			s.Any = append(s.Any, string(part))
		case SubstringFinal:
			s.Final = string(part)
		default:
			return s, ErrBadFilter
		}
	}
	return s, nil
}
