package ldap

import "github.com/FatmanUK/olivine_ldap/internal/ber"

// Filter tags, from include/ldap.h:571-591.
const (
	FilterAnd        ber.Tag = 0xa0
	FilterOr         ber.Tag = 0xa1
	FilterNot        ber.Tag = 0xa2
	FilterEquality   ber.Tag = 0xa3
	FilterSubstrings ber.Tag = 0xa4
	FilterGE         ber.Tag = 0xa5
	FilterLE         ber.Tag = 0xa6
	FilterPresent    ber.Tag = 0x87
	FilterApprox     ber.Tag = 0xa8
	FilterExtensible ber.Tag = 0xa9

	SubstringInitial ber.Tag = 0x80
	SubstringAny     ber.Tag = 0x81
	SubstringFinal   ber.Tag = 0x82
)

// Filter is a parsed search filter, RFC 4511 4.5.1.7.
//
// One struct rather than an interface hierarchy: a filter is
// decoded straight off the wire and walked once, and the tag
// already says which fields are meaningful.
type Filter struct {
	Tag ber.Tag
	// Sub holds the operands of and, or and not.
	Sub []Filter
	// Attribute is the attribute description, for everything
	// except and/or/not.
	Attribute string
	// Value is the assertion value for equality, >=, <= and
	// approx.
	Value string
	// Substrings is set for a substrings filter.
	Substrings Substrings
}

// Substrings is a substrings filter's three parts.
//
// Initial and Final appear at most once each; Any may repeat.
// RFC 4511 4.5.1.7.2.
type Substrings struct {
	Initial string
	Any     []string
	Final   string
}

// ParseFilter decodes one filter from its BER contents.
func ParseFilter(tag ber.Tag, content []byte) (
	Filter, error,
) {
	f := Filter{Tag: tag}
	switch tag {
	case FilterAnd, FilterOr, FilterNot:
		sub, err := parseFilterList(content)
		f.Sub = sub
		return f, err
	case FilterPresent:
		// Present is primitive: the contents *are* the
		// attribute description.
		f.Attribute = string(content)
		return f, nil
	case FilterEquality, FilterGE, FilterLE, FilterApprox:
		return parseAVAFilter(f, content)
	case FilterSubstrings:
		return parseSubstringsFilter(f, content)
	}
	return f, ErrBadFilter
}

// parseFilterList decodes the operands of and, or or not.
func parseFilterList(content []byte) ([]Filter, error) {
	var out []Filter
	d := ber.NewDecoder(content)
	for !d.Done() {
		tag, sub, err := d.Next()
		if err != nil {
			return nil, ErrBadFilter
		}
		f, err := ParseFilter(tag, sub)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// parseAVAFilter decodes an AttributeValueAssertion.
func parseAVAFilter(
	f Filter, content []byte,
) (Filter, error) {
	d := ber.NewDecoder(content)
	_, attr, err := d.Next()
	if err != nil {
		return f, ErrBadFilter
	}
	_, value, err := d.Next()
	if err != nil {
		return f, ErrBadFilter
	}
	f.Attribute, f.Value = string(attr), string(value)
	return f, nil
}
