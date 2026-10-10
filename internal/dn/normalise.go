package dn

import (
	"sort"
	"strings"

	"github.com/FatmanUK/olivine_ldap/internal/schema"
)

// Normalise returns the DN in the form slapd's dnNormalize
// produces: the form used as a key, so two DNs that name the
// same entry normalise identically.
//
// Needs the schema: an attribute type nothing defines is an
// error, and whether a value is case-folded depends on the
// type's equality matching rule.
func Normalise(r *schema.Registry, s string) (string, error) {
	return convert(r, s, true)
}

// Pretty returns the DN in the form dnPretty produces: the
// attribute descriptions canonicalised but the values left as
// written.
func Pretty(r *schema.Registry, s string) (string, error) {
	return convert(r, s, false)
}

// convert does the shared work of Normalise and Pretty.
func convert(
	r *schema.Registry, s string, norm bool,
) (string, error) {
	parsed, err := Parse(s)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(parsed))
	for _, rdn := range parsed {
		text, err := convertRDN(r, rdn, norm)
		if err != nil {
			return "", err
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, ","), nil
}

// convertRDN renders one RDN, sorting its AVAs.
//
// slapd sorts multi-valued RDNs: sn=b+cn=a comes back as
// cn=a+sn=b, in both normal and pretty form. Without that, two
// spellings of the same RDN would not compare equal.
func convertRDN(
	r *schema.Registry, rdn RDN, norm bool,
) (string, error) {
	parts := make([]string, 0, len(rdn))
	for _, ava := range rdn {
		text, err := convertAVA(r, ava, norm)
		if err != nil {
			return "", err
		}
		parts = append(parts, text)
	}
	sort.Strings(parts)
	return strings.Join(parts, "+"), nil
}

// convertAVA renders one type=value pair.
func convertAVA(
	r *schema.Registry, ava AVA, norm bool,
) (string, error) {
	at, ok := r.AttributeType(ava.Type)
	if !ok {
		return "", ErrUnknownAttr
	}
	// The canonical name, lower-cased. An OID-form type
	// resolves to the name: 2.5.4.3=value becomes cn=value.
	name := strings.ToLower(canonicalName(at))
	value := ava.Value
	if norm {
		value = normaliseValue(r, at, value)
	}
	return name + "=" + escape(value), nil
}

// canonicalName is an attribute type's first name, or its OID
// if it has none.
func canonicalName(at *schema.AttributeType) string {
	if len(at.Names) > 0 {
		return at.Names[0]
	}
	return at.OID
}
