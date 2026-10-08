package dn

import "strings"

// Parse splits a DN into RDNs and AVAs, unescaping values.
//
// It does not consult the schema, so it accepts attribute types
// that no schema defines; Normalise and Pretty reject those.
//
// ';' is accepted as an RDN separator and treated as ','. That
// is RFC 1779 legacy that slapd still honours: cn=a;dc=x
// normalises to cn=a,dc=x.
func Parse(s string) (DN, error) {
	if strings.TrimSpace(s) == "" {
		return nil, ErrEmpty
	}
	var out DN
	for _, rdnText := range splitUnescaped(s, ",;") {
		rdn, err := parseRDN(rdnText)
		if err != nil {
			return nil, err
		}
		out = append(out, rdn)
	}
	return out, nil
}

// parseRDN parses one RDN, which may hold several AVAs.
func parseRDN(s string) (RDN, error) {
	parts := splitUnescaped(s, "+")
	rdn := make(RDN, 0, len(parts))
	for _, part := range parts {
		ava, err := parseAVA(part)
		if err != nil {
			return nil, err
		}
		rdn = append(rdn, ava)
	}
	return rdn, nil
}

// parseAVA parses one type=value pair.
func parseAVA(s string) (AVA, error) {
	eqs := splitUnescaped(s, "=")
	if len(eqs) != 2 {
		return AVA{}, ErrSyntax
	}
	typ := strings.TrimSpace(eqs[0])
	if !validType(typ) {
		return AVA{}, ErrSyntax
	}
	// Surrounding space that was not escaped is not part of
	// the value: "CN=  spaced  " is "spaced". An *escaped*
	// trailing space is part of it, though: cn=trail\
	// prettifies to cn=trail\20, so trimming blindly here
	// leaves a dangling backslash and a bogus syntax error.
	raw := trimUnescaped(eqs[1])
	if raw == "" {
		return AVA{}, ErrEmptyValue
	}
	// slapd rejects the #hexstring form, even when the hex
	// decodes to well-formed BER: #0403616263 is a valid
	// OCTET STRING and slapdn still refuses it.
	if raw[0] == '#' {
		return AVA{}, ErrBinaryValue
	}
	value, err := unescape(raw)
	if err != nil {
		return AVA{}, err
	}
	return AVA{Type: typ, Value: value}, nil
}

// unescape resolves \XX and \c escapes.
func unescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", ErrSyntax
		}
		hi, ok := unhex(s[i+1])
		if !ok || i+2 >= len(s) {
			// \c form: the next byte, literally.
			b.WriteByte(s[i+1])
			i++
			continue
		}
		lo, ok := unhex(s[i+2])
		if !ok {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}
