package dn

import "strings"

// needsEscape lists the characters slapd escapes anywhere in a
// value.
//
// '=' is in the list because slapd escapes it — cn=a\=b
// normalises to cn=a\3Db — even though RFC 4514 2.4 does not
// require escaping '=' outside the first position.
const needsEscape = `"+,;<>\=`

// escape renders a value with the escaping slapd emits.
//
// slapd always writes \XX in upper-case hex, never the \c
// short form: cn=a\,b normalises to cn=a\2Cb, and an input of
// \2c comes back as \2C. Observed through slapdn.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case strings.IndexByte(needsEscape, c) >= 0:
			writeHex(&b, c)
		case c == '#' && i == 0:
			// Only leading, since # elsewhere is literal.
			writeHex(&b, c)
		case c < 0x20:
			// Control bytes always, wherever they sit. A
			// fuzzer found that an escaped tab otherwise
			// came back as a bare tab, which parsing then
			// trimmed away as insignificant whitespace.
			writeHex(&b, c)
		case c == ' ' && (i == 0 || i == len(s)-1):
			// A leading or trailing space is significant
			// only if it survived parsing, which means it
			// was escaped. cn=trail\ prettifies to
			// cn=trail\20.
			writeHex(&b, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// writeHex writes one \XX escape.
func writeHex(b *strings.Builder, c byte) {
	const hex = "0123456789ABCDEF"
	b.WriteByte('\\')
	b.WriteByte(hex[c>>4])
	b.WriteByte(hex[c&0x0f])
}

// unhex decodes one hex digit.
func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
