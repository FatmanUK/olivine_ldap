package dn

// validType reports whether s is a syntactically valid
// attribute type.
//
// RFC 4514 2.3: attributeType = descr / numericoid, where descr
// is a keystring — a letter followed by letters, digits or
// hyphens. Nothing else, so no backslash and no space.
//
// Checked at parse time rather than left to the schema lookup.
// A fuzzer found that `\ =0` was otherwise accepted with the
// type `\`, which DN.String() then rendered as `\=0` — a string
// that will not parse, because the backslash escapes the '='.
func validType(s string) bool {
	if s == "" {
		return false
	}
	if isDigit(s[0]) {
		return validOID(s)
	}
	return validDescr(s)
}

// validDescr checks the keystring form.
func validDescr(s string) bool {
	if !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(c) && c != '-' {
			return false
		}
	}
	return true
}

// validOID checks a dotted-decimal OID: digits in groups
// separated by single dots, no empty group.
func validOID(s string) bool {
	group := 0
	for i := 0; i < len(s); i++ {
		switch {
		case isDigit(s[i]):
			group++
		case s[i] == '.':
			if group == 0 {
				return false
			}
			group = 0
		default:
			return false
		}
	}
	return group > 0
}

// isAlpha reports whether c is an ASCII letter.
func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isDigit reports whether c is an ASCII digit.
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
