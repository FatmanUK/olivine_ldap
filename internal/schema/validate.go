package schema

import (
	"errors"
	"strings"
)

// ErrInvalidSyntax reports a value its syntax rejects.
var ErrInvalidSyntax = errors.New("schema: invalid syntax")

// Syntax OIDs that have a validator, from schema_init.c's
// syntax table.
const (
	SyntaxDirectoryString = "1.3.6.1.4.1.1466.115.121.1.15"
	SyntaxIA5String       = "1.3.6.1.4.1.1466.115.121.1.26"
	SyntaxInteger         = "1.3.6.1.4.1.1466.115.121.1.27"
	SyntaxBoolean         = "1.3.6.1.4.1.1466.115.121.1.7"
	SyntaxNumericString   = "1.3.6.1.4.1.1466.115.121.1.36"
	SyntaxPrintableString = "1.3.6.1.4.1.1466.115.121.1.44"
	SyntaxOID             = "1.3.6.1.4.1.1466.115.121.1.38"
	SyntaxDN              = "1.3.6.1.4.1.1466.115.121.1.12"
)

// validators maps a syntax OID to its check. A syntax with no
// entry accepts anything, which is what a NULL validator does.
var validators = map[string]func(string) error{
	SyntaxInteger:         validateInteger,
	SyntaxBoolean:         validateBoolean,
	SyntaxNumericString:   validateNumericString,
	SyntaxPrintableString: validatePrintableString,
	SyntaxDirectoryString: validateDirectoryString,
	SyntaxIA5String:       validateIA5String,
	SyntaxOID:             validateOIDSyntax,
}

// validateInteger is integerValidate from
// schema_init.c:2507-2541.
//
// It is the validator, not a normalizer, that makes integers
// canonical: non-canonical spellings are refused rather than
// rewritten, which is why integerMatch can compare by length.
func validateInteger(v string) error {
	if v == "" {
		return ErrInvalidSyntax
	}
	body := v
	if strings.HasPrefix(body, "-") {
		body = body[1:]
		// A bare "-" and "-0" are both invalid.
		if body == "" || body[0] == '0' {
			return ErrInvalidSyntax
		}
	} else if body[0] == '0' && len(body) > 1 {
		// "0" alone is fine; "0" with anything after it is
		// a leading zero.
		return ErrInvalidSyntax
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return ErrInvalidSyntax
		}
	}
	return nil
}

// validateBoolean accepts only TRUE and FALSE, upper case.
func validateBoolean(v string) error {
	if v != "TRUE" && v != "FALSE" {
		return ErrInvalidSyntax
	}
	return nil
}

// validateNumericString accepts digits and spaces, non-empty.
func validateNumericString(v string) error {
	if v == "" {
		return ErrInvalidSyntax
	}
	for i := 0; i < len(v); i++ {
		if v[i] == ' ' {
			continue
		}
		if v[i] < '0' || v[i] > '9' {
			return ErrInvalidSyntax
		}
	}
	return nil
}

// validateDirectoryString rejects only the empty string: a
// DirectoryString is UTF-8 and must have at least one character.
func validateDirectoryString(v string) error {
	if v == "" {
		return ErrInvalidSyntax
	}
	return nil
}

// validateIA5String rejects non-ASCII.
func validateIA5String(v string) error {
	for i := 0; i < len(v); i++ {
		if v[i] > 0x7f {
			return ErrInvalidSyntax
		}
	}
	return nil
}

// printableExtra are the non-alphanumeric characters a
// PrintableString permits, from X.520.
const printableExtra = "'()+,-.=/:? "

// validatePrintableString accepts the restricted X.520 set.
func validatePrintableString(v string) error {
	if v == "" {
		return ErrInvalidSyntax
	}
	for _, r := range v {
		if isAlphaRune(r) || isDigitRune(r) {
			continue
		}
		if strings.ContainsRune(printableExtra, r) {
			continue
		}
		return ErrInvalidSyntax
	}
	return nil
}

// validateOIDSyntax accepts a numeric OID or a descriptor,
// which is what the OID syntax allows: slapd resolves names as
// well as dotted numbers.
func validateOIDSyntax(v string) error {
	if v == "" {
		return ErrInvalidSyntax
	}
	if isDigitRune(rune(v[0])) {
		return validateNumericOID(v)
	}
	return validateDescriptor(v)
}

// validateNumericOID accepts dotted decimal with no empty arc.
func validateNumericOID(v string) error {
	arc := 0
	for i := 0; i < len(v); i++ {
		switch {
		case v[i] >= '0' && v[i] <= '9':
			arc++
		case v[i] == '.':
			if arc == 0 {
				return ErrInvalidSyntax
			}
			arc = 0
		default:
			return ErrInvalidSyntax
		}
	}
	if arc == 0 {
		return ErrInvalidSyntax
	}
	return nil
}

// validateDescriptor accepts a keystring: a letter followed by
// letters, digits or hyphens.
func validateDescriptor(v string) error {
	if !isAlphaRune(rune(v[0])) {
		return ErrInvalidSyntax
	}
	for _, r := range v[1:] {
		if isAlphaRune(r) || isDigitRune(r) || r == '-' {
			continue
		}
		return ErrInvalidSyntax
	}
	return nil
}

// isAlphaRune reports whether r is an ASCII letter.
func isAlphaRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// isDigitRune reports whether r is an ASCII digit.
func isDigitRune(r rune) bool {
	return r >= '0' && r <= '9'
}
