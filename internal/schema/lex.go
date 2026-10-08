package schema

import (
	"errors"
	"strings"
)

// Token kinds in a schema description.
type kind int

const (
	tokEOF kind = iota
	tokLParen
	tokRParen
	tokDollar
	// tokQString is a 'quoted' string.
	tokQString
	// tokBare is an OID, a descriptor or a keyword.
	tokBare
)

// token is one lexed element.
type token struct {
	kind kind
	text string
}

var (
	ErrUnterminated = errors.New(
		"schema: unterminated quoted string")
	ErrSyntax = errors.New("schema: malformed description")
	ErrNoOID  = errors.New("schema: missing OID")
	ErrDup    = errors.New("schema: duplicate definition")
)

// lex splits a schema description into tokens.
//
// The grammar is RFC 4512 4.1, but the .schema files in the
// submodule are what this must actually read, and OpenLDAP's
// parser is more forgiving than the ABNF: it accepts a
// descriptor where the ABNF demands a numericoid, which is how
// the olc* configuration attributes are written.
func lex(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' ||
			c == '\r':
			i++
		case c == '(':
			out = append(out, token{tokLParen, "("})
			i++
		case c == ')':
			out = append(out, token{tokRParen, ")"})
			i++
		case c == '$':
			out = append(out, token{tokDollar, "$"})
			i++
		case c == '\'':
			t, n, err := lexQuoted(s[i:])
			if err != nil {
				return nil, err
			}
			out = append(out, t)
			i += n
		default:
			t, n := lexBare(s[i:])
			out = append(out, t)
			i += n
		}
	}
	return append(out, token{tokEOF, ""}), nil
}

// lexQuoted reads a 'quoted' string, returning the token and
// how many bytes it consumed.
func lexQuoted(s string) (token, int, error) {
	end := strings.IndexByte(s[1:], '\'')
	if end < 0 {
		return token{}, 0, ErrUnterminated
	}
	return token{tokQString, s[1 : 1+end]}, end + 2, nil
}

// lexBare reads an unquoted run: an OID, descriptor or
// keyword. A trailing {len} stays attached, because
// SYNTAX 1.3.6...15{32768} is written without a space and the
// length belongs to the syntax.
func lexBare(s string) (token, int) {
	n := 0
	for n < len(s) && !isDelim(s[n]) {
		n++
	}
	return token{tokBare, s[:n]}, n
}

// isDelim reports whether c ends a bare token.
func isDelim(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '(', ')', '$', '\'':
		return true
	}
	return false
}
