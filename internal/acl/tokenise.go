package acl

import "fmt"

// tokenise splits a directive on whitespace, keeping quoted
// strings together.
//
// DNs in access directives are routinely quoted, because they
// contain commas and spaces: `by dn="cn=a b,dc=x" read`.
func tokenise(s string) ([]string, error) {
	var out []string
	var cur []byte
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			cur = append(cur, c)
		case !inQuote && (c == ' ' || c == '\t'):
			if len(cur) > 0 {
				out = append(out, string(cur))
				cur = nil
			}
		default:
			cur = append(cur, c)
		}
	}
	if inQuote {
		return nil, fmt.Errorf(
			"%w: unterminated quote", ErrSyntax)
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out, nil
}
