package dn

import "strings"

// splitUnescaped splits s at any unescaped byte in seps.
//
// A separator preceded by a backslash belongs to the value, so
// a naive strings.Split would break cn=a\,b into two RDNs.
func splitUnescaped(s, seps string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			// Skip the escaped byte, whatever it is.
			i++
			continue
		}
		if strings.IndexByte(seps, s[i]) >= 0 {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// trimUnescaped removes surrounding whitespace that is not
// escaped.
//
// A trailing space preceded by an odd number of backslashes was
// escaped and belongs to the value.
func trimUnescaped(s string) string {
	s = strings.TrimLeft(s, " \t")
	for len(s) > 0 {
		last := s[len(s)-1]
		if last != ' ' && last != '\t' {
			break
		}
		if isEscaped(s, len(s)-1) {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

// isEscaped reports whether the byte at i is preceded by an odd
// number of backslashes.
func isEscaped(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}
