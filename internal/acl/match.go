package acl

import "strings"

// matchDN reports whether dn falls within pattern at style.
//
// The DNs are already normalised, so this is textual. The
// separator in the subtree and children cases is load-bearing:
// without it, dc=example,dc=com would also match
// dc=examplecorp,dc=com — the same trap the store's reversed-DN
// prefix test has.
func matchDN(pattern string, style Style, dn string) bool {
	switch style {
	case StyleBase:
		return dn == pattern
	case StyleOne:
		return parentOf(dn) == pattern
	case StyleSubtree:
		return dn == pattern || under(pattern, dn)
	case StyleChildren:
		return under(pattern, dn)
	}
	return false
}

// under reports whether dn is strictly beneath pattern.
func under(pattern, dn string) bool {
	return strings.HasSuffix(dn, ","+pattern)
}

// parentOf returns a normalised DN's parent, empty at the top.
func parentOf(dn string) string {
	_, rest, found := strings.Cut(dn, ",")
	if !found {
		return ""
	}
	return rest
}
