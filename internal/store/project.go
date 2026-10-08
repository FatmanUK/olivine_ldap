package store

import (
	"sort"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// project turns a stored entry into the entry to send back,
// honouring the requested attribute list.
//
// RFC 4511 4.5.1.8 gives the list three special spellings:
// empty means all user attributes, "*" means the same
// explicitly, and "1.1" — which is not a real OID — means none
// at all. "+" for operational attributes is RFC 3673.
func (s *Store) project(
	e *Entry, req *ldap.SearchRequest,
) ldap.SearchEntry {
	out := ldap.SearchEntry{DN: e.PrettyDN}
	if onlyNoAttributes(req.Attributes) {
		return out
	}
	wanted := s.wantedTypes(req.Attributes)
	byType := map[string][]string{}
	var order []string
	for _, v := range e.Values {
		if wanted != nil && !wanted[v.Type] {
			continue
		}
		if _, seen := byType[v.Type]; !seen {
			order = append(order, v.Type)
		}
		if req.TypesOnly {
			byType[v.Type] = nil
			continue
		}
		byType[v.Type] = append(byType[v.Type], v.Value)
	}
	sort.Strings(order)
	for _, t := range order {
		out.Attributes = append(out.Attributes,
			ldap.AttributeChange{
				Type:   s.declaredName(t),
				Values: byType[t],
			})
	}
	return out
}

// declaredName returns an attribute type in the capitalisation
// the schema declares.
//
// The stored type is lower-cased, which is right for matching and
// indexing but wrong on the wire: slapd returns the declared
// spelling, so an entry comes back carrying `objectClass` and not
// `objectclass`. The golden harness caught this — every search
// script differed by exactly that one capital letter.
func (s *Store) declaredName(stored string) string {
	at, ok := s.schema.AttributeType(stored)
	if !ok {
		return stored
	}
	return canonicalName(at)
}

// onlyNoAttributes reports whether the list is exactly the
// "no attributes" marker.
func onlyNoAttributes(attrs []string) bool {
	return len(attrs) == 1 && attrs[0] == ldap.NoAttributes
}

// wantedTypes resolves the requested list to stored type names,
// or nil when everything is wanted.
func (s *Store) wantedTypes(
	attrs []string,
) map[string]bool {
	if len(attrs) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, a := range attrs {
		switch a {
		case ldap.AllUserAttributes,
			ldap.AllOperationalAttributes:
			// Operational attributes are not stored
			// apart yet, so "+" selects nothing extra
			// rather than pretend otherwise.
			return nil
		case ldap.NoAttributes:
			continue
		}
		if t, ok := canonical(s.schema, a); ok {
			out[t] = true
		}
	}
	return out
}
