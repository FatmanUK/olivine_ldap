package store

import (
	"sort"

	"github.com/FatmanUK/openldap_olivine/internal/acl"
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
	e *Entry, req *ldap.SearchRequest, who Identity,
) ldap.SearchEntry {
	out := ldap.SearchEntry{DN: e.PrettyDN}
	if onlyNoAttributes(req.Attributes) {
		return out
	}
	wanted := s.wantedTypes(req.Attributes)
	byType := map[string][]string{}
	var order []string
	for _, v := range e.Values {
		if !s.wantedAttribute(req, wanted, v.Type) {
			continue
		}
		// Per attribute, because selection is per attribute:
		// one clause can hide description while a later one
		// grants the rest.
		if s.accessTo(who, e.DN, v.Type) < acl.Read {
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

// wantedAttribute reports whether one stored attribute belongs
// in the reply.
//
// An explicit list selects exactly what it names. Otherwise the
// split is by usage: a plain search or "*" returns user
// attributes, and "+" returns operational ones — and only those.
// slapd's "+" output carries no objectClass line, which is the
// observable consequence.
func (s *Store) wantedAttribute(
	req *ldap.SearchRequest, wanted map[string]bool,
	typ string,
) bool {
	if wanted != nil {
		return wanted[typ]
	}
	at, ok := s.schema.AttributeType(typ)
	if !ok {
		return false
	}
	if isOperational(at) {
		return wantsOperational(req.Attributes)
	}
	return wantsUser(req.Attributes)
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
			// A wildcard is present, so selection falls
			// to the usage split in wantedAttribute,
			// not to an explicit set.
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
