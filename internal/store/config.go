package store

import (
	"strings"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// ConfigDN is the configuration naming context, as slapd's.
const ConfigDN = "cn=config"

// databaseDN is the one database entry the projection shows.
//
// slapd numbers its databases — olcDatabase={1}mdb — because it
// can hold several. Olivine holds one, backed by Postgres, and the
// index is kept so a client walking the tree sees the shape it
// expects.
const databaseDN = "olcDatabase={1}postgres,cn=config"

// cn=config is a *read-only projection of the environment*, which
// settles the open question the plan recorded.
//
// slapd makes cn=config writable and treats it as the authority:
// an administrator reconfigures a running directory by modifying
// it. That is incompatible with the 12-factor departure, where the
// environment is the authority and the process is disposable — two
// sources of truth that can disagree is worse than one that cannot
// be edited live. So the tree is readable and every write answers
// unwillingToPerform, naming the variable to set instead.
//
// It is also readable only by the administrator. The configuration
// names the suffixes, the root DN and the limits; none of that
// belongs to an anonymous caller, and slapd likewise protects
// cn=config behind a rootdn of its own.
func (s *Store) isConfigRequest(norm string) bool {
	return norm == ConfigDN ||
		strings.HasSuffix(norm, ","+ConfigDN)
}

// searchConfig answers a search of the configuration tree.
func (s *Store) searchConfig(
	req *ldap.SearchRequest, who Identity, norm string,
) ([]ldap.SearchEntry, ldap.Result) {
	if !s.isRoot(who) {
		// Hidden rather than refused: an anonymous caller
		// learns nothing, not even that the tree is there.
		return nil, ldap.Result{Code: ldap.NoSuchObject}
	}
	entries := s.configEntries()
	out := make([]ldap.SearchEntry, 0, len(entries))
	for _, e := range entries {
		if !inConfigScope(norm, req.Scope, e.DN) {
			continue
		}
		out = append(out, projectConfig(e, req))
	}
	if len(out) == 0 {
		return nil, ldap.Result{Code: ldap.NoSuchObject}
	}
	return out, ldap.Result{Code: ldap.Success}
}

// inConfigScope reports whether a configuration entry is within
// scope of the base.
func inConfigScope(
	base string, scope ldap.Scope, dn string,
) bool {
	switch scope {
	case ldap.ScopeBase:
		return dn == base
	case ldap.ScopeOneLevel:
		return parentOf(dn) == base
	case ldap.ScopeSubtree:
		return dn == base ||
			strings.HasSuffix(dn, ","+base)
	case ldap.ScopeSubordinate:
		return strings.HasSuffix(dn, ","+base)
	}
	return false
}

// refuseConfigWrite is the answer to any attempt to change the
// configuration over LDAP.
func refuseConfigWrite() ldap.Result {
	return ldap.Result{
		Code: ldap.UnwillingToPerform,
		Diagnostic: "cn=config is read-only; " +
			"configuration comes from the environment",
	}
}

// configBase resolves a search base inside the configuration tree.
//
// The DN is lower-cased rather than normalised through the schema:
// olcDatabase is defined in slapd's own olc* schema, which Olivine
// does not carry, so dn.Normalise would call it an unknown
// attribute type. Lower-casing is enough for a tree whose DNs this
// server generates itself.
func (s *Store) configBase(raw string) (string, bool) {
	norm := strings.ToLower(strings.TrimSpace(raw))
	norm = strings.ReplaceAll(norm, ", ", ",")
	if !s.isConfigRequest(norm) {
		return "", false
	}
	return norm, true
}

// isConfigTarget reports whether a write names the configuration
// tree.
func (s *Store) isConfigTarget(raw string) bool {
	_, ok := s.configBase(raw)
	return ok
}
