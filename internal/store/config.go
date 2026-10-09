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

// cn=config is writable, and backed by Postgres.
//
// It began as a read-only projection of the environment, on the
// reasoning that the 12-factor departure made the environment the
// single authority. That was wrong, and the mistake is worth
// recording: 12-factor calls config what *varies between
// deploys*, and the suffixes, the limits and the access policy do
// not vary between replicas — they are identical across all of
// them, which makes them shared state rather than per-process
// configuration. Keeping them in the environment meant changing
// one was a redeploy of every replica in lockstep, which is the
// opposite of the high availability the departure was for.
//
// So the mutable settings live in the config_settings table,
// which every replica reads and any may write; the environment
// supplies defaults for a database that has none yet. What stays
// environmental is whatever is needed before the database can be
// reached at all — the DSN, the TLS material, the listen address.
// See Setting and Config.
//
// Entries cannot be added or removed: there is one database, so
// the tree has a fixed shape and only its values change.
//
// It is readable and writable only by the administrator. The
// settings name the suffixes, the root DN and the limits; none of
// that belongs to an anonymous caller, and slapd likewise protects
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

// refuseConfigWrite is the answer to adding or deleting a
// configuration entry.
//
// The shape of the tree is fixed — one global entry and one
// database — so there is no entry to create and none that may go
// away. Only the values of the two that exist can change, which
// is a modify.
func refuseConfigWrite() ldap.Result {
	return ldap.Result{
		Code: ldap.UnwillingToPerform,
		Diagnostic: "cn=config holds one database; " +
			"entries cannot be added or removed",
	}
}

// configBase resolves a search base inside the configuration tree.
//
// The DN is lower-cased rather than normalised through the schema:
// olcDatabase is defined in slapd's own olc* schema, which Olivine
// does not carry, so dn.Normalise would call it an unknown
// attribute type. Lower-casing is enough for a tree whose DNs this
// server generates itself.
// A known entry resolves to the spelling the projection uses,
// not to the lower-cased form: olcDatabase={1}postgres is mixed
// case, and comparing a lower-cased base against the entry's own
// DN would miss it — which it did, so a base-scope search of the
// database entry found nothing.
func (s *Store) configBase(raw string) (string, bool) {
	norm := strings.ToLower(strings.TrimSpace(raw))
	norm = strings.ReplaceAll(norm, ", ", ",")
	for _, known := range []string{ConfigDN, databaseDN} {
		if norm == strings.ToLower(known) {
			return known, true
		}
	}
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
