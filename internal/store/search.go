package store

import (
	"errors"

	"gorm.io/gorm"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// Get returns one entry by DN, with its values.
func (s *Store) Get(rawDN string) (*Entry, error) {
	norm, _, err := s.normalise(rawDN)
	if err != nil {
		return nil, err
	}
	var e Entry
	err = s.db.Preload("Values").
		Where("dn = ?", norm).First(&e).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Search returns the entries within scope of base.
//
// The four scopes follow back-mdb/search.c:874-895, where the
// fall-through encodes a distinction worth stating plainly:
// SUBTREE includes the base entry, ONELEVEL and SUBORDINATE do
// not. SUBORDINATE is OpenLDAP's extension, and is SUBTREE minus
// the base.
func (s *Store) Search(
	rawBase string, scope ldap.Scope,
) ([]Entry, error) {
	if !scope.Valid() {
		return nil, errors.New("store: invalid scope")
	}
	norm, _, err := s.normalise(rawBase)
	if err != nil {
		return nil, err
	}
	var out []Entry
	q := s.scopeQuery(norm, scope)
	if err := q.Order("dn").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// scopeQuery builds the query for one scope.
func (s *Store) scopeQuery(
	norm string, scope ldap.Scope,
) *gorm.DB {
	q := s.db.Preload("Values").Model(&Entry{})
	rev := revDN(norm)
	switch scope {
	case ldap.ScopeBase:
		return q.Where("dn = ?", norm)
	case ldap.ScopeOneLevel:
		return q.Where("parent_dn = ?", norm)
	case ldap.ScopeSubtree:
		// Prefix test on the reversed DN, which an index
		// can serve. See the Entry doc comment.
		return q.Where("rev_dn = ? OR rev_dn LIKE ?",
			rev, likePrefix(rev))
	}
	// ScopeSubordinate: the subtree without its base.
	return q.Where("rev_dn LIKE ?", likePrefix(rev))
}

// likePrefix builds a LIKE pattern matching everything strictly
// beneath rev.
//
// The separator is included so that dc=com,dc=example does not
// also match dc=com,dc=examplecorp. Any LIKE metacharacter in
// the DN itself is escaped, since a DN value may legitimately
// contain % or _.
func likePrefix(rev string) string {
	return escapeLike(rev) + ",%"
}

// escapeLike neutralises LIKE metacharacters.
func escapeLike(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%', '_', '\\':
			b = append(b, '\\')
		}
		b = append(b, s[i])
	}
	return string(b)
}
