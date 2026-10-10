package store

import (
	"strings"

	"gorm.io/gorm"

	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// renameTx does the rename inside a transaction.
//
// Three things change, and missing any of them leaves the
// directory inconsistent:
//
// The entry's own DN columns.
//
// The RDN attribute values. slapd replaces them: renaming
// cn=Alice to cn=Alicia leaves the entry carrying `cn: Alicia`,
// not `cn: Alice`. Changing only the DN leaves an entry whose cn
// does not match its own name, and a search for the new name
// finds nothing.
//
// Every descendant. back-mdb renames a whole subtree — verified
// against the oracle, which renamed ou=people with children under
// it and answered success. An earlier version of this refused with
// notAllowedOnNonLeaf on the strength of an assumption.
func (s *Store) renameTx(
	tx *gorm.DB, oldNorm, newNorm, newPretty string,
	req *ldap.ModDNRequest,
) error {
	var e Entry
	if tx.Where("dn = ?", oldNorm).
		First(&e).Error != nil {
		return ErrNotFound
	}
	if err := refuseIfTaken(tx, newNorm); err != nil {
		return err
	}
	if !s.inScope(newNorm) && !s.isSuffix(newNorm) {
		return ErrOutOfScope
	}
	if err := requireParent(tx, s, newNorm); err != nil {
		return err
	}
	if err := s.moveRDNValues(tx, &e, req); err != nil {
		return err
	}
	// The entry's *old* pretty DN is needed before it is
	// overwritten: a descendant's pretty DN keeps its own
	// spelling and only its moved suffix is replaced.
	err := s.moveSubtree(
		tx, oldNorm, newNorm, e.PrettyDN, newPretty)
	if err != nil {
		return err
	}
	return tx.Model(&e).Updates(map[string]any{
		"dn":        newNorm,
		"pretty_dn": newPretty,
		"rev_dn":    revDN(newNorm),
		"parent_dn": parentOf(newNorm),
	}).Error
}

// moveSubtree rewrites every descendant's DN columns.
//
// The reversed DN earns its keep here: "is under" is a prefix, so
// finding the descendants is a prefix query rather than a walk.
//
// The pretty DN is rebuilt from the descendant's *own* pretty
// prefix, not from the normalised DN. Using the normal form gives
// cn=alice,ou=humans where slapd returns cn=Alice,ou=humans — the
// descendant keeps its own spelling and only the moved suffix
// changes. The harness caught exactly that.
func (s *Store) moveSubtree(
	tx *gorm.DB, oldNorm, newNorm string,
	oldPretty, newPretty string,
) error {
	var kids []Entry
	err := tx.Where("rev_dn LIKE ?",
		likePrefix(revDN(oldNorm))).Find(&kids).Error
	if err != nil {
		return err
	}
	for i := range kids {
		if err := moveOne(tx, &kids[i], move{
			oldNorm: oldNorm, newNorm: newNorm,
			oldPretty: oldPretty,
			newPretty: newPretty,
		}); err != nil {
			return err
		}
	}
	return nil
}

// move carries the four DNs a subtree move needs.
type move struct {
	oldNorm, newNorm     string
	oldPretty, newPretty string
}

// moveOne rewrites one descendant.
func moveOne(tx *gorm.DB, k *Entry, m move) error {
	norm := replaceSuffix(k.DN, m.oldNorm, m.newNorm)
	pretty := replaceSuffix(
		k.PrettyDN, m.oldPretty, m.newPretty)
	return tx.Model(k).Updates(map[string]any{
		"dn":        norm,
		"pretty_dn": pretty,
		"rev_dn":    revDN(norm),
		"parent_dn": parentOf(norm),
	}).Error
}

// replaceSuffix swaps a trailing ",old" for ",new".
func replaceSuffix(dnText, old, new string) string {
	prefix := strings.TrimSuffix(dnText, ","+old)
	if prefix == dnText {
		return dnText
	}
	return prefix + "," + new
}

// refuseIfTaken refuses a rename onto an existing DN.
func refuseIfTaken(tx *gorm.DB, norm string) error {
	var n int64
	err := tx.Model(&Entry{}).Where("dn = ?", norm).
		Count(&n).Error
	if err != nil {
		return err
	}
	if n > 0 {
		return ErrExists
	}
	return nil
}

// requireParent refuses a move under a parent that is absent.
func requireParent(
	tx *gorm.DB, s *Store, norm string,
) error {
	if s.isSuffix(norm) {
		return nil
	}
	parent := parentOf(norm)
	if parent == "" {
		return ErrNoParent
	}
	var n int64
	err := tx.Model(&Entry{}).
		Where("dn = ?", parent).Count(&n).Error
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoParent
	}
	return nil
}
