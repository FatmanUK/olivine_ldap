package store

import (
	"gorm.io/gorm"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// Delete removes one entry.
//
// Refused if the entry has children: RFC 4511 4.8 allows Delete
// only on a leaf, and notAllowedOnNonLeaf is the code for it.
// back-mdb enforces the same thing.
func (s *Store) Delete(rawDN string) error {
	norm, _, err := s.normalise(rawDN)
	if err != nil {
		return err
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var kids int64
		err := tx.Model(&Entry{}).
			Where("parent_dn = ?", norm).
			Count(&kids).Error
		if err != nil {
			return err
		}
		if kids > 0 {
			return ErrNotLeaf
		}
		return deleteOne(tx, norm)
	})
}

// deleteOne removes the entry and its values.
func deleteOne(tx *gorm.DB, norm string) error {
	var e Entry
	err := tx.Where("dn = ?", norm).First(&e).Error
	if err != nil {
		return ErrNotFound
	}
	err = tx.Where("entry_id = ?", e.ID).
		Delete(&Value{}).Error
	if err != nil {
		return err
	}
	return tx.Delete(&Entry{}, e.ID).Error
}

// ModOp is one modification's kind, RFC 4511 4.6.
type ModOp int

const (
	ModAdd ModOp = iota
	ModDelete
	ModReplace
)

// Mod is one modification.
type Mod struct {
	Op        ModOp
	Attribute Attribute
}

// Modify applies modifications to one entry, all or nothing.
//
// RFC 4511 4.6 requires the whole list to succeed or none of it
// to apply, which is what the transaction is for: a Modify that
// half-applied would leave an entry no client asked for.
func (s *Store) Modify(rawDN string, mods []Mod) error {
	norm, _, err := s.normalise(rawDN)
	if err != nil {
		return err
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var e Entry
		err := tx.Where("dn = ?", norm).First(&e).Error
		if err != nil {
			return ErrNotFound
		}
		for _, m := range mods {
			if err := s.applyMod(tx, &e, m); err != nil {
				return err
			}
		}
		// slapd checks the schema after the whole list has
		// applied, not after each modification: an
		// intermediate state may legitimately violate it,
		// as when one mod adds an objectClass and the next
		// adds the attribute it requires.
		if err := s.recheck(tx, &e); err != nil {
			return err
		}
		return tx.Model(&e).
			Update("updated_at", gorm.Expr("now()")).
			Error
	})
}

// Scope is re-exported so callers need not import internal/ldap
// just to name a search scope.
type Scope = ldap.Scope
