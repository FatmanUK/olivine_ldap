package store

import (
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/FatmanUK/openldap_olivine/internal/schema"
)

// Attribute is one attribute and its values, as a caller
// supplies them.
type Attribute struct {
	Type   string
	Values []string
}

// Add stores a new entry.
//
// The parent must exist unless the entry is a suffix root,
// which is what makes the tree a tree: RFC 4511 4.7 gives
// noSuchObject for an add whose parent is absent.
func (s *Store) Add(
	rawDN string, attrs []Attribute,
) (*Entry, error) {
	norm, pretty, err := s.normalise(rawDN)
	if err != nil {
		return nil, err
	}
	values, err := s.buildValues(attrs)
	if err != nil {
		return nil, err
	}
	if err := s.checkEntry(values); err != nil {
		return nil, err
	}
	entry := &Entry{
		DN:       norm,
		PrettyDN: pretty,
		RevDN:    revDN(norm),
		ParentDN: parentOf(norm),
		Values:   values,
	}
	if err := s.insert(entry); err != nil {
		return nil, err
	}
	return entry, nil
}

// insert writes the entry and its values in one transaction.
func (s *Store) insert(entry *Entry) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.checkParent(tx, entry); err != nil {
			return err
		}
		err := tx.Create(entry).Error
		if isUniqueViolation(err) {
			return ErrExists
		}
		return err
	})
}

// checkParent refuses an entry whose parent is missing.
//
// A suffix root has no parent in the database — nothing holds
// dc=com above dc=example,dc=com — so an entry that *is* a
// suffix is allowed through. See AddSuffix.
func (s *Store) checkParent(
	tx *gorm.DB, entry *Entry,
) error {
	if s.isSuffix(entry.DN) {
		return nil
	}
	if !s.inScope(entry.DN) {
		return ErrOutOfScope
	}
	if entry.ParentDN == "" {
		return ErrNoParent
	}
	var n int64
	err := tx.Model(&Entry{}).
		Where("dn = ?", entry.ParentDN).Count(&n).Error
	if err != nil {
		return err
	}
	if n == 0 {
		// Only the immediate parent is checked. A deeper
		// gap cannot exist if every add checked its own
		// parent.
		return ErrNoParent
	}
	return nil
}

// buildValues canonicalises the attributes a caller supplied.
func (s *Store) buildValues(
	attrs []Attribute,
) ([]Value, error) {
	var out []Value
	for _, a := range attrs {
		at, ok := s.schema.AttributeType(a.Type)
		if !ok {
			return nil, &UnknownAttributeError{
				Type: a.Type,
			}
		}
		name := strings.ToLower(canonicalName(at))
		for _, v := range a.Values {
			out = append(out, Value{
				Type:  name,
				Value: v,
				Norm: NormaliseValue(
					s.schema, at, v),
			})
		}
	}
	return out, nil
}

// canonicalName is an attribute type's first name, or its OID.
func canonicalName(at *schema.AttributeType) string {
	if len(at.Names) > 0 {
		return at.Names[0]
	}
	return at.OID
}

// UnknownAttributeError names an attribute no schema defines.
type UnknownAttributeError struct {
	Type string
}

// Error implements error.
func (e *UnknownAttributeError) Error() string {
	return "store: unknown attribute type " + e.Type
}

// isUniqueViolation reports whether err is a duplicate-key
// error. Checked by message rather than by SQLSTATE so the same
// code works if the driver changes underneath.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "duplicate key") ||
		strings.Contains(s, "SQLSTATE 23505")
}
