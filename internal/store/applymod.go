package store

import (
	"errors"

	"gorm.io/gorm"
)

var (
	ErrNotLeaf = errors.New(
		"store: entry has children")
	ErrNoSuchValue = errors.New(
		"store: no such attribute value")
)

// applyMod applies one modification within a transaction.
//
// The canonical type name is resolved separately from the
// values, because a delete or replace with *no* values still
// names an attribute, and buildValues yields no rows to read it
// from.
func (s *Store) applyMod(
	tx *gorm.DB, e *Entry, m Mod,
) error {
	typ, err := s.canonicalType(m.Attribute.Type)
	if err != nil {
		return err
	}
	values, err := s.buildValues([]Attribute{m.Attribute})
	if err != nil {
		return err
	}
	for i := range values {
		values[i].EntryID = e.ID
	}
	switch m.Op {
	case ModAdd:
		return addValues(tx, values)
	case ModDelete:
		return deleteValues(tx, e, m, typ, values)
	case ModReplace:
		return replaceValues(tx, e, typ, values)
	}
	return errors.New("store: unknown modification")
}

// addValues inserts values, refusing a duplicate.
//
// RFC 4511 4.6: adding a value that is already present is
// attributeOrValueExists, not a silent no-op.
func addValues(tx *gorm.DB, values []Value) error {
	for _, v := range values {
		var n int64
		err := tx.Model(&Value{}).Where(
			"entry_id = ? AND type = ? AND norm = ?",
			v.EntryID, v.Type, v.Norm).Count(&n).Error
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrValueExists
		}
	}
	if len(values) == 0 {
		return nil
	}
	return tx.Create(&values).Error
}

// deleteValues removes the listed values, or the whole
// attribute when none are listed.
//
// RFC 4511 4.6 gives delete-with-no-values the meaning "remove
// the attribute entirely", which is easy to miss and quite
// different from a no-op.
func deleteValues(
	tx *gorm.DB, e *Entry, m Mod, typ string,
	values []Value,
) error {
	if len(m.Attribute.Values) == 0 {
		return tx.Where(
			"entry_id = ? AND type = ?", e.ID, typ).
			Delete(&Value{}).Error
	}
	for _, v := range values {
		res := tx.Where(
			"entry_id = ? AND type = ? AND norm = ?",
			e.ID, v.Type, v.Norm).Delete(&Value{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNoSuchValue
		}
	}
	return nil
}

// replaceValues swaps an attribute's values wholesale. A replace
// with no values deletes the attribute, as RFC 4511 4.6 says.
func replaceValues(
	tx *gorm.DB, e *Entry, typ string, values []Value,
) error {
	err := tx.Where("entry_id = ? AND type = ?",
		e.ID, typ).Delete(&Value{}).Error
	if err != nil {
		return err
	}
	if len(values) == 0 {
		return nil
	}
	return tx.Create(&values).Error
}

// ErrValueExists reports an add of a value already present.
var ErrValueExists = errors.New(
	"store: attribute value already exists")
