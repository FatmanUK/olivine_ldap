package store

import (
	"errors"

	"gorm.io/gorm"

	"github.com/FatmanUK/olivine_ldap/internal/ldap"
	"github.com/FatmanUK/olivine_ldap/internal/schema"
)

// checkEntry validates a set of values against the schema.
//
// slapd checks on every add and after every modify, and refuses
// the operation rather than storing something the schema forbids.
// Olivine did neither until now, which the golden harness exposed:
// the fixture's `objectClass: domain` was accepted here and
// refused there.
func (s *Store) checkEntry(values []Value) error {
	e := schema.Entry{Attributes: map[string][]string{}}
	for _, v := range values {
		e.Attributes[v.Type] = append(
			e.Attributes[v.Type], v.Value)
	}
	return s.schema.Check(e)
}

// violationResult turns a schema violation into a result,
// preserving the code slapd uses for it.
func violationResult(err error) (ldap.Result, bool) {
	var v *schema.Violation
	if !errors.As(err, &v) {
		return ldap.Result{}, false
	}
	return ldap.Result{
		Code:       ldap.ResultCode(v.Code),
		Diagnostic: v.Text,
	}, true
}

// recheck validates an entry as it stands inside a transaction.
func (s *Store) recheck(tx *gorm.DB, e *Entry) error {
	var values []Value
	err := tx.Where("entry_id = ?", e.ID).
		Find(&values).Error
	if err != nil {
		return err
	}
	return s.checkEntry(values)
}
