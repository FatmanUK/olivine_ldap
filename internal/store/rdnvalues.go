package store

import (
	"gorm.io/gorm"

	"github.com/FatmanUK/openldap_olivine/internal/dn"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// moveRDNValues brings an entry's attributes in line with its new
// RDN.
//
// slapd replaces them: renaming cn=Alice to cn=Alicia leaves the
// entry carrying `cn: Alicia`. Verified against the oracle, which
// is also where the consequence of not doing it showed up — a
// search for the new name found nothing, because only the DN had
// moved.
//
// deleteoldrdn says whether the old value goes. When it is false
// the entry keeps both, which is how an entry ends up with two cn
// values after a rename.
func (s *Store) moveRDNValues(
	tx *gorm.DB, e *Entry, req *ldap.ModDNRequest,
) error {
	if req.DeleteOldRDN {
		if err := s.dropRDNValues(
			tx, e, e.DN); err != nil {
			return err
		}
	}
	return s.addRDNValues(tx, e, req.NewRDN)
}

// dropRDNValues removes the values named by a DN's first RDN.
func (s *Store) dropRDNValues(
	tx *gorm.DB, e *Entry, fromDN string,
) error {
	avas, err := s.firstRDN(fromDN)
	if err != nil {
		return err
	}
	for _, a := range avas {
		typ, norm, err := s.rdnValue(a)
		if err != nil {
			return err
		}
		err = tx.Where(
			"entry_id = ? AND type = ? AND norm = ?",
			e.ID, typ, norm).Delete(&Value{}).Error
		if err != nil {
			return err
		}
	}
	return nil
}

// addRDNValues adds the values a new RDN names, skipping any the
// entry already has.
func (s *Store) addRDNValues(
	tx *gorm.DB, e *Entry, newRDN string,
) error {
	avas, err := s.firstRDN(newRDN)
	if err != nil {
		return err
	}
	for _, a := range avas {
		typ, norm, err := s.rdnValue(a)
		if err != nil {
			return err
		}
		var n int64
		err = tx.Model(&Value{}).Where(
			"entry_id = ? AND type = ? AND norm = ?",
			e.ID, typ, norm).Count(&n).Error
		if err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		err = tx.Create(&Value{
			EntryID: e.ID, Type: typ,
			Value: a.Value, Norm: norm,
		}).Error
		if err != nil {
			return err
		}
	}
	return nil
}

// firstRDN parses the leading RDN of a DN or a bare RDN.
func (s *Store) firstRDN(text string) (dn.RDN, error) {
	parsed, err := dn.Parse(text)
	if err != nil {
		return nil, err
	}
	if len(parsed) == 0 {
		return nil, dn.ErrEmpty
	}
	return parsed[0], nil
}

// rdnValue resolves one AVA to its stored type and normal form.
func (s *Store) rdnValue(
	a dn.AVA,
) (string, string, error) {
	at, ok := s.schema.AttributeType(a.Type)
	if !ok {
		return "", "", &UnknownAttributeError{
			Type: a.Type,
		}
	}
	typ, err := s.canonicalType(a.Type)
	if err != nil {
		return "", "", err
	}
	return typ, NormaliseValue(s.schema, at, a.Value), nil
}
