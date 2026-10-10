package store

import (
	"errors"

	"gorm.io/gorm"

	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// ErrNewRDNExists reports a rename onto an existing DN.
var ErrNewRDNExists = errors.New(
	"store: the new DN already exists")

// BackendModDN renames or moves an entry, and its subtree.
//
// back-mdb renames a whole subtree, verified against the oracle:
// renaming ou=people with children beneath it answers success. An
// earlier version of this refused a non-leaf with
// notAllowedOnNonLeaf, on the strength of an assumption that
// upstream behaved like Delete. It does not.
func (s *Store) BackendModDN(
	req *ldap.ModDNRequest, who Identity,
) ldap.Result {
	if s.isConfigTarget(req.Entry) ||
		s.isConfigTarget(req.NewSuperior) {
		return refuseConfigWrite()
	}
	if res, ok := requireAuthenticatedUpdate(who); !ok {
		return res
	}
	if res, ok := s.denyWrite(who, req.Entry); !ok {
		return res
	}
	newDN, err := s.renamedDN(req)
	if err != nil {
		return resultFor(err)
	}
	if res, ok := s.denyWrite(who, newDN); !ok {
		return res
	}
	if err := s.rename(req, newDN); err != nil {
		return resultFor(err)
	}
	return ldap.Result{Code: ldap.Success}
}

// renamedDN builds the DN the entry will have.
func (s *Store) renamedDN(
	req *ldap.ModDNRequest,
) (string, error) {
	norm, _, err := s.normalise(req.Entry)
	if err != nil {
		return "", err
	}
	parent := parentOf(norm)
	if req.HasNewSuperior {
		parent, _, err = s.normalise(req.NewSuperior)
		if err != nil {
			return "", err
		}
	}
	if parent == "" {
		return req.NewRDN, nil
	}
	return req.NewRDN + "," + parent, nil
}

// rename moves an entry, and its subtree, to a new DN.
func (s *Store) rename(
	req *ldap.ModDNRequest, newRaw string,
) error {
	oldNorm, _, err := s.normalise(req.Entry)
	if err != nil {
		return err
	}
	newNorm, newPretty, err := s.normalise(newRaw)
	if err != nil {
		return err
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		return s.renameTx(
			tx, oldNorm, newNorm, newPretty, req)
	})
}
