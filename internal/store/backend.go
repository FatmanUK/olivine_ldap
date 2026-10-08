package store

import (
	"errors"

	"github.com/FatmanUK/openldap_olivine/internal/dn"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// The methods below make a Store satisfy the Backend interface
// internal/server declares. They answer in LDAP result codes
// because the code is what a client receives, and a translation
// layer between Go errors and result codes is somewhere for a
// code to go astray.

// BackendSearch runs a search and returns the matching entries.
func (s *Store) BackendSearch(
	req *ldap.SearchRequest,
) ([]ldap.SearchEntry, ldap.Result) {
	// The base must exist, scope notwithstanding: RFC 4511
	// 4.5.3 gives noSuchObject when it does not, even for a
	// subtree search that would otherwise return nothing.
	if _, err := s.Get(req.BaseObject); err != nil {
		return nil, resultFor(err)
	}
	entries, err := s.Search(req.BaseObject, req.Scope)
	if err != nil {
		return nil, resultFor(err)
	}
	out := make([]ldap.SearchEntry, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		if !Matches(s.schema, e, req.Filter) {
			continue
		}
		out = append(out, s.project(e, req))
	}
	return out, ldap.Result{Code: ldap.Success}
}

// BackendAdd creates an entry.
func (s *Store) BackendAdd(
	req *ldap.AddRequest,
) ldap.Result {
	attrs := make([]Attribute, 0, len(req.Attributes))
	for _, a := range req.Attributes {
		attrs = append(attrs,
			Attribute{Type: a.Type, Values: a.Values})
	}
	if _, err := s.Add(req.Entry, attrs); err != nil {
		return resultFor(err)
	}
	return ldap.Result{Code: ldap.Success}
}

// BackendDelete removes an entry.
func (s *Store) BackendDelete(rawDN string) ldap.Result {
	if err := s.Delete(rawDN); err != nil {
		return resultFor(err)
	}
	return ldap.Result{Code: ldap.Success}
}

// BackendModify applies modifications.
func (s *Store) BackendModify(
	req *ldap.ModifyRequest,
) ldap.Result {
	mods := make([]Mod, 0, len(req.Modifications))
	for _, m := range req.Modifications {
		op, ok := modOp(m.Op)
		if !ok {
			return ldap.Result{
				Code:       ldap.ProtocolError,
				Diagnostic: "bad modification type",
			}
		}
		mods = append(mods, Mod{
			Op: op,
			Attribute: Attribute{
				Type:   m.Attribute.Type,
				Values: m.Attribute.Values,
			},
		})
	}
	if err := s.Modify(req.Object, mods); err != nil {
		return resultFor(err)
	}
	return ldap.Result{Code: ldap.Success}
}

// modOp maps the wire value to the store's own.
func modOp(op ldap.ModifyOp) (ModOp, bool) {
	switch op {
	case ldap.ModifyAdd:
		return ModAdd, true
	case ldap.ModifyDelete:
		return ModDelete, true
	case ldap.ModifyReplace:
		return ModReplace, true
	}
	return 0, false
}

// resultFor maps a store error to a result code.
func resultFor(err error) ldap.Result {
	// A schema violation carries the code slapd uses, so it is
	// consulted before the sentinel errors.
	if res, ok := violationResult(err); ok {
		return res
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return ldap.Result{Code: ldap.NoSuchObject}
	case errors.Is(err, ErrExists):
		return ldap.Result{Code: ldap.AlreadyExists}
	case errors.Is(err, ErrNoParent),
		errors.Is(err, ErrOutOfScope):
		// RFC 4511 4.7: an add whose parent is absent is
		// noSuchObject, not a naming violation.
		return ldap.Result{Code: ldap.NoSuchObject}
	case errors.Is(err, ErrNotLeaf):
		return ldap.Result{Code: ldap.NotAllowedOnNonLeaf}
	case errors.Is(err, ErrValueExists):
		return ldap.Result{Code: ldap.TypeOrValueExists}
	case errors.Is(err, ErrNoSuchValue):
		return ldap.Result{Code: ldap.NoSuchAttribute}
	case errors.Is(err, dn.ErrUnknownAttr):
		return ldap.Result{Code: ldap.UndefinedType}
	case errors.Is(err, dn.ErrSyntax),
		errors.Is(err, dn.ErrEmpty),
		errors.Is(err, dn.ErrEmptyValue),
		errors.Is(err, dn.ErrBinaryValue):
		return ldap.Result{Code: ldap.InvalidDNSyntax}
	}
	var unknown *UnknownAttributeError
	if errors.As(err, &unknown) {
		return ldap.Result{
			Code:       ldap.UndefinedType,
			Diagnostic: unknown.Type,
		}
	}
	return ldap.Result{Code: ldap.Other}
}
