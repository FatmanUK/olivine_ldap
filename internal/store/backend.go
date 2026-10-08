package store

import (
	"errors"

	"github.com/FatmanUK/openldap_olivine/internal/acl"
	"github.com/FatmanUK/openldap_olivine/internal/dn"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// The methods below make a Store satisfy the Backend interface
// internal/server declares. They answer in LDAP result codes
// because the code is what a client receives, and a translation
// layer between Go errors and result codes is somewhere for a
// code to go astray.

// BackendSearch runs a search and returns the matching entries.
//
// The levels follow what the oracle showed, which is finer than
// a single read check:
//
//	below Search on the base  the search is refused outright
//	Search but not Read       success, and no entries at all
//	Read                      the entry, with the attributes
//	                          that are themselves readable
func (s *Store) BackendSearch(
	req *ldap.SearchRequest, who Identity,
) ([]ldap.SearchEntry, ldap.Result, []ldap.Control) {
	paged, hasPaged, err := ldap.FindPaged(req.Controls)
	if err != nil {
		return nil, ldap.Result{
			Code:       ldap.ProtocolError,
			Diagnostic: err.Error(),
		}, nil
	}
	entries, res := s.searchEntries(req, who)
	if res.Code != ldap.Success || !hasPaged {
		return entries, res, nil
	}
	return s.page(entries, paged)
}

// searchEntries does the search itself, before paging.
func (s *Store) searchEntries(
	req *ldap.SearchRequest, who Identity,
) ([]ldap.SearchEntry, ldap.Result) {
	if isRootDSERequest(req) {
		return s.searchRootDSE(req, who)
	}
	// cn=config is not in the database: it is a read-only
	// projection of the environment, so it is answered before
	// the base-must-exist check that follows.
	if cfg, ok := s.configBase(req.BaseObject); ok {
		return s.searchConfig(req, who, cfg)
	}
	// The base must exist, scope notwithstanding: RFC 4511
	// 4.5.3 gives noSuchObject when it does not, even for a
	// subtree search that would otherwise return nothing.
	if _, err := s.Get(req.BaseObject); err != nil {
		return nil, resultFor(err)
	}
	norm, _, err := s.normalise(req.BaseObject)
	if err != nil {
		return nil, resultFor(err)
	}
	level := s.accessTo(who, norm, acl.EntryAttribute)
	if level < acl.Search {
		return nil, denyResult(level)
	}
	entries, err := s.Search(req.BaseObject, req.Scope)
	if err != nil {
		return nil, resultFor(err)
	}
	return s.limited(entries, req, who)
}

// limited applies the size and time limits to a search.
//
// The entries up to the limit are returned *and* the overrun is
// reported: slapd sends what it has and then sizeLimitExceeded,
// rather than discarding the lot. A result of exactly the limit is
// success — code 4 means there were more, which the oracle showed
// by answering success for a filter matching exactly the limit.
func (s *Store) limited(
	entries []Entry, req *ldap.SearchRequest,
	who Identity,
) ([]ldap.SearchEntry, ldap.Result) {
	size := s.effectiveSize(req, who)
	deadline := s.deadline(req, who)
	out := make([]ldap.SearchEntry, 0, len(entries))
	for i := range entries {
		// Abandon is cooperative, as it is in slapd:
		// abandon.c sets o_abandon and the backend checks it
		// "at a convenient time". Between entries is that
		// time, the same place the time limit is checked.
		if cancelled(req.Context) {
			return nil, ldap.Result{
				Code: ldap.Other,
			}
		}
		if timedOut(deadline) {
			return out, ldap.Result{
				Code: ldap.TimeLimitExceeded,
			}
		}
		e := &entries[i]
		if !s.visible(e, req, who) {
			continue
		}
		if size > 0 && int32(len(out)) == size {
			// One more matched than the limit allows.
			return out, ldap.Result{
				Code: ldap.SizeLimitExceeded,
			}
		}
		out = append(out, s.project(e, req, who))
	}
	return out, ldap.Result{Code: ldap.Success}
}

// visible reports whether an entry is a result at all: readable,
// and matching the filter.
func (s *Store) visible(
	e *Entry, req *ldap.SearchRequest, who Identity,
) bool {
	// Each entry in its own right: a subtree search crosses
	// entries with different access.
	if s.accessTo(who, e.DN, acl.EntryAttribute) <
		acl.Read {
		return false
	}
	return Matches(s.schema, e, req.Filter)
}

// searchRootDSE answers a search of the empty DN.
//
// Base scope only: slapd gives noSuchObject for a one-level or
// subtree search from "", so the root DSE is not the top of a
// walkable tree. A client enumerating the directory has to read
// namingContexts and start again from there.
func (s *Store) searchRootDSE(
	req *ldap.SearchRequest, who Identity,
) ([]ldap.SearchEntry, ldap.Result) {
	if req.Scope != ldap.ScopeBase {
		return nil, ldap.Result{Code: ldap.NoSuchObject}
	}
	return []ldap.SearchEntry{s.rootDSE(req, who)},
		ldap.Result{Code: ldap.Success}
}

// BackendAdd creates an entry.
//
// Write access is needed on the entry being created. The check
// is against the new DN, because that is what the policy's dn
// clauses are written in terms of.
func (s *Store) BackendAdd(
	req *ldap.AddRequest, who Identity,
) ldap.Result {
	attrs := make([]Attribute, 0, len(req.Attributes))
	for _, a := range req.Attributes {
		attrs = append(attrs,
			Attribute{Type: a.Type, Values: a.Values})
	}
	// The schema first, then the connection restriction, then
	// the ACL. That is the order slapd uses: an anonymous add
	// of an entry with an undefined objectClass answers
	// invalidSyntax (21), and one with a valid schema answers
	// strongerAuthRequired (8). Checking access first gives
	// insufficientAccess and differs from the C on both.
	if s.isConfigTarget(req.Entry) {
		return refuseConfigWrite()
	}
	if res, ok := s.denySchema(attrs); !ok {
		return res
	}
	if res, ok := requireAuthenticatedUpdate(who); !ok {
		return res
	}
	if res, ok := s.denyWrite(who, req.Entry); !ok {
		return res
	}
	if _, err := s.Add(req.Entry, attrs); err != nil {
		return resultFor(err)
	}
	return ldap.Result{Code: ldap.Success}
}

// denySchema validates the attributes a request carries, so the
// schema can be checked before access control.
func (s *Store) denySchema(
	attrs []Attribute,
) (ldap.Result, bool) {
	values, err := s.buildValues(attrs)
	if err != nil {
		return resultFor(err), false
	}
	if err := s.checkEntry(values); err != nil {
		return resultFor(err), false
	}
	return ldap.Result{}, true
}

// BackendDelete removes an entry.
func (s *Store) BackendDelete(
	rawDN string, who Identity,
) ldap.Result {
	if s.isConfigTarget(rawDN) {
		return refuseConfigWrite()
	}
	if res, ok := requireAuthenticatedUpdate(who); !ok {
		return res
	}
	if res, ok := s.denyWrite(who, rawDN); !ok {
		return res
	}
	if err := s.Delete(rawDN); err != nil {
		return resultFor(err)
	}
	return ldap.Result{Code: ldap.Success}
}

// BackendModify applies modifications.
//
// Write is checked per attribute, not once for the entry: a
// policy may permit changing one attribute and not another, and
// checking only the entry would let the narrower grant through.
func (s *Store) BackendModify(
	req *ldap.ModifyRequest, who Identity,
) ldap.Result {
	if s.isConfigTarget(req.Object) {
		return refuseConfigWrite()
	}
	if res, ok := requireAuthenticatedUpdate(who); !ok {
		return res
	}
	for _, m := range req.Modifications {
		res, ok := s.denyWriteAttr(
			who, req.Object, m.Attribute.Type)
		if !ok {
			return res
		}
	}
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
	if res, ok := sentinelResult(err); ok {
		return res
	}
	return typedResult(err)
}

// sentinelResult maps the store's own errors.
func sentinelResult(err error) (ldap.Result, bool) {
	switch {
	case errors.Is(err, ErrNotFound):
		return ldap.Result{Code: ldap.NoSuchObject}, true
	case errors.Is(err, ErrExists):
		return ldap.Result{Code: ldap.AlreadyExists}, true
	case errors.Is(err, ErrNoParent),
		errors.Is(err, ErrOutOfScope):
		// RFC 4511 4.7: an add whose parent is absent is
		// noSuchObject, not a naming violation.
		return ldap.Result{Code: ldap.NoSuchObject}, true
	case errors.Is(err, ErrNotLeaf):
		return ldap.Result{
			Code: ldap.NotAllowedOnNonLeaf}, true
	case errors.Is(err, ErrValueExists):
		return ldap.Result{
			Code: ldap.TypeOrValueExists}, true
	case errors.Is(err, ErrNoSuchValue):
		return ldap.Result{
			Code: ldap.NoSuchAttribute}, true
	}
	return ldap.Result{}, false
}

// typedResult maps the errors that carry detail.
func typedResult(err error) ldap.Result {
	var bad *SyntaxError
	if errors.As(err, &bad) {
		return ldap.Result{
			Code:       ldap.InvalidSyntax,
			Diagnostic: bad.Type,
		}
	}
	var unknown *UnknownAttributeError
	if errors.As(err, &unknown) {
		return ldap.Result{
			Code:       ldap.UndefinedType,
			Diagnostic: unknown.Type,
		}
	}
	return dnResult(err)
}

// dnResult maps DN parsing failures.
func dnResult(err error) ldap.Result {
	switch {
	case errors.Is(err, dn.ErrUnknownAttr):
		return ldap.Result{Code: ldap.UndefinedType}
	case errors.Is(err, dn.ErrSyntax),
		errors.Is(err, dn.ErrEmpty),
		errors.Is(err, dn.ErrEmptyValue),
		errors.Is(err, dn.ErrBinaryValue):
		return ldap.Result{Code: ldap.InvalidDNSyntax}
	}
	return ldap.Result{Code: ldap.Other}
}
