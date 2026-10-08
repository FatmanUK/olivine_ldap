package server

import "github.com/FatmanUK/openldap_olivine/internal/ldap"

// Backend is what the dispatcher needs from a database.
//
// Deliberately narrow, and expressed in internal/ldap types
// rather than store types, so internal/server does not depend on
// Postgres. The server's own tests use a fake; the store's tests
// use a real database; the golden harness checks the two
// together against the C.
//
// Every method answers with an ldap.Result rather than a Go
// error, because the result code *is* the answer a client gets,
// and a mapping layer between the two is somewhere for a code to
// go astray.
type Backend interface {
	// Bind authenticates. A Result of Success means the
	// identity in the request is now the connection's.
	//
	// The Identity passed in is the one in force *before* this
	// bind, which is usually anonymous. Access control needs
	// it: auth on userPassword is checked as the requester the
	// connection currently is, not as the one it is trying to
	// become.
	//
	// The Identity returned is the one the connection now has,
	// and its DN is *normalised*. The backend has to supply it
	// because only it has the schema: a client may spell its
	// DN however it likes, and comparing an unnormalised DN
	// against stored entries makes `self` and `dn=` clauses
	// silently never match. slapd keeps o_ndn for the same
	// reason.
	Bind(*ldap.BindRequest, ldap.Identity) (
		ldap.Identity, ldap.Result)

	// Search returns the matching entries. Entries are sent
	// before the result, so a non-Success Result with entries
	// already returned is still reported after them.
	Search(*ldap.SearchRequest, ldap.Identity) (
		[]ldap.SearchEntry, ldap.Result)

	Add(*ldap.AddRequest, ldap.Identity) ldap.Result
	Delete(dn string, who ldap.Identity) ldap.Result
	Modify(*ldap.ModifyRequest, ldap.Identity) ldap.Result

	// Compare answers compareTrue or compareFalse, which are
	// both successes: a compare that answers is not a compare
	// that failed.
	Compare(*ldap.CompareRequest, ldap.Identity) ldap.Result

	// Suffixes are the naming contexts, for the root DSE.
	Suffixes() []string
}
