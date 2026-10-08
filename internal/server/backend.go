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
	Bind(*ldap.BindRequest) ldap.Result

	// Search returns the matching entries. Entries are sent
	// before the result, so a non-Success Result with entries
	// already returned is still reported after them.
	Search(*ldap.SearchRequest) ([]ldap.SearchEntry, ldap.Result)

	Add(*ldap.AddRequest) ldap.Result
	Delete(dn string) ldap.Result
	Modify(*ldap.ModifyRequest) ldap.Result

	// Compare answers compareTrue or compareFalse, which are
	// both successes: a compare that answers is not a compare
	// that failed.
	Compare(*ldap.CompareRequest) ldap.Result

	// Suffixes are the naming contexts, for the root DSE.
	Suffixes() []string
}
