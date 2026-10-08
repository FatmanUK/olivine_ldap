package server

import "github.com/FatmanUK/openldap_olivine/internal/ldap"

// fakeBackend records what it was asked and answers as told.
//
// The server's tests use this rather than Postgres: what is
// under test here is the dispatch and the wire encoding, and a
// database in the loop would make these tests slow, non-hermetic
// and worse at saying which layer broke.
type fakeBackend struct {
	entries  []ldap.SearchEntry
	result   ldap.Result
	suffixes []string

	bindCalls    []*ldap.BindRequest
	searchCalls  []*ldap.SearchRequest
	addCalls     []*ldap.AddRequest
	deleteCalls  []string
	modifyCalls  []*ldap.ModifyRequest
	compareCalls []*ldap.CompareRequest
}

// newFake returns a backend that succeeds at everything.
func newFake() *fakeBackend {
	return &fakeBackend{
		result:   ldap.Result{Code: ldap.Success},
		suffixes: []string{"dc=example,dc=com"},
	}
}

func (f *fakeBackend) Bind(
	r *ldap.BindRequest,
) ldap.Result {
	f.bindCalls = append(f.bindCalls, r)
	return f.result
}

func (f *fakeBackend) Search(
	r *ldap.SearchRequest,
) ([]ldap.SearchEntry, ldap.Result) {
	f.searchCalls = append(f.searchCalls, r)
	return f.entries, f.result
}

func (f *fakeBackend) Add(
	r *ldap.AddRequest,
) ldap.Result {
	f.addCalls = append(f.addCalls, r)
	return f.result
}

func (f *fakeBackend) Delete(dn string) ldap.Result {
	f.deleteCalls = append(f.deleteCalls, dn)
	return f.result
}

func (f *fakeBackend) Modify(
	r *ldap.ModifyRequest,
) ldap.Result {
	f.modifyCalls = append(f.modifyCalls, r)
	return f.result
}

func (f *fakeBackend) Compare(
	r *ldap.CompareRequest,
) ldap.Result {
	f.compareCalls = append(f.compareCalls, r)
	return f.result
}

func (f *fakeBackend) Suffixes() []string {
	return f.suffixes
}
