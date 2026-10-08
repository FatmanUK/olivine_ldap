package server

import (
	"strings"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

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

	// identities records who each call was made as, so a test
	// can assert that the pre-bind identity reaches the
	// backend.
	identities []ldap.Identity

	bindCalls    []*ldap.BindRequest
	searchCalls  []*ldap.SearchRequest
	addCalls     []*ldap.AddRequest
	deleteCalls  []string
	modifyCalls  []*ldap.ModifyRequest
	compareCalls []*ldap.CompareRequest
	modDNCalls   []*ldap.ModDNRequest
}

// newFake returns a backend that succeeds at everything.
func newFake() *fakeBackend {
	return &fakeBackend{
		result:   ldap.Result{Code: ldap.Success},
		suffixes: []string{"dc=example,dc=com"},
	}
}

func (f *fakeBackend) Bind(
	r *ldap.BindRequest, who ldap.Identity,
) (ldap.Identity, ldap.Result) {
	f.bindCalls = append(f.bindCalls, r)
	f.identities = append(f.identities, who)
	// A real backend returns the *normalised* DN; the fake
	// lower-cases to stand in for that, so a test can tell the
	// two apart.
	return ldap.Identity{
		DN: strings.ToLower(r.Name),
	}, f.result
}

func (f *fakeBackend) Search(
	r *ldap.SearchRequest, who ldap.Identity,
) ([]ldap.SearchEntry, ldap.Result) {
	f.searchCalls = append(f.searchCalls, r)
	f.identities = append(f.identities, who)
	return f.entries, f.result
}

func (f *fakeBackend) Add(
	r *ldap.AddRequest, who ldap.Identity,
) ldap.Result {
	f.addCalls = append(f.addCalls, r)
	f.identities = append(f.identities, who)
	return f.result
}

func (f *fakeBackend) Delete(
	dn string, who ldap.Identity,
) ldap.Result {
	f.deleteCalls = append(f.deleteCalls, dn)
	f.identities = append(f.identities, who)
	return f.result
}

func (f *fakeBackend) Modify(
	r *ldap.ModifyRequest, who ldap.Identity,
) ldap.Result {
	f.modifyCalls = append(f.modifyCalls, r)
	f.identities = append(f.identities, who)
	return f.result
}

func (f *fakeBackend) Compare(
	r *ldap.CompareRequest, who ldap.Identity,
) ldap.Result {
	f.compareCalls = append(f.compareCalls, r)
	f.identities = append(f.identities, who)
	return f.result
}

func (f *fakeBackend) ModDN(
	r *ldap.ModDNRequest, who ldap.Identity,
) ldap.Result {
	f.modDNCalls = append(f.modDNCalls, r)
	f.identities = append(f.identities, who)
	return f.result
}

func (f *fakeBackend) Suffixes() []string {
	return f.suffixes
}
