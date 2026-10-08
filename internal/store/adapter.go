package store

import "github.com/FatmanUK/openldap_olivine/internal/ldap"

// Adapter makes a Store satisfy the Backend interface
// internal/server declares.
//
// A wrapper rather than methods on Store directly, because
// Store.Search and Store.Add already exist with different
// signatures — the store's own, which take a DN and return Go
// errors. Overloading is not available, and renaming the store's
// own methods to suit the interface would put the wire protocol's
// vocabulary into the persistence layer.
type Adapter struct {
	store *Store
}

// NewAdapter wraps s for use as a server Backend.
func NewAdapter(s *Store) *Adapter {
	return &Adapter{store: s}
}

// Bind authenticates.
func (a *Adapter) Bind(
	req *ldap.BindRequest,
) ldap.Result {
	return a.store.BackendBind(req)
}

// Search returns the matching entries.
func (a *Adapter) Search(
	req *ldap.SearchRequest,
) ([]ldap.SearchEntry, ldap.Result) {
	return a.store.BackendSearch(req)
}

// Add creates an entry.
func (a *Adapter) Add(req *ldap.AddRequest) ldap.Result {
	return a.store.BackendAdd(req)
}

// Delete removes an entry.
func (a *Adapter) Delete(rawDN string) ldap.Result {
	return a.store.BackendDelete(rawDN)
}

// Modify applies modifications.
func (a *Adapter) Modify(
	req *ldap.ModifyRequest,
) ldap.Result {
	return a.store.BackendModify(req)
}

// Compare tests one attribute value.
func (a *Adapter) Compare(
	req *ldap.CompareRequest,
) ldap.Result {
	return a.store.BackendCompare(req)
}

// Suffixes are the naming contexts, for the root DSE.
func (a *Adapter) Suffixes() []string {
	return a.store.Suffixes()
}
