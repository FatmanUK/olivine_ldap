package ldap

// Identity is the authenticated requester on a connection.
//
// Empty DN means anonymous. It is passed into every backend
// operation because access control needs it, and because the
// identity at *bind* time is the one in force before that bind
// succeeds — which is why a policy of
// `by self write by users read by * none` makes it impossible
// for anyone to bind at all. See internal/acl.
type Identity struct {
	// DN is the normalised bound DN, empty when anonymous.
	DN string
}

// Anonymous reports whether nothing has bound.
func (i Identity) Anonymous() bool { return i.DN == "" }
