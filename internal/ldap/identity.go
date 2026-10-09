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
	// DN is the normalised bound DN, empty when anonymous. This
	// is what an access check compares.
	DN string
	// Pretty is the same DN in the form to show a client, which
	// is what RFC 4532's whoami returns. slapd answers whoami
	// from o_dn, the pretty form, not o_ndn — so returning the
	// normalised DN there would lower-case a client's own name
	// back at it.
	//
	// Empty for an identity that has no client spelling to
	// preserve: a SASL-derived DN is synthesised from a
	// certificate subject or a Kerberos principal and has no
	// entry behind it, and slapd reports the normalised form
	// for those. whoami falls back to DN, which is that form.
	Pretty string
}

// Anonymous reports whether nothing has bound.
func (i Identity) Anonymous() bool { return i.DN == "" }
