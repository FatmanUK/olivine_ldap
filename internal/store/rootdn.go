package store

import (
	"github.com/FatmanUK/openldap_olivine/internal/acl"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// SetRootDN configures the administrative identity.
//
// slapd takes it from `rootdn` and `rootpw`, and it has two
// properties that make it unlike every other identity:
//
// The entry need not exist. rootdn is a name the server answers
// to, not a thing in the database, so a directory can be
// administered before it holds anything at all — which is how the
// first entry ever gets added.
//
// It bypasses access control entirely, as though granted manage
// everywhere. That is why a policy of `by * none` locks out every
// user and not the administrator.
//
// The password is stored hashed, in the same format as any other.
//
// In memory only; see AddSuffix.
func (s *Store) SetRootDN(
	rawDN, hashedPassword string,
) error {
	norm, pretty, err := s.normalise(rawDN)
	if err != nil {
		return err
	}
	return s.mutate(func(c *settings) error {
		c.rootDN = norm
		c.rootPretty = pretty
		c.rootPassword = hashedPassword
		return nil
	})
}

// isRoot reports whether an identity is the administrator.
func (s *Store) isRoot(who Identity) bool {
	root := s.conf().rootDN
	return root != "" && who.DN == root
}

// bindAsRoot answers a bind against the configured rootdn.
//
// Reports whether the request named the rootdn at all, so an
// ordinary bind for a DN that merely resembles it still falls
// through to the database.
func (s *Store) bindAsRoot(
	req *ldap.BindRequest,
) (Identity, ldap.Result, bool) {
	c := s.conf()
	if c.rootDN == "" {
		return Identity{}, ldap.Result{}, false
	}
	norm, _, err := s.normalise(req.Name)
	if err != nil || norm != c.rootDN {
		return Identity{}, ldap.Result{}, false
	}
	if c.rootPassword == "" ||
		!VerifyPassword(c.rootPassword, req.Simple) {
		return Identity{}, ldap.Result{
			Code: ldap.InvalidCredentials,
		}, true
	}
	// The rootdn has no entry, so there is no stored pretty
	// form; the configured spelling is the best there is.
	return Identity{
		DN: c.rootDN, Pretty: c.rootPretty,
	}, ldap.Result{Code: ldap.Success}, true
}

// rootLevel is the access the administrator has: everything.
const rootLevel = acl.Manage
