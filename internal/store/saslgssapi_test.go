package store

import (
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// The synthetic DN slapd's slap_sasl_getdn composes. The first
// case is the one observed against the oracle: binding as
// tester@OLIVINE.TEST to a slapd in that realm reported
// dn:uid=tester,cn=gssapi,cn=auth, with no realm RDN.
func TestSASLDN(t *testing.T) {
	const own = "OLIVINE.TEST"
	cases := []struct{ principal, want string }{
		{"tester@OLIVINE.TEST",
			"uid=tester,cn=gssapi,cn=auth"},
		// A realm that is not the server's own stays inside
		// the uid value rather than becoming an RDN of its
		// own. Observed: the oracle answered
		// dn:uid=tester@other.test,cn=gssapi,cn=auth for a
		// cross-realm bind, where reading slap_sasl_getdn
		// alone had suggested cn=OTHER.TEST.
		{"tester@OTHER.TEST",
			"uid=tester@OTHER.TEST," +
				"cn=gssapi,cn=auth"},
		// Case-insensitively: a realm is written upper-case
		// by convention, not by rule.
		{"tester@olivine.test",
			"uid=tester,cn=gssapi,cn=auth"},
		// A service principal keeps both components.
		{"host/web@OLIVINE.TEST",
			"uid=host/web,cn=gssapi,cn=auth"},
		// No realm at all, which a keytab-less principal
		// could be.
		{"tester", "uid=tester,cn=gssapi,cn=auth"},
		// DN metacharacters in a principal are escaped,
		// which is ITS#3419's point.
		{"a+b,c@OLIVINE.TEST",
			`uid=a\+b\,c,cn=gssapi,cn=auth`},
	}
	for _, c := range cases {
		if got := saslDN(c.principal, own); got != c.want {
			t.Errorf("saslDN(%q) = %q, want %q",
				c.principal, got, c.want)
		}
	}
}

// The realm separator is the last @, because a principal's name
// component may contain one.
func TestSplitPrincipal(t *testing.T) {
	user, realm := splitPrincipal("a@b@REALM")
	if user != "a@b" || realm != "REALM" {
		t.Errorf("got %q, %q", user, realm)
	}
}

// GSSAPI is advertised only when a keytab is configured.
// slapd advertises it whenever Cyrus has the plugin, which lets
// a client pick a mechanism that cannot work.
func TestGSSAPIAdvertisedOnlyWhenConfigured(
	t *testing.T,
) {
	s := testStore(t)
	for _, m := range s.Mechanisms() {
		if m == MechGSSAPI {
			t.Fatal("advertised with no keytab")
		}
	}
	_, res := s.saslBind(&ldap.BindRequest{
		IsSASL: true, Mechanism: MechGSSAPI,
	}, anyone)
	if res.Code != ldap.AuthMethodNotSupported {
		t.Errorf("code = %v, want "+
			"authMethodNotSupported", res.Code)
	}
}
