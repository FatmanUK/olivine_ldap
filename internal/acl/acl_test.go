package acl

import "testing"

const (
	alice = "cn=alice,dc=example,dc=com"
	bob   = "cn=bob,dc=example,dc=com"
	base  = "dc=example,dc=com"
)

// mustParse parses or fails the test.
func mustParse(t *testing.T, text string) *Policy {
	t.Helper()
	p, err := Parse(text)
	if err != nil {
		t.Fatalf("parsing %q: %v", text, err)
	}
	return p
}

// Every expectation here was established against the oracle, by
// configuring slapd with the directive and observing the result
// codes. None is read off the manual page.

// With no directives at all, access is read
// (frontend.c:99, be_dfltaccess = ACL_READ).
func TestDefaultAccessIsRead(t *testing.T) {
	p := NewPolicy()
	req := Request{TargetDN: alice, Attribute: "sn"}
	if got := p.Level(req); got != Read {
		t.Errorf("default = %v, want read", got)
	}
}

// A clause that matches but whose `by` clauses do not denies —
// it does not fall through to the default. The oracle showed an
// anonymous base search answering noSuchObject under
// `access to * by dn="cn=nobody,..." read`.
func TestMatchingClauseWithNoMatchingByDenies(t *testing.T) {
	p := mustParse(t, `access to * `+
		`by dn="cn=nobody,dc=example,dc=com" read`)
	req := Request{TargetDN: alice, Attribute: "sn"}
	if got := p.Level(req); got != None {
		t.Errorf("level = %v, want none", got)
	}
}

// Selection is per attribute, so an earlier clause can hide one
// attribute while a later one grants the rest. The oracle
// returned the entry with description missing and the others
// present.
func TestPerAttributeSelection(t *testing.T) {
	p := mustParse(t, `access to attrs=description by * none
access to * by * read`)
	hidden := Request{TargetDN: alice,
		Attribute: "description"}
	if got := p.Level(hidden); got != None {
		t.Errorf("description = %v, want none", got)
	}
	shown := Request{TargetDN: alice, Attribute: "sn"}
	if got := p.Level(shown); got != Read {
		t.Errorf("sn = %v, want read", got)
	}
	// And the entry itself is still readable, because
	// attrs=description does not select the entry
	// pseudo-attribute.
	entry := Request{TargetDN: alice,
		Attribute: EntryAttribute}
	if got := p.Level(entry); got != Read {
		t.Errorf("entry = %v, want read", got)
	}
}

// Levels are cumulative: a grant of read satisfies a need for
// search, and a grant of search does not satisfy read.
func TestLevelsAreCumulative(t *testing.T) {
	p := mustParse(t, `access to * by * search`)
	req := Request{TargetDN: alice, Attribute: "sn"}
	for _, need := range []Level{
		Disclose, Auth, Compare, Search,
	} {
		if !p.Allows(req, need) {
			t.Errorf("search should satisfy %v", need)
		}
	}
	for _, need := range []Level{Read, Write, Manage} {
		if p.Allows(req, need) {
			t.Errorf("search should not satisfy %v", need)
		}
	}
}

func TestWhoClauses(t *testing.T) {
	p := mustParse(t,
		`access to * by self write by users read by * none`)
	cases := []struct {
		name string
		req  Request
		want Level
	}{
		{"self", Request{TargetDN: alice,
			Attribute: "sn", BoundDN: alice}, Write},
		{"other user", Request{TargetDN: alice,
			Attribute: "sn", BoundDN: bob}, Read},
		{"anonymous", Request{TargetDN: alice,
			Attribute: "sn"}, None},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := p.Level(c.req); got != c.want {
				t.Errorf("got %v, want %v",
					got, c.want)
			}
		})
	}
}

// The classic footgun, confirmed against the oracle: this policy
// makes it impossible for anyone to bind at all, because at bind
// time the requester is still anonymous, so neither `self` nor
// `users` matches and `* none` denies auth on userPassword.
// slapd answered invalidCredentials (49).
func TestSelfWriteBreaksBind(t *testing.T) {
	p := mustParse(t,
		`access to * by self write by users read by * none`)
	req := Request{TargetDN: alice,
		Attribute: "userpassword"}
	if p.Allows(req, Auth) {
		t.Error("anonymous should not have auth here; " +
			"slapd cannot bind under this policy either")
	}
}

// The canonical working pattern: auth on userPassword for
// everyone, nothing else. The oracle bound successfully and
// refused the anonymous search.
func TestAuthOnPasswordAllowsBind(t *testing.T) {
	p := mustParse(t, `access to attrs=userPassword by * auth
access to * by * none`)
	pw := Request{TargetDN: alice,
		Attribute: "userpassword"}
	if !p.Allows(pw, Auth) {
		t.Error("bind should be possible")
	}
	// But not readable.
	if p.Allows(pw, Read) {
		t.Error("auth must not imply read")
	}
	other := Request{TargetDN: alice, Attribute: "sn"}
	if p.Allows(other, Read) {
		t.Error("sn should not be readable")
	}
}
