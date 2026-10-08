package store

import (
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// pagedSearch is a subtree search carrying the paged control.
func pagedSearch(
	t *testing.T, size int32, cookie []byte,
) *ldap.SearchRequest {
	t.Helper()
	value, err := ldap.Paged{
		Size: size, Cookie: cookie,
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	r := searchReq("dc=example,dc=com", ldap.ScopeSubtree,
		presentFilter("objectClass"))
	r.Controls = []ldap.Control{{
		OID:      ldap.OIDPagedResults,
		Value:    value,
		HasValue: true,
	}}
	return r
}

// cookieFrom pulls the cookie out of a reply's controls.
func cookieFrom(
	t *testing.T, controls []ldap.Control,
) []byte {
	t.Helper()
	paged, found, err := ldap.FindPaged(controls)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("no paged control in the reply")
	}
	return paged.Cookie
}

// Walking the pages must cover every entry exactly once and stop.
func TestPagedWalkCoversEverythingOnce(t *testing.T) {
	s := testStore(t)
	seed(t, s)

	seen := map[string]int{}
	var cookie []byte
	pages := 0
	for pages < 20 {
		got, res, controls := s.BackendSearch(
			pagedSearch(t, 2, cookie), anyone)
		if res.Code != ldap.Success {
			t.Fatalf("page %d: %v", pages, res.Code)
		}
		pages++
		for _, e := range got {
			seen[e.DN]++
		}
		cookie = cookieFrom(t, controls)
		if len(cookie) == 0 {
			break
		}
	}
	if pages != 3 {
		t.Errorf("%d pages, want 3 for five entries at 2",
			pages)
	}
	if len(seen) != 5 {
		t.Errorf("%d distinct entries, want 5", len(seen))
	}
	for dn, n := range seen {
		if n != 1 {
			t.Errorf("%s returned %d times", dn, n)
		}
	}
}

// The last page comes with an empty cookie, which is how a client
// knows to stop.
func TestPagedLastPageClosesTheCookie(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	_, res, controls := s.BackendSearch(
		pagedSearch(t, 100, nil), anyone)
	if res.Code != ldap.Success {
		t.Fatal(res.Code)
	}
	if c := cookieFrom(t, controls); len(c) != 0 {
		t.Errorf("cookie = %q, want empty", c)
	}
}

// A cookie this server did not issue is refused rather than
// guessed at: resuming from a position it cannot interpret would
// silently return the wrong page.
func TestPagedRejectsForeignCookie(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	_, res, _ := s.BackendSearch(
		pagedSearch(t, 2, []byte("AwAAAAAAAAA=")), anyone)
	if res.Code != ldap.UnwillingToPerform {
		t.Errorf("code = %v, want unwillingToPerform",
			res.Code)
	}
}

// RFC 2696 2: a page size of zero ends the paged search.
func TestPagedZeroSizeEndsIt(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	got, res, controls := s.BackendSearch(
		pagedSearch(t, 0, nil), anyone)
	if res.Code != ldap.Success {
		t.Fatal(res.Code)
	}
	if len(got) != 0 {
		t.Errorf("%d entries, want none", len(got))
	}
	if c := cookieFrom(t, controls); len(c) != 0 {
		t.Errorf("cookie = %q, want empty", c)
	}
}

// An entry deleted behind the cursor must not shift the sequence:
// the cookie names a DN, not an offset.
func TestPagedSurvivesDeletionBehindTheCursor(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	withRoot(t, s)

	got, _, controls := s.BackendSearch(
		pagedSearch(t, 2, nil), anyone)
	if len(got) != 2 {
		t.Fatalf("first page held %d", len(got))
	}
	cookie := cookieFrom(t, controls)

	// Remove an entry from the page already returned.
	if res := s.BackendDelete(got[0].DN, admin); res.Code !=
		ldap.Success {
		t.Fatalf("delete: %v", res.Code)
	}
	// The next page must carry on from where it left off, not
	// repeat an entry because the offsets moved.
	next, res, _ := s.BackendSearch(
		pagedSearch(t, 2, cookie), anyone)
	if res.Code != ldap.Success {
		t.Fatal(res.Code)
	}
	for _, e := range next {
		if e.DN == got[1].DN {
			t.Errorf("%s repeated after a deletion",
				e.DN)
		}
	}
}

// A critical paged control must be honoured, not refused. It is
// implemented, so RFC 4511 4.1.11's unavailableCriticalExtension
// does not apply — and a client marking it critical is the normal
// case, since paging silently ignored returns the wrong answer.
func TestPagedCriticalIsHonoured(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	req := pagedSearch(t, 2, nil)
	req.Controls[0].Critical = true
	got, res, _ := s.BackendSearch(req, anyone)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v, want success", res.Code)
	}
	if len(got) != 2 {
		t.Errorf("%d entries, want 2", len(got))
	}
}
