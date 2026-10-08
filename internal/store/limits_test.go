package store

import (
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// sizeSearch is a subtree search with a request size limit.
func sizeSearch(size int32) *ldap.SearchRequest {
	r := searchReq("dc=example,dc=com", ldap.ScopeSubtree,
		presentFilter("objectClass"))
	r.SizeLimit = size
	return r
}

// Each expectation came from the oracle, configured with
// `sizelimit 2` and probed.

// Code 4 means there were *more* than the limit. A result of
// exactly the limit is success: slapd answered success for a
// filter matching exactly two under `sizelimit 2`.
func TestSizeLimitExactlyAtLimitIsSuccess(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	s.SetLimits(Limits{Size: 5})

	// The fixture holds exactly five entries.
	got, res := s.BackendSearch(sizeSearch(0), anyone)
	if res.Code != ldap.Success {
		t.Errorf("code = %v, want success", res.Code)
	}
	if len(got) != 5 {
		t.Errorf("%d entries, want 5", len(got))
	}
}

func TestSizeLimitOverrun(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	s.SetLimits(Limits{Size: 2})

	got, res := s.BackendSearch(sizeSearch(0), anyone)
	if res.Code != ldap.SizeLimitExceeded {
		t.Errorf("code = %v, want sizeLimitExceeded",
			res.Code)
	}
	// The entries it did find are returned, not discarded.
	if len(got) != 2 {
		t.Errorf("%d entries, want 2", len(got))
	}
}

// The lower of the two wins, and zero means that side is
// unlimited rather than the smallest.
func TestSizeLimitTakesTheLower(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	s.SetLimits(Limits{Size: 3})

	cases := []struct {
		name    string
		request int32
		want    int
	}{
		{"request unlimited", 0, 3},
		{"request below admin", 1, 1},
		{"request above admin", 10, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := s.BackendSearch(
				sizeSearch(c.request), anyone)
			if len(got) != c.want {
				t.Errorf("%d entries, want %d",
					len(got), c.want)
			}
		})
	}
}

// The administrator is not subject to the limit: a search as
// rootdn against `sizelimit 2` returned all four entries.
func TestSizeLimitRootBypasses(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	withRoot(t, s)
	s.SetLimits(Limits{Size: 1})

	got, res := s.BackendSearch(sizeSearch(0), admin)
	if res.Code != ldap.Success {
		t.Errorf("code = %v, want success", res.Code)
	}
	if len(got) != 5 {
		t.Errorf("%d entries, want all 5", len(got))
	}
}

// Unset limits mean slapd's defaults, not unlimited.
func TestDefaultLimitsAreSlapds(t *testing.T) {
	if DefaultLimits.Size != 500 {
		t.Errorf("size = %d, want 500",
			DefaultLimits.Size)
	}
	if DefaultLimits.Time != 3600 {
		t.Errorf("time = %d, want 3600",
			DefaultLimits.Time)
	}
	s := testStore(t)
	if got := s.limitsOrDefault(); got != DefaultLimits {
		t.Errorf("unset limits = %+v", got)
	}
}
