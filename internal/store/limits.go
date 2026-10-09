package store

import (
	"context"
	"time"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// Limits are the administrative search limits, as slapd's
// `sizelimit` and `timelimit`. Zero means unlimited.
type Limits struct {
	Size int32
	Time int32
}

// DefaultLimits are slapd's: 500 entries and 3600 seconds.
//
// Taken from slapd's own defaults rather than invented, so a
// directory stood up with no limits configured behaves the same
// under both.
var DefaultLimits = Limits{Size: 500, Time: 3600}

// SetLimits installs the administrative limits.
//
// In memory only; see AddSuffix.
func (s *Store) SetLimits(l Limits) {
	_ = s.mutate(func(c *settings) error {
		c.limits = l
		return nil
	})
}

// limitsOrDefault returns the limits in force.
func (s *Store) limitsOrDefault() Limits {
	l := s.conf().limits
	if l == (Limits{}) {
		return DefaultLimits
	}
	return l
}

// effectiveSize returns the size limit for one search.
//
// The lower of the request's and the administrator's wins, and
// zero on either side means that side is unlimited. Verified
// against the oracle: with `sizelimit 2` configured, a request
// asking for 10 still gets 2, and one asking for 0 also gets 2.
//
// The administrator bypasses the limit entirely — a search as
// rootdn against `sizelimit 2` returned all four entries.
func (s *Store) effectiveSize(
	req *ldap.SearchRequest, who Identity,
) int32 {
	if s.isRoot(who) {
		return 0
	}
	return lower(req.SizeLimit, s.limitsOrDefault().Size)
}

// effectiveTime returns the time limit for one search, in
// seconds.
func (s *Store) effectiveTime(
	req *ldap.SearchRequest, who Identity,
) time.Duration {
	if s.isRoot(who) {
		return 0
	}
	n := lower(req.TimeLimit, s.limitsOrDefault().Time)
	return time.Duration(n) * time.Second
}

// lower returns the smaller of two limits, treating zero as
// unlimited rather than as the smallest.
func lower(a, b int32) int32 {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	}
	return b
}

// deadline returns when a search must stop, or the zero time when
// it is unlimited.
func (s *Store) deadline(
	req *ldap.SearchRequest, who Identity,
) time.Time {
	d := s.effectiveTime(req, who)
	if d <= 0 {
		return time.Time{}
	}
	return time.Now().Add(d)
}

// timedOut reports whether a deadline has passed.
//
// Checked between entries rather than inside the database query.
// That is coarser than slapd, which can abandon mid-index-scan,
// and it means a single very slow query can overrun the limit —
// recorded rather than hidden.
func timedOut(deadline time.Time) bool {
	return !deadline.IsZero() &&
		time.Now().After(deadline)
}

// cancelled reports whether an operation has been abandoned.
//
// A nil context means the caller cannot abandon, which is how the
// store's own tests and anything not driven by a connection run.
func cancelled(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
