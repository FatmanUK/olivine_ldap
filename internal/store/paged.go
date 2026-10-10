package store

import (
	"encoding/base64"
	"strings"

	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// pageCookie is the opaque value handed to a client to resume a
// paged search.
//
// It names the last DN returned, not an offset. slapd's cookie is
// an index position, and an offset silently skips or repeats
// entries when the data changes between pages — a deletion before
// the cursor shifts everything left. Resuming after a DN cannot
// skip an entry that was there all along, which matters more here
// than byte-compatibility with a value RFC 2696 declares opaque
// anyway.
//
// Encoded so a client cannot mistake it for something meaningful,
// and so a malformed one is distinguishable from a truncated one.
const cookiePrefix = "olv1:"

// encodeCookie renders a resume point.
func encodeCookie(lastDN string) []byte {
	if lastDN == "" {
		return nil
	}
	return []byte(cookiePrefix +
		base64.RawURLEncoding.EncodeToString(
			[]byte(lastDN)))
}

// decodeCookie reads a resume point.
//
// Reports whether the cookie was understood. An empty cookie is
// the start of a search and is understood; anything else that is
// not ours is not, and the caller answers
// unwillingToPerform — refusing beats resuming from a position we
// cannot interpret, which would silently return the wrong page.
func decodeCookie(cookie []byte) (string, bool) {
	if len(cookie) == 0 {
		return "", true
	}
	text := string(cookie)
	if !strings.HasPrefix(text, cookiePrefix) {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(
		strings.TrimPrefix(text, cookiePrefix))
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// pagedResponse builds the response control for a page.
//
// The size is zero: it is the server's estimate of the result set,
// and slapd sends zero rather than counting. An empty cookie means
// this was the last page.
func pagedResponse(lastDN string) (ldap.Control, error) {
	value, err := ldap.Paged{
		Cookie: encodeCookie(lastDN),
	}.Encode()
	if err != nil {
		return ldap.Control{}, err
	}
	return ldap.Control{
		OID:      ldap.OIDPagedResults,
		Value:    value,
		HasValue: true,
	}, nil
}

// page returns one page of results and the cookie for the next.
//
// The entries arrive ordered by DN, so a cookie naming the last DN
// of a page resumes exactly after it. A page size of zero means
// the client is ending the paged search, which RFC 2696 2 allows,
// and the answer is an empty page with an empty cookie.
func (s *Store) page(
	entries []ldap.SearchEntry, paged ldap.Paged,
) ([]ldap.SearchEntry, ldap.Result, []ldap.Control) {
	after, ok := decodeCookie(paged.Cookie)
	if !ok {
		return nil, ldap.Result{
			Code: ldap.UnwillingToPerform,
			Diagnostic: "unrecognised paged " +
				"results cookie",
		}, nil
	}
	rest := skipPast(entries, after)
	if paged.Size <= 0 {
		res, controls := closedPage()
		return nil, res, controls
	}
	if int32(len(rest)) <= paged.Size {
		// The last page: an empty cookie says so.
		res, controls := closedPage()
		return rest, res, controls
	}
	out := rest[:paged.Size]
	control, err := pagedResponse(out[len(out)-1].DN)
	if err != nil {
		return nil, ldap.Result{Code: ldap.Other}, nil
	}
	return out, ldap.Result{Code: ldap.Success},
		[]ldap.Control{control}
}

// closedPage is the result and control for a final page.
func closedPage() (ldap.Result, []ldap.Control) {
	control, err := pagedResponse("")
	if err != nil {
		return ldap.Result{Code: ldap.Other}, nil
	}
	return ldap.Result{Code: ldap.Success},
		[]ldap.Control{control}
}

// skipPast drops the entries up to and including after.
//
// Comparing DNs rather than counting is what makes the cookie
// survive a change between pages: an entry deleted behind the
// cursor shifts no offsets.
func skipPast(
	entries []ldap.SearchEntry, after string,
) []ldap.SearchEntry {
	if after == "" {
		return entries
	}
	for i, e := range entries {
		if e.DN == after {
			return entries[i+1:]
		}
	}
	// The cookie's entry is gone. Resuming from the first entry
	// that sorts after it keeps the sequence monotonic rather
	// than restarting the search.
	for i, e := range entries {
		if e.DN > after {
			return entries[i:]
		}
	}
	return nil
}
