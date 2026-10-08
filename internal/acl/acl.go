// Package acl implements slapd's access control.
//
// Ported from servers/slapd/acl.c and aclparse.c. The semantics
// below were established against the oracle rather than read off
// the manual page, because several are counter-intuitive:
//
//   - The default, when no `access to` clause matches at all, is
//     *read* (frontend.c:99, be_dfltaccess = ACL_READ).
//   - When a clause matches but none of its `by` clauses does,
//     access is denied — not defaulted.
//   - `disclose` is the switch between hiding and admitting: with
//     it, an unreadable entry answers insufficientAccess; without
//     it, noSuchObject.
//   - Selection is per attribute, so one clause can hide
//     `description` while a later one grants everything else.
package acl

// Level is an access level, from slap.h:1263-1270. The order is
// the point: each level includes the ones below it, so a grant of
// Read satisfies a need for Search.
type Level int

const (
	None Level = iota
	Disclose
	Auth
	Compare
	Search
	Read
	Write
	Manage
)

// String names the level as slapd.access(5) spells it.
func (l Level) String() string {
	switch l {
	case Disclose:
		return "disclose"
	case Auth:
		return "auth"
	case Compare:
		return "compare"
	case Search:
		return "search"
	case Read:
		return "read"
	case Write:
		return "write"
	case Manage:
		return "manage"
	}
	return "none"
}

// Style is how a dn clause matches, from slapd.access(5).
type Style int

const (
	// StyleBase is `exact` and `base`: the DN itself.
	StyleBase Style = iota
	// StyleOne is immediate children only.
	StyleOne
	// StyleSubtree is the DN and everything beneath it.
	StyleSubtree
	// StyleChildren is everything beneath but not the DN.
	StyleChildren
)

// EntryAttribute is slapd's pseudo-attribute for entry-level
// access, as in `access to attrs=entry`.
const EntryAttribute = "entry"

// Request is one access question.
type Request struct {
	// TargetDN is the normalised DN being accessed.
	TargetDN string
	// Attribute is the normalised attribute type, or
	// EntryAttribute for the entry itself.
	Attribute string
	// BoundDN is the normalised authenticated identity, empty
	// when the connection is anonymous.
	BoundDN string
}

// Anonymous reports whether the requester has not bound.
func (r Request) Anonymous() bool {
	return r.BoundDN == ""
}
