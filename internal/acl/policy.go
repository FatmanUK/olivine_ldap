package acl

import "strings"

// WhoKind is the sort of requester a `by` clause names.
type WhoKind int

const (
	// WhoAll is `*`: anyone, bound or not.
	WhoAll WhoKind = iota
	// WhoAnonymous matches only an unbound connection.
	WhoAnonymous
	// WhoUsers matches any bound connection.
	WhoUsers
	// WhoSelf matches when the target is the requester.
	WhoSelf
	// WhoDN matches a DN pattern.
	WhoDN
)

// Who is a `by` clause's subject.
type Who struct {
	Kind  WhoKind
	DN    string
	Style Style
}

// By is one `by <who> <level>` clause.
type By struct {
	Who   Who
	Level Level
}

// What is an `access to` clause's target.
//
// An empty Attrs matches every attribute, including the `entry`
// pseudo-attribute.
type What struct {
	HasDN bool
	DN    string
	Style Style
	Attrs []string
}

// Rule is one access clause and its by-clauses in order.
type Rule struct {
	What What
	By   []By
}

// Policy is an ordered list of rules plus the default.
type Policy struct {
	Rules []Rule
	// Default applies when no rule's What matches. slapd's is
	// read (frontend.c:99); NewPolicy sets it.
	Default Level
}

// NewPolicy returns an empty policy with slapd's default.
func NewPolicy() *Policy {
	return &Policy{Default: Read}
}

// Level returns the access the policy grants for req.
//
// The first rule whose What matches decides, and within it the
// first matching By. A rule that matches with no matching By
// denies: that is the behaviour the oracle showed, where
// `access to * by dn="cn=nobody,..." read` left an anonymous
// base search answering noSuchObject rather than falling through
// to the default.
func (p *Policy) Level(req Request) Level {
	for i := range p.Rules {
		r := &p.Rules[i]
		if !r.What.matches(req) {
			continue
		}
		for _, b := range r.By {
			if b.Who.matches(req) {
				return b.Level
			}
		}
		return None
	}
	return p.Default
}

// Allows reports whether the policy grants at least need.
//
// Levels are cumulative, so Read satisfies Search.
func (p *Policy) Allows(req Request, need Level) bool {
	return p.Level(req) >= need
}

// matches reports whether a What selects this request.
func (w *What) matches(req Request) bool {
	if w.HasDN && !matchDN(w.DN, w.Style, req.TargetDN) {
		return false
	}
	if len(w.Attrs) == 0 {
		return true
	}
	for _, a := range w.Attrs {
		if strings.EqualFold(a, req.Attribute) {
			return true
		}
	}
	return false
}

// matches reports whether a Who names this requester.
func (w *Who) matches(req Request) bool {
	switch w.Kind {
	case WhoAll:
		return true
	case WhoAnonymous:
		return req.Anonymous()
	case WhoUsers:
		return !req.Anonymous()
	case WhoSelf:
		return !req.Anonymous() &&
			req.BoundDN == req.TargetDN
	case WhoDN:
		return !req.Anonymous() &&
			matchDN(w.DN, w.Style, req.BoundDN)
	}
	return false
}
