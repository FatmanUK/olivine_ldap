package schema

import (
	"fmt"
	"sort"
	"strings"
)

// checkStructural enforces exactly one structural class chain.
//
// Several structural classes are fine when they form a chain —
// person and organizationalPerson, say — because the subordinate
// one implies its superiors. Two unrelated ones are not, and
// slapd says so as
// "invalid structural object class chain (a/b)".
func (r *Registry) checkStructural(
	classes []*ObjectClass,
) error {
	var structural []*ObjectClass
	for _, oc := range classes {
		if oc.Kind == Structural {
			structural = append(structural, oc)
		}
	}
	if len(structural) == 0 {
		return &Violation{
			Code: codeObjectClassViolation,
			Text: "no structural object class provided",
		}
	}
	tip := r.chainTip(structural)
	if tip == nil {
		return &Violation{
			Code: codeObjectClassViolation,
			Text: chainError(structural),
		}
	}
	return nil
}

// chainTip returns the one structural class descended from all
// the others, or nil when they do not form a single chain.
func (r *Registry) chainTip(
	structural []*ObjectClass,
) *ObjectClass {
	for _, candidate := range structural {
		ok := true
		for _, other := range structural {
			if candidate == other {
				continue
			}
			if !r.descendsFrom(candidate, other) {
				ok = false
				break
			}
		}
		if ok {
			return candidate
		}
	}
	return nil
}

// descendsFrom reports whether oc is other, or inherits from it.
func (r *Registry) descendsFrom(
	oc, other *ObjectClass,
) bool {
	return r.descends(oc, other, 0)
}

// descends walks the SUP chain with a depth limit, since a
// looping schema would otherwise hang the server.
func (r *Registry) descends(
	oc, other *ObjectClass, depth int,
) bool {
	if oc == nil || depth > 16 {
		return false
	}
	if oc == other {
		return true
	}
	for _, sup := range oc.SuperiorOIDs {
		parent, ok := r.ObjectClass(sup)
		if !ok {
			continue
		}
		if r.descends(parent, other, depth+1) {
			return true
		}
	}
	return false
}

// chainError renders slapd's diagnostic for an invalid chain.
func chainError(structural []*ObjectClass) string {
	names := make([]string, 0, len(structural))
	for _, oc := range structural {
		names = append(names, classNameOf(oc))
	}
	return fmt.Sprintf(
		"invalid structural object class chain (%s)",
		strings.Join(names, "/"))
}

// checkRequired enforces the MUST attributes.
func checkRequired(e Entry, required map[string]string) error {
	missing := make([]string, 0, len(required))
	for attr := range required {
		if len(e.Attributes[attr]) == 0 {
			missing = append(missing, attr)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	// Sorted so the diagnostic is stable; map order is not.
	sort.Strings(missing)
	attr := missing[0]
	return &Violation{
		Code: codeObjectClassViolation,
		Text: fmt.Sprintf(
			"object class '%s' requires attribute '%s'",
			required[attr], attr),
	}
}

// checkAllowed refuses an attribute no class permits.
func checkAllowed(e Entry, allowed map[string]string) error {
	extra := make([]string, 0, len(e.Attributes))
	for attr := range e.Attributes {
		if attr == ObjectClassAttr {
			continue
		}
		if _, ok := allowed[attr]; !ok {
			extra = append(extra, attr)
		}
	}
	if len(extra) == 0 {
		return nil
	}
	sort.Strings(extra)
	return &Violation{
		Code: codeObjectClassViolation,
		Text: fmt.Sprintf("attribute '%s' not allowed",
			extra[0]),
	}
}
