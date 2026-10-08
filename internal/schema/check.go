package schema

import (
	"fmt"
	"strings"
)

// Violation is a schema check failure, carrying the result code
// slapd uses for it.
//
// The codes were taken from slapd rather than guessed, by adding
// deliberately bad entries to the oracle. One is genuinely
// surprising: an *undefined* objectClass is invalidSyntax (21),
// not objectClassViolation (65), because slapd validates the
// attribute's value against the objectClass syntax before it
// ever considers the class hierarchy.
type Violation struct {
	// Code is the LDAP result code, as an int32 to avoid a
	// dependency on internal/ldap from here.
	Code int32
	Text string
}

// Error implements error.
func (v *Violation) Error() string { return v.Text }

// Result codes used by the checks, from include/ldap.h.
const (
	codeUndefinedType        int32 = 0x11
	codeInvalidSyntax        int32 = 0x15
	codeObjectClassViolation int32 = 0x41
)

// Entry is what a schema check examines: attribute types already
// resolved to canonical names, with their values.
type Entry struct {
	// Attributes maps a canonical, lower-cased type to values.
	Attributes map[string][]string
}

// ObjectClassAttr is the attribute naming an entry's classes.
const ObjectClassAttr = "objectclass"

// Check validates an entry against the schema.
//
// Order matters, and follows what the oracle does: undefined
// types first, then the object classes themselves, then the
// structural chain, then MUST, then what is allowed. Checking
// MUST before the classes resolve would report the wrong thing.
func (r *Registry) Check(e Entry) error {
	if err := r.checkTypesDefined(e); err != nil {
		return err
	}
	classes, err := r.resolveClasses(e)
	if err != nil {
		return err
	}
	if err := r.checkStructural(classes); err != nil {
		return err
	}
	allowed, required := r.collect(classes)
	if err := checkRequired(e, required); err != nil {
		return err
	}
	return checkAllowed(e, allowed)
}

// checkTypesDefined refuses an attribute no schema defines.
func (r *Registry) checkTypesDefined(e Entry) error {
	for typ := range e.Attributes {
		if _, ok := r.AttributeType(typ); !ok {
			return &Violation{
				Code: codeUndefinedType,
				Text: typ +
					": attribute type undefined",
			}
		}
	}
	return nil
}

// resolveClasses looks up every objectClass value.
//
// An unresolvable one is invalidSyntax, matching slapd's
// "objectClass: value #0 invalid per syntax".
func (r *Registry) resolveClasses(
	e Entry,
) ([]*ObjectClass, error) {
	values := e.Attributes[ObjectClassAttr]
	if len(values) == 0 {
		return nil, &Violation{
			Code: codeObjectClassViolation,
			Text: "no structural object class provided",
		}
	}
	out := make([]*ObjectClass, 0, len(values))
	for i, v := range values {
		oc, ok := r.ObjectClass(v)
		if !ok {
			return nil, badClassValue(i)
		}
		out = append(out, oc)
	}
	return out, nil
}

// badClassValue is slapd's diagnostic for an objectClass value
// that names no defined class.
func badClassValue(i int) *Violation {
	return &Violation{
		Code: codeInvalidSyntax,
		Text: fmt.Sprintf(
			"objectClass: value #%d invalid per syntax",
			i),
	}
}

// collect gathers the MUST and MAY sets of the classes and their
// superiors, lower-cased.
func (r *Registry) collect(
	classes []*ObjectClass,
) (allowed, required map[string]string) {
	allowed = map[string]string{}
	required = map[string]string{}
	for _, oc := range classes {
		r.walkClass(oc, allowed, required, 0)
	}
	return allowed, required
}

// walkClass folds one class and its superiors into the sets. The
// value recorded is the class that contributed the attribute, so
// a diagnostic can name it as slapd's does.
func (r *Registry) walkClass(
	oc *ObjectClass, allowed, required map[string]string,
	depth int,
) {
	if oc == nil || depth > 16 {
		return
	}
	name := classNameOf(oc)
	for _, a := range oc.Must {
		key := strings.ToLower(a)
		required[key] = name
		allowed[key] = name
	}
	for _, a := range oc.May {
		allowed[strings.ToLower(a)] = name
	}
	for _, sup := range oc.SuperiorOIDs {
		if parent, ok := r.ObjectClass(sup); ok {
			r.walkClass(parent, allowed, required,
				depth+1)
		}
	}
}

// classNameOf is an object class's first name, or its OID.
func classNameOf(oc *ObjectClass) string {
	if len(oc.Names) > 0 {
		return oc.Names[0]
	}
	return oc.OID
}
