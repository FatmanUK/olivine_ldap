package schema

import (
	"fmt"
	"strings"
)

// macros holds OpenLDAP's OID macros.
//
// A .schema file may declare one with
//
//	objectIdentifier DynGroupBase 1.3.6.1.4.1.4203.666.4
//	objectIdentifier DynGroupAttr DynGroupBase:1
//
// and then use DynGroupAttr:3 as a definition's OID. The
// declarations nest, so resolution is recursive. This is an
// OpenLDAP extension and not RFC 4512.
type macros map[string]string

// define records one objectIdentifier declaration.
//
// The value may itself be a macro reference, and a macro may be
// declared before the one it refers to is used but not before
// the one it refers to is declared, which is why this resolves
// eagerly.
func (m macros) define(name, value string) error {
	key := strings.ToLower(name)
	// slapd refuses a redefinition:
	//
	//	dsee.schema: line 25 objectidentifier:
	//	"NetscapeRoot" previously defined
	//	"2.16.840.1.113730"
	//
	// which is how upstream ships two schema files that
	// cannot be loaded together — dsee.schema and
	// dyngroup.schema both define NetscapeRoot. Matching the
	// refusal keeps that visible rather than silently
	// preferring whichever loaded last.
	if prev, dup := m[key]; dup {
		return fmt.Errorf(
			"%w: OID macro %q previously defined %q",
			ErrDup, name, prev)
	}
	resolved, err := m.resolve(value)
	if err != nil {
		return err
	}
	m[key] = resolved
	return nil
}

// resolve expands a possible macro reference into a dotted OID.
//
// A plain numeric OID passes through untouched, so this is safe
// to call on every definition's OID.
func (m macros) resolve(s string) (string, error) {
	name, suffix, found := strings.Cut(s, ":")
	if !found {
		return s, nil
	}
	base, ok := m[strings.ToLower(name)]
	if !ok {
		return "", fmt.Errorf(
			"%w: undefined OID macro %q", ErrSyntax, name)
	}
	if suffix == "" {
		return base, nil
	}
	return base + "." + suffix, nil
}
