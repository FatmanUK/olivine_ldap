package acl

import (
	"fmt"
	"strings"
)

// parseWhat reads the `to` target, returning what is left.
func parseWhat(
	fields []string,
) (What, []string, error) {
	var w What
	for len(fields) > 0 {
		f := fields[0]
		if strings.EqualFold(f, "by") {
			break
		}
		if f == "*" {
			fields = fields[1:]
			continue
		}
		if err := applyWhatField(&w, f); err != nil {
			return w, nil, err
		}
		fields = fields[1:]
	}
	return w, fields, nil
}

// applyWhatField reads one `dn[.style]=` or `attrs=` term.
func applyWhatField(w *What, f string) error {
	key, value, found := strings.Cut(f, "=")
	if !found {
		return fmt.Errorf("%w: expected key=value: %q",
			ErrSyntax, f)
	}
	base, style, err := splitStyle(key)
	if err != nil {
		return err
	}
	switch strings.ToLower(base) {
	case "dn":
		w.HasDN = true
		w.DN = unquote(value)
		w.Style = style
	case "attrs", "attr":
		w.Attrs = append(w.Attrs,
			strings.Split(unquote(value), ",")...)
	case "filter":
		// Recognised and refused rather than ignored: a
		// filter clause that silently matched everything
		// would widen access, which is the wrong way for a
		// gap in an access-control implementation to fail.
		return fmt.Errorf(
			"%w: filter= is not implemented", ErrSyntax)
	default:
		return fmt.Errorf("%w: unknown selector %q",
			ErrSyntax, base)
	}
	return nil
}

// splitStyle separates a `.style` suffix from a selector.
func splitStyle(key string) (string, Style, error) {
	base, name, found := strings.Cut(key, ".")
	if !found {
		return base, StyleBase, nil
	}
	switch strings.ToLower(name) {
	case "base", "exact", "baseobject":
		return base, StyleBase, nil
	case "one", "onelevel":
		return base, StyleOne, nil
	case "sub", "subtree":
		return base, StyleSubtree, nil
	case "children":
		return base, StyleChildren, nil
	}
	// regex and the various expand styles are not
	// implemented. Refusing beats guessing: a style treated as
	// `base` by mistake would grant access to the wrong DNs.
	return base, StyleBase, fmt.Errorf(
		"%w: unsupported style %q", ErrSyntax, name)
}

// unquote strips surrounding double quotes.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' &&
		s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
