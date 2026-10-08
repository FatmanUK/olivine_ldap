package acl

import (
	"fmt"
	"strings"
)

// parseBys reads the `by <who> <level>` clauses.
//
// A directive with no `by` clause at all denies everything the
// What selects, which is what slapd does: the clause matches and
// nothing within it grants.
func parseBys(fields []string) ([]By, error) {
	var out []By
	for len(fields) > 0 {
		if !strings.EqualFold(fields[0], "by") {
			return nil, fmt.Errorf(
				"%w: expected `by`, got %q",
				ErrSyntax, fields[0])
		}
		fields = fields[1:]
		if len(fields) == 0 {
			return nil, fmt.Errorf(
				"%w: `by` with no subject", ErrSyntax)
		}
		who, err := parseWho(fields[0])
		if err != nil {
			return nil, err
		}
		fields = fields[1:]
		level, rest, err := parseLevel(fields)
		if err != nil {
			return nil, err
		}
		out = append(out, By{Who: who, Level: level})
		fields = rest
	}
	return out, nil
}

// parseWho reads one `by` subject.
func parseWho(f string) (Who, error) {
	switch strings.ToLower(f) {
	case "*":
		return Who{Kind: WhoAll}, nil
	case "anonymous":
		return Who{Kind: WhoAnonymous}, nil
	case "users":
		return Who{Kind: WhoUsers}, nil
	case "self":
		return Who{Kind: WhoSelf}, nil
	}
	key, value, found := strings.Cut(f, "=")
	if !found {
		return Who{}, fmt.Errorf(
			"%w: unknown subject %q", ErrSyntax, f)
	}
	base, style, err := splitStyle(key)
	if err != nil {
		return Who{}, err
	}
	if !strings.EqualFold(base, "dn") {
		// group=, set=, ssf= and the rest are not
		// implemented, and are refused rather than ignored:
		// an unrecognised subject treated as a match would
		// grant access it should not.
		return Who{}, fmt.Errorf(
			"%w: subject %q is not implemented",
			ErrSyntax, base)
	}
	return Who{
		Kind: WhoDN, DN: unquote(value), Style: style,
	}, nil
}

// parseLevel reads an access level, returning what is left.
//
// slapd also accepts privilege sets — `=wrscxd` and the +/-
// forms. Those are refused for now rather than approximated,
// since a misread privilege set silently grants the wrong thing.
func parseLevel(
	fields []string,
) (Level, []string, error) {
	if len(fields) == 0 {
		// `by <who>` with no level means +0 in slapd: no
		// access, and the clause still stops evaluation.
		return None, nil, nil
	}
	l, ok := levelByName(fields[0])
	if !ok {
		return None, nil, fmt.Errorf(
			"%w: unknown access level %q",
			ErrSyntax, fields[0])
	}
	rest := fields[1:]
	// A control keyword may follow. Only `stop` is the default
	// behaviour; the others change evaluation order and are
	// refused rather than silently ignored.
	if len(rest) > 0 && isControl(rest[0]) {
		if !strings.EqualFold(rest[0], "stop") {
			return None, nil, fmt.Errorf(
				"%w: control %q is not implemented",
				ErrSyntax, rest[0])
		}
		rest = rest[1:]
	}
	return l, rest, nil
}

// isControl reports whether f is an evaluation control.
func isControl(f string) bool {
	switch strings.ToLower(f) {
	case "stop", "continue", "break":
		return true
	}
	return false
}

// levelByName maps a level keyword.
func levelByName(f string) (Level, bool) {
	switch strings.ToLower(f) {
	case "none":
		return None, true
	case "disclose":
		return Disclose, true
	case "auth":
		return Auth, true
	case "compare":
		return Compare, true
	case "search":
		return Search, true
	case "read":
		return Read, true
	case "write", "add", "delete":
		return Write, true
	case "manage":
		return Manage, true
	}
	return 0, false
}
