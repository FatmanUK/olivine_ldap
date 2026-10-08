package acl

import (
	"errors"
	"fmt"
	"strings"
)

var ErrSyntax = errors.New("acl: malformed access directive")

// Parse reads slapd's access directives.
//
// The grammar is slapd.access(5):
//
//	access to <what> [ by <who> <level> ]+
//
// Continuation lines are indented, as in slapd.conf. Rules apply
// in the order given, which is the whole of their semantics: the
// first matching clause decides and later ones are not consulted.
func Parse(text string) (*Policy, error) {
	p := NewPolicy()
	for _, directive := range splitDirectives(text) {
		rule, err := parseRule(directive)
		if err != nil {
			return nil, err
		}
		p.Rules = append(p.Rules, rule)
	}
	return p, nil
}

// splitDirectives groups the text into one string per `access`
// directive, joining indented continuations.
func splitDirectives(text string) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(text, "\n") {
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indented := line[0] == ' ' || line[0] == '\t'
		if !indented && cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
		cur.WriteString(" ")
		cur.WriteString(strings.TrimSpace(line))
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// stripComment removes a # comment outside quotes.
func stripComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}

// parseRule reads one `access to ... by ...` directive.
func parseRule(directive string) (Rule, error) {
	fields, err := tokenise(directive)
	if err != nil {
		return Rule{}, err
	}
	if len(fields) < 3 ||
		!strings.EqualFold(fields[0], "access") ||
		!strings.EqualFold(fields[1], "to") {
		return Rule{}, fmt.Errorf(
			"%w: expected `access to`: %.40s",
			ErrSyntax, directive)
	}
	rest := fields[2:]
	what, rest, err := parseWhat(rest)
	if err != nil {
		return Rule{}, err
	}
	bys, err := parseBys(rest)
	if err != nil {
		return Rule{}, err
	}
	return Rule{What: what, By: bys}, nil
}
