package schema

import (
	"strconv"
	"strings"
)

// parser walks a lexed description.
type parser struct {
	toks []token
	pos  int
}

// peek returns the current token.
func (p *parser) peek() token {
	return p.toks[p.pos]
}

// next consumes and returns the current token.
func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tokEOF {
		p.pos++
	}
	return t
}

// expect consumes a token of kind k.
func (p *parser) expect(k kind) (token, error) {
	t := p.peek()
	if t.kind != k {
		return t, ErrSyntax
	}
	return p.next(), nil
}

// keyword returns the current token's text uppercased if it is
// a bare word, else the empty string.
func (p *parser) keyword() string {
	t := p.peek()
	if t.kind != tokBare {
		return ""
	}
	return strings.ToUpper(t.text)
}

// qdescrs reads either one name or a parenthesised list.
//
//	NAME 'cn'
//	NAME ( 'sn' 'surname' )
func (p *parser) qdescrs() ([]string, error) {
	if p.peek().kind != tokLParen {
		t := p.next()
		return []string{t.text}, nil
	}
	p.next()
	var out []string
	for {
		switch p.peek().kind {
		case tokRParen:
			p.next()
			return out, nil
		case tokEOF:
			return nil, ErrSyntax
		case tokDollar:
			p.next()
		default:
			out = append(out, p.next().text)
		}
	}
}

// oids reads one OID or a parenthesised $-separated list.
//
//	SUP top
//	MUST ( sn $ cn )
func (p *parser) oids() ([]string, error) {
	return p.qdescrs()
}

// noidlen reads a syntax OID with an optional {len} suffix.
//
// The suffix is an upper bound on value length and is advisory:
// slapd parses and records it. It is split off here so the OID
// can be looked up.
func (p *parser) noidlen() (string, int, error) {
	t := p.peek()
	// msuser.schema writes SYNTAX '1.3.6.1...' in quotes,
	// which the ABNF does not allow and slapd accepts.
	if t.kind != tokBare && t.kind != tokQString {
		return "", 0, ErrSyntax
	}
	p.next()
	oid, n := splitLen(t.text)
	return oid, n, nil
}

// splitLen separates a trailing {len} from an OID.
func splitLen(s string) (string, int) {
	open := strings.IndexByte(s, '{')
	if open < 0 || !strings.HasSuffix(s, "}") {
		return s, 0
	}
	n, err := strconv.Atoi(s[open+1 : len(s)-1])
	if err != nil {
		return s, 0
	}
	return s[:open], n
}

// qdstring reads a quoted description.
func (p *parser) qdstring() (string, error) {
	t := p.next()
	if t.kind != tokQString && t.kind != tokBare {
		return "", ErrSyntax
	}
	return t.text, nil
}
