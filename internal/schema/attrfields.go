package schema

import "strings"

// attrValued handles the fields that take a value.
func (p *parser) attrValued(
	at *AttributeType, kw string,
) (bool, error) {
	switch kw {
	case "NAME":
		p.next()
		names, err := p.qdescrs()
		at.Names = names
		return false, err
	case "DESC":
		p.next()
		desc, err := p.qdstring()
		at.Desc = desc
		return false, err
	case "SUP", "EQUALITY", "ORDERING", "SUBSTR":
		p.next()
		return false, p.one(attrSlot(at, kw))
	case "SYNTAX":
		p.next()
		oid, n, err := p.noidlen()
		at.SyntaxOID, at.SyntaxLen = oid, n
		return false, err
	case "USAGE":
		p.next()
		return false, p.usage(&at.Usage)
	}
	// An unknown keyword is an extension (X-...) or something
	// this version does not model. slapd keeps extensions
	// rather than refusing the definition, so skipping is the
	// compatible behaviour.
	return p.skipExtension()
}

// attrSlot picks the field an OID-valued keyword fills.
func attrSlot(at *AttributeType, kw string) *string {
	switch kw {
	case "SUP":
		return &at.SuperiorOID
	case "EQUALITY":
		return &at.EqualityOID
	case "ORDERING":
		return &at.OrderingOID
	}
	return &at.SubstrOID
}

// one reads a single OID into dst. A quoted OID is accepted
// for the same reason noidlen accepts one.
func (p *parser) one(dst *string) error {
	t := p.peek()
	if t.kind != tokBare && t.kind != tokQString {
		return ErrSyntax
	}
	p.next()
	*dst = t.text
	return nil
}

// usage reads a USAGE value.
func (p *parser) usage(dst *Usage) error {
	t, err := p.expect(tokBare)
	if err != nil {
		return err
	}
	switch strings.ToLower(t.text) {
	case "userapplications":
		*dst = UserApplications
	case "directoryoperation":
		*dst = DirectoryOperation
	case "distributedoperation":
		*dst = DistributedOperation
	case "dsaoperation":
		*dst = DSAOperation
	default:
		return ErrSyntax
	}
	return nil
}

// skipExtension consumes an unrecognised keyword and whatever
// value follows it, reporting whether the definition ended.
func (p *parser) skipExtension() (bool, error) {
	p.next()
	switch p.peek().kind {
	case tokEOF:
		return true, nil
	case tokRParen:
		return true, nil
	case tokLParen:
		_, err := p.qdescrs()
		return false, err
	default:
		p.next()
		return false, nil
	}
}
