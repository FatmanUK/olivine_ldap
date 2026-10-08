package schema

// Usage is an attribute type's usage, RFC 4512 4.1.2.
type Usage int

const (
	UserApplications Usage = iota
	DirectoryOperation
	DistributedOperation
	DSAOperation
)

// AttributeType is one attribute type definition.
//
// Ported from servers/slapd/at.c and the hardcoded table in
// schema_init.c.
type AttributeType struct {
	OID                string
	Names              []string
	Desc               string
	Obsolete           bool
	SuperiorOID        string
	EqualityOID        string
	OrderingOID        string
	SubstrOID          string
	SyntaxOID          string
	SyntaxLen          int
	SingleValue        bool
	Collective         bool
	NoUserModification bool
	Usage              Usage
}

// ParseAttributeType parses an AttributeTypeDescription.
func ParseAttributeType(s string) (*AttributeType, error) {
	toks, err := lex(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	if _, err := p.expect(tokLParen); err != nil {
		return nil, err
	}
	oidTok, err := p.expect(tokBare)
	if err != nil {
		return nil, ErrNoOID
	}
	at := &AttributeType{OID: oidTok.text}
	if err := p.attrFields(at); err != nil {
		return nil, err
	}
	_, err = p.expect(tokRParen)
	return at, err
}

// attrFields reads the optional fields of an attribute type.
func (p *parser) attrFields(at *AttributeType) error {
	for {
		kw := p.keyword()
		if kw == "" {
			return nil
		}
		done, err := p.attrField(at, kw)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// attrField reads one field, reporting whether the definition
// is finished.
func (p *parser) attrField(
	at *AttributeType, kw string,
) (bool, error) {
	if p.attrFlag(at, kw) {
		return false, nil
	}
	return p.attrValued(at, kw)
}

// attrFlag handles the valueless fields.
func (p *parser) attrFlag(
	at *AttributeType, kw string,
) bool {
	switch kw {
	case "OBSOLETE":
		at.Obsolete = true
	case "SINGLE-VALUE":
		at.SingleValue = true
	case "COLLECTIVE":
		at.Collective = true
	case "NO-USER-MODIFICATION":
		at.NoUserModification = true
	default:
		return false
	}
	p.next()
	return true
}
