package schema

import "strings"

// Kind is an object class's kind, RFC 4512 4.1.1.
type Kind int

const (
	Structural Kind = iota
	Abstract
	Auxiliary
)

// String names the kind as a schema description spells it.
func (k Kind) String() string {
	switch k {
	case Abstract:
		return "ABSTRACT"
	case Auxiliary:
		return "AUXILIARY"
	}
	return "STRUCTURAL"
}

// ObjectClass is one object class definition.
//
// Ported from servers/slapd/oc.c.
type ObjectClass struct {
	OID          string
	Names        []string
	Desc         string
	Obsolete     bool
	SuperiorOIDs []string
	Kind         Kind
	Must         []string
	May          []string
}

// ParseObjectClass parses an ObjectClassDescription.
func ParseObjectClass(s string) (*ObjectClass, error) {
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
	// STRUCTURAL is the default when no kind is given,
	// RFC 4512 4.1.1.
	oc := &ObjectClass{OID: oidTok.text, Kind: Structural}
	if err := p.ocFields(oc); err != nil {
		return nil, err
	}
	_, err = p.expect(tokRParen)
	return oc, err
}

// ocFields reads the optional fields of an object class.
func (p *parser) ocFields(oc *ObjectClass) error {
	for {
		kw := p.keyword()
		if kw == "" {
			return nil
		}
		done, err := p.ocField(oc, kw)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// ocField reads one field, reporting whether the definition is
// finished.
func (p *parser) ocField(
	oc *ObjectClass, kw string,
) (bool, error) {
	switch kw {
	case "OBSOLETE":
		p.next()
		oc.Obsolete = true
		return false, nil
	case "ABSTRACT", "STRUCTURAL", "AUXILIARY":
		p.next()
		oc.Kind = kindOf(kw)
		return false, nil
	case "NAME":
		p.next()
		names, err := p.qdescrs()
		oc.Names = names
		return false, err
	case "DESC":
		p.next()
		desc, err := p.qdstring()
		oc.Desc = desc
		return false, err
	case "SUP", "MUST", "MAY":
		p.next()
		list, err := p.oids()
		*ocSlot(oc, kw) = list
		return false, err
	}
	return p.skipExtension()
}

// kindOf maps a kind keyword to a Kind.
func kindOf(kw string) Kind {
	switch strings.ToUpper(kw) {
	case "ABSTRACT":
		return Abstract
	case "AUXILIARY":
		return Auxiliary
	}
	return Structural
}

// ocSlot picks the field a list-valued keyword fills.
func ocSlot(oc *ObjectClass, kw string) *[]string {
	switch kw {
	case "SUP":
		return &oc.SuperiorOIDs
	case "MUST":
		return &oc.Must
	}
	return &oc.May
}
