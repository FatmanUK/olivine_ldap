package ldap

import "github.com/FatmanUK/olivine_ldap/internal/ber"

// readAttributeList reads a SEQUENCE OF Attribute, where each
// is a type and a SET OF value.
func readAttributeList(
	content []byte,
) ([]AttributeChange, error) {
	var out []AttributeChange
	d := ber.NewDecoder(content)
	for !d.Done() {
		_, item, err := d.Next()
		if err != nil {
			return nil, ErrBadRequest
		}
		a, err := readAttribute(item)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// readAttribute reads one type and its values.
func readAttribute(
	item []byte,
) (AttributeChange, error) {
	var a AttributeChange
	d := ber.NewDecoder(item)
	typ, err := nextString(d)
	if err != nil {
		return a, err
	}
	a.Type = typ
	_, vals, err := d.Next()
	if err != nil {
		return a, ErrBadRequest
	}
	a.Values, err = readStringList(vals)
	return a, err
}

// ModifyOp is one modification's kind, RFC 4511 4.6.
type ModifyOp int32

const (
	ModifyAdd     ModifyOp = 0
	ModifyDelete  ModifyOp = 1
	ModifyReplace ModifyOp = 2
)

// Modification is one change within a ModifyRequest.
type Modification struct {
	Op        ModifyOp
	Attribute AttributeChange
}

// ModifyRequest is RFC 4511 4.6.
type ModifyRequest struct {
	Object        string
	Modifications []Modification
}

// ParseModifyRequest decodes a ModifyRequest body.
func ParseModifyRequest(
	body []byte,
) (*ModifyRequest, error) {
	d := ber.NewDecoder(body)
	object, err := nextString(d)
	if err != nil {
		return nil, err
	}
	_, list, err := d.Next()
	if err != nil {
		return nil, ErrBadRequest
	}
	mods, err := readModifications(list)
	if err != nil {
		return nil, err
	}
	return &ModifyRequest{
		Object: object, Modifications: mods,
	}, nil
}

// readModifications reads the SEQUENCE OF modification.
func readModifications(
	content []byte,
) ([]Modification, error) {
	var out []Modification
	d := ber.NewDecoder(content)
	for !d.Done() {
		_, item, err := d.Next()
		if err != nil {
			return nil, ErrBadRequest
		}
		m, err := readModification(item)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// readModification reads one operation and its attribute.
func readModification(
	item []byte,
) (Modification, error) {
	var m Modification
	d := ber.NewDecoder(item)
	op, err := nextInt(d)
	if err != nil {
		return m, err
	}
	m.Op = ModifyOp(op)
	_, attr, err := d.Next()
	if err != nil {
		return m, ErrBadRequest
	}
	m.Attribute, err = readAttribute(attr)
	return m, err
}
