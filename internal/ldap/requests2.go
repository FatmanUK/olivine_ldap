package ldap

import "github.com/FatmanUK/openldap_olivine/internal/ber"

// BindRequest is RFC 4511 4.2.
type BindRequest struct {
	Version int32
	Name    string
	// Simple is the password on a simple bind. SASL is an
	// open question (plan step 8); Mechanism is set when the
	// choice was SASL so a caller can refuse it precisely.
	Simple    string
	IsSASL    bool
	Mechanism string
}

// ParseBindRequest decodes a BindRequest body.
func ParseBindRequest(body []byte) (*BindRequest, error) {
	d := ber.NewDecoder(body)
	version, err := nextInt(d)
	if err != nil {
		return nil, err
	}
	name, err := nextString(d)
	if err != nil {
		return nil, err
	}
	r := &BindRequest{Version: version, Name: name}
	tag, content, err := d.Next()
	if err != nil {
		return nil, ErrBadRequest
	}
	switch tag {
	case AuthSimple:
		r.Simple = string(content)
	case AuthSASL:
		r.IsSASL = true
		sd := ber.NewDecoder(content)
		mech, err := nextString(sd)
		if err != nil {
			return nil, err
		}
		r.Mechanism = mech
	default:
		return nil, ErrBadRequest
	}
	return r, nil
}

// AttributeChange is one attribute and its values, as an add or
// modify carries them.
type AttributeChange struct {
	Type   string
	Values []string
}

// AddRequest is RFC 4511 4.7.
type AddRequest struct {
	Entry      string
	Attributes []AttributeChange
}

// ParseAddRequest decodes an AddRequest body.
func ParseAddRequest(body []byte) (*AddRequest, error) {
	d := ber.NewDecoder(body)
	entry, err := nextString(d)
	if err != nil {
		return nil, err
	}
	_, list, err := d.Next()
	if err != nil {
		return nil, ErrBadRequest
	}
	attrs, err := readAttributeList(list)
	if err != nil {
		return nil, err
	}
	return &AddRequest{Entry: entry, Attributes: attrs}, nil
}

// CompareRequest is RFC 4511 4.10.
type CompareRequest struct {
	Entry     string
	Attribute string
	Value     string
}

// ParseCompareRequest decodes a CompareRequest body.
func ParseCompareRequest(
	body []byte,
) (*CompareRequest, error) {
	d := ber.NewDecoder(body)
	entry, err := nextString(d)
	if err != nil {
		return nil, err
	}
	_, ava, err := d.Next()
	if err != nil {
		return nil, ErrBadRequest
	}
	ad := ber.NewDecoder(ava)
	attr, err := nextString(ad)
	if err != nil {
		return nil, err
	}
	value, err := nextString(ad)
	if err != nil {
		return nil, err
	}
	return &CompareRequest{
		Entry: entry, Attribute: attr, Value: value,
	}, nil
}
