package ldap

import (
	"github.com/FatmanUK/olivine_ldap/internal/ber"
	"github.com/FatmanUK/olivine_ldap/internal/gss"
)

// BindRequest is RFC 4511 4.2.
type BindRequest struct {
	Version int32
	Name    string
	// Simple is the password on a simple bind.
	Simple string
	// IsSASL, Mechanism and Credentials describe a SASL bind.
	//
	//	SaslCredentials ::= SEQUENCE {
	//		mechanism   LDAPString,
	//		credentials OCTET STRING OPTIONAL }
	//
	// HasCredentials separates an absent credentials field from
	// an empty one. EXTERNAL cares: slapd refuses a *present*
	// credential with "proxy authorization not supported"
	// (sasl.c:1756-1759), because that field would be an
	// authorization identity to impersonate.
	IsSASL         bool
	Mechanism      string
	Credentials    []byte
	HasCredentials bool
	// External is the identity the transport authenticated: the
	// client certificate's subject DN under TLS, empty when the
	// client presented none. Filled in by the server, which is
	// the only part that can see the TLS state.
	External string
	// GSS is the connection's GSSAPI exchange state, which a
	// multi-round mechanism needs to survive between bind
	// requests. Owned by the server, which owns the
	// connection; nil when no connection does.
	GSS *gss.Context
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
		if err := readSASL(r, content); err != nil {
			return nil, err
		}
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

// readSASL decodes the SaslCredentials choice.
func readSASL(r *BindRequest, content []byte) error {
	d := ber.NewDecoder(content)
	mech, err := nextString(d)
	if err != nil {
		return err
	}
	r.Mechanism = mech
	if d.Done() {
		return nil
	}
	_, creds, err := d.Next()
	if err != nil {
		return ErrBadRequest
	}
	r.Credentials, r.HasCredentials = creds, true
	return nil
}
